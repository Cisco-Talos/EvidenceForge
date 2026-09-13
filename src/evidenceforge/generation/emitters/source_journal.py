# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Composed spool and finalization operations for Windows evidence providers.

All mutable state stays on the existing emitter owner so checkpoint adapters,
lock ordering, and fault recovery entrypoints retain their original contracts.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import get_ident
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationParticipantKey,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.source_finalization import (
    ExactSourceRow,
    SourceFinalizationError,
)

if TYPE_CHECKING:
    from .sysmon import SysmonEventEmitter
    from .windows import WindowsEventEmitter

    SourceOwner = WindowsEventEmitter | SysmonEventEmitter

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def preflight_private_spool_root(self: SourceOwner, *, provider: str) -> None:
    """Validate configured exact-spool trust and disjointness before generation."""

    configured = os.environ.get("EFORGE_SPOOL_DIR")
    root = Path(
        os.path.realpath(
            os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
        )
    )
    output_root = Path(os.path.realpath(os.fspath(self._base_dir)))
    if root == output_root or root.is_relative_to(output_root):
        raise ExactPublicationError(f"{provider} private spool root must be outside public output")
    ancestor = root
    while not ancestor.exists():
        if ancestor == ancestor.parent:
            raise ExactPublicationError(
                f"{provider} private spool has no existing trusted ancestor"
            )
        ancestor = ancestor.parent
    self._validate_private_spool_ancestry(ancestor)


def adopt_private_journal_descriptor_unlocked(
    self: SourceOwner, descriptor: int, *, provider: str
) -> None:
    """Retain the identity returned by one exclusive journal create."""

    metadata = os.fstat(descriptor)
    effective_user = int(os.geteuid())
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or int(metadata.st_uid) != effective_user
    ):
        raise ExactPublicationError(f"{provider} private journal is not an owner file")
    os.fchmod(descriptor, 0o600)
    self._spool_file_identity = (int(metadata.st_dev), int(metadata.st_ino))


def adopt_private_journal_create_lost_return_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Retain a journal entry created before its exclusive-open return was lost."""

    directory_descriptor = self._spool_directory_descriptor
    filename = self._spool_filename
    if directory_descriptor is None or filename is None:
        raise ExactPublicationError(f"{provider} private journal lost its create owner")
    try:
        descriptor = os.open(
            filename,
            os.O_RDWR | _NOFOLLOW,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        return
    try:
        self._adopt_private_journal_descriptor_unlocked(descriptor)
    finally:
        os.close(descriptor)


def finish_private_journal_initialization_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Retryably create, initialize, and durably publish the retained journal."""

    directory_descriptor = self._spool_directory_descriptor
    filename = self._spool_filename
    path = self._spool_path
    if directory_descriptor is None or filename is None or path is None:
        raise ExactPublicationError(f"{provider} private journal lost its initialization owner")
    if self._spool_file_identity is None:
        try:
            descriptor = os.open(
                filename,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as error:
            raise ExactPublicationError(
                f"{provider} private journal create ownership is ambiguous"
            ) from error
        except BaseException:
            self._adopt_private_journal_create_lost_return_unlocked()
            raise
        else:
            try:
                self._adopt_private_journal_descriptor_unlocked(descriptor)
            finally:
                os.close(descriptor)
    self._validate_spool_file_unlocked()
    if self._spool_conn is None:
        self._spool_conn = sqlite3.connect(
            f"{path.as_uri()}?mode=rw",
            uri=True,
            check_same_thread=False,
        )
    self._initialize_spool_schema_unlocked(self._spool_conn)
    self._validate_spool_file_unlocked()
    os.fsync(directory_descriptor)
    self._spool_file_initialization_pending = False


def initialize_spool_schema_unlocked(
    self: SourceOwner, connection: sqlite3.Connection, *, provider: str
) -> None:
    """Create one bounded candidate/final journal with memory-only SQLite temp state."""

    connection.execute("PRAGMA temp_store=MEMORY")
    if connection.execute("PRAGMA temp_store").fetchone() != (2,):
        raise ExactPublicationError(f"{provider} journal could not confine SQLite temp storage")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("PRAGMA user_version").fetchone() == (1,):
        self._validate_initial_spool_schema_unlocked(connection)
        return
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """CREATE TABLE events (
                sequence INTEGER PRIMARY KEY,
                sort_key TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (phase IN ('candidate', 'final')),
                payload TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
                ordinal INTEGER,
                route_kind TEXT,
                route_key TEXT,
                payload_digest TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX events_candidate_order ON events (phase, sort_key, sequence)"
        )
        connection.execute("CREATE UNIQUE INDEX events_final_order ON events (phase, ordinal)")
        connection.execute(
            """CREATE TABLE finalization_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                phase TEXT NOT NULL,
                candidate_rows INTEGER NOT NULL,
                candidate_bytes INTEGER NOT NULL,
                final_rows INTEGER NOT NULL,
                final_bytes INTEGER NOT NULL,
                routes INTEGER NOT NULL,
                published_rows INTEGER NOT NULL,
                epoch INTEGER NOT NULL,
                high_water_rows INTEGER NOT NULL,
                high_water_bytes INTEGER NOT NULL,
                high_water_routes INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO finalization_state
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (1, "candidate", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        )
        connection.execute("PRAGMA user_version=1")
        connection.commit()
    except BaseException:
        if not connection.in_transaction:
            try:
                self._validate_initial_spool_schema_unlocked(connection)
            except ExactPublicationError:
                pass
            else:
                return
        connection.rollback()
        raise
    self._validate_initial_spool_schema_unlocked(connection)


def validate_initial_spool_schema_unlocked(
    connection: sqlite3.Connection, *, provider: str
) -> None:
    """Adopt only the exact empty schema after an initialization lost return."""

    objects = set(
        connection.execute(
            """SELECT type, name FROM sqlite_master
               WHERE name IN (?, ?, ?, ?)""",
            (
                "events",
                "events_candidate_order",
                "events_final_order",
                "finalization_state",
            ),
        ).fetchall()
    )
    expected = {
        ("table", "events"),
        ("index", "events_candidate_order"),
        ("index", "events_final_order"),
        ("table", "finalization_state"),
    }
    state = connection.execute(
        "SELECT * FROM finalization_state WHERE singleton = ?",
        (1,),
    ).fetchone()
    if (
        connection.execute("PRAGMA user_version").fetchone() != (1,)
        or objects != expected
        or state != (1, "candidate", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        or connection.execute("SELECT COUNT(*) FROM events").fetchone() != (0,)
    ):
        raise ExactPublicationError(f"{provider} private journal schema is not immutable")


def open_directory_nofollow(path: Path, *, create: bool = False, provider: str) -> int:
    """Open every existing absolute directory component without following symlinks."""

    absolute = Path(os.path.abspath(os.fspath(path)))
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
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_private_spool_ancestry(cls: type[SourceOwner], path: Path, *, provider: str) -> None:
    """Require root-or-process-owned ancestry with sticky shared roots."""

    effective_user = int(os.geteuid())
    current = path
    while True:
        descriptor = cls._open_directory_nofollow(current)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if int(metadata.st_uid) not in {0, effective_user}:
            raise ExactPublicationError(
                f"{provider} private spool ancestry is not process controlled"
            )
        permissions = stat.S_IMODE(metadata.st_mode)
        if permissions & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise ExactPublicationError(
                f"{provider} private spool ancestry is externally writable without sticky mode"
            )
        if current == current.parent:
            return
        current = current.parent


def adopt_private_spool_create_lost_return_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Retain an owner-only leaf created before mkdir's return was lost."""

    root_descriptor = self._spool_root_descriptor
    directory_name = self._spool_directory_name
    if root_descriptor is None or directory_name is None:
        raise ExactPublicationError(f"{provider} private spool lost its create owner")
    try:
        metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    effective_user = int(os.geteuid())
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or int(metadata.st_uid) != effective_user
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ExactPublicationError(f"{provider} private spool leaf is not owner-only")
    self._spool_directory_identity = (int(metadata.st_dev), int(metadata.st_ino))


def finish_private_spool_initialization_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Retryably pin and durably publish one newly allocated private leaf."""

    root_descriptor = self._spool_root_descriptor
    directory_name = self._spool_directory_name
    if root_descriptor is None or directory_name is None:
        raise ExactPublicationError(f"{provider} private spool lost its initialization owner")
    try:
        metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.mkdir(directory_name, mode=0o700, dir_fd=root_descriptor)
        except BaseException:
            self._adopt_private_spool_create_lost_return_unlocked()
            raise
        metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
    effective_user = int(os.geteuid())
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or int(metadata.st_uid) != effective_user
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ExactPublicationError(f"{provider} private spool leaf is not owner-only")
    identity = (int(metadata.st_dev), int(metadata.st_ino))
    if self._spool_directory_identity not in {None, identity}:
        raise ExactPublicationError(f"{provider} private spool leaf identity changed")
    if self._spool_directory_descriptor is None:
        self._spool_directory_descriptor = os.open(
            directory_name,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
            dir_fd=root_descriptor,
        )
    retained = os.fstat(self._spool_directory_descriptor)
    if (int(retained.st_dev), int(retained.st_ino)) != identity:
        raise ExactPublicationError(f"{provider} private spool descriptor changed identity")
    self._spool_directory_identity = identity
    os.fsync(self._spool_directory_descriptor)
    os.fsync(root_descriptor)
    self._spool_initialization_pending = False


def source_lifecycle_snapshot(self: SourceOwner, *, provider: str) -> tuple[str, int | None]:
    """Read source owner state under the shared close admission lock."""

    with self._close_condition:
        return self._source_finalization_state, self._source_finalization_owner


@contextmanager
def source_finalization_operation(self: SourceOwner, *, provider: str) -> Iterator[None]:
    """Fence one terminal mutation while allowing sequential thread transfer."""

    if not self._source_finalization_operation_lock.acquire(blocking=False):
        raise SourceFinalizationError(
            f"{provider} source finalization already has an active owner operation"
        )
    owner = get_ident()
    try:
        with self._close_condition:
            if self._source_finalization_owner is not None:
                raise SourceFinalizationError(
                    f"{provider} source finalization retained a stale operation owner"
                )
            self._source_finalization_owner = owner
        yield
    finally:
        with self._close_condition:
            if self._source_finalization_owner == owner:
                self._source_finalization_owner = None
                self._close_condition.notify_all()
        self._source_finalization_operation_lock.release()


def set_source_lifecycle_state(self: SourceOwner, state: str, *, provider: str) -> None:
    """Advance source owner state under the shared close admission lock."""

    with self._close_condition:
        owner = self._source_finalization_owner
        if owner is not None and owner != get_ident():
            raise SourceFinalizationError(
                f"{provider} source-finalization state has a different owner"
            )
        self._source_finalization_state = state
        self._close_condition.notify_all()


def require_source_owner(self: SourceOwner, allowed_states: set[str], *, provider: str) -> str:
    """Require the retained owner for every terminal source mutation entry."""

    state, owner = self._source_lifecycle_snapshot()
    if state not in allowed_states:
        raise SourceFinalizationError(
            f"{provider} source-finalization state {state!r} is not mutable here"
        )
    if owner != get_ident():
        raise SourceFinalizationError(
            f"{provider} source-finalization mutation has a different owner"
        )
    return state


def journal_state_unlocked(self: SourceOwner, *, provider: str) -> tuple[Any, ...]:
    """Return the singleton source-journal state while holding `_file_lock`."""

    connection = self._get_spool_conn_unlocked()
    self._validate_spool_file_unlocked()
    row = connection.execute(
        """SELECT phase, candidate_rows, candidate_bytes, final_rows, final_bytes,
                  routes, published_rows, epoch, high_water_rows, high_water_bytes,
                  high_water_routes
           FROM finalization_state WHERE singleton = ?""",
        (1,),
    ).fetchone()
    if row is None:
        raise SourceFinalizationError(f"{provider} source journal lost its singleton state")
    return tuple(row)


def commit_journal_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Commit the private journal through one injectable lost-return boundary."""

    if self._spool_conn is None:
        raise SourceFinalizationError(f"{provider} source journal is not open")
    self._spool_conn.commit()


def rollback_journal_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Roll back an unsealed private-journal transaction."""

    if self._spool_conn is not None:
        self._spool_conn.rollback()


def route_id_unlocked(
    self: SourceOwner, route_kind: str, route_key: str, writer: _SingleHostWriter, *, provider: str
) -> int:
    """Retain one already-resolved physical writer under the finite route cap."""

    token = (route_kind, route_key)
    route_id = self._source_finalization_route_ids.get(token)
    if route_id is not None:
        if self._source_finalization_routes.get(route_id) is not writer:
            raise SourceFinalizationError(
                f"{provider} source route changed its physical writer during sealing"
            )
        return route_id
    if len(self._source_finalization_route_ids) >= self._finalization_route_capacity:
        raise SourceFinalizationError(f"{provider} finalization route capacity is exhausted")
    route_id = len(self._source_finalization_route_ids)
    self._source_finalization_route_ids[token] = route_id
    self._source_finalization_routes[route_id] = writer
    return route_id


def resolve_sealed_writer_unlocked(
    self: SourceOwner, route_kind: str, route_key: str, *, provider: str
) -> _SingleHostWriter:
    """Resolve the writer retained when this immutable route was sealed."""

    route_id = self._source_finalization_route_ids.get((route_kind, route_key))
    writer = self._source_finalization_routes.get(route_id) if route_id is not None else None
    if writer is None:
        raise SourceFinalizationError(
            f"{provider} sealed route lost its same-process physical writer"
        )
    return writer


def read_final_row_unlocked(self: SourceOwner, ordinal: int, *, provider: str) -> ExactSourceRow:
    """Load and authenticate one immutable final row by exact ordinal."""

    if type(ordinal) is not int or ordinal < 0:
        raise SourceFinalizationError(
            f"{provider} immutable final row ordinal must be a nonnegative exact int"
        )
    connection = self._spool_conn
    if connection is None:
        raise SourceFinalizationError(f"{provider} source journal is not open")
    row = connection.execute(
        """SELECT route_kind, route_key, payload, payload_bytes, payload_digest
           FROM events WHERE phase = ? AND ordinal = ?""",
        ("final", ordinal),
    ).fetchone()
    if row is None:
        raise SourceFinalizationError(f"{provider} immutable final row is missing")
    route_kind, route_key, rendered, payload_bytes, payload_digest = row
    if (
        type(route_kind) is not str
        or type(route_key) is not str
        or type(rendered) is not str
        or type(payload_bytes) is not int
        or payload_bytes < 0
        or type(payload_digest) is not str
    ):
        raise SourceFinalizationError(f"{provider} immutable final row has invalid types")
    encoded = rendered.encode("utf-8")
    if len(encoded) != payload_bytes or hashlib.sha256(encoded).hexdigest() != payload_digest:
        raise SourceFinalizationError(f"{provider} immutable final row failed validation")
    return ExactSourceRow(
        writer=self._resolve_sealed_writer_unlocked(route_kind, route_key),
        content=rendered,
    )


def finish_exact_candidate_terminal_cleanup(self: SourceOwner, *, provider: str) -> None:
    """Drop bounded released receipts only after terminal source ownership ends."""

    with self._exact_publication_condition:
        if self._active_exact_publication_keys:
            raise ExactPublicationError(
                f"{provider} terminal cleanup found an active exact candidate batch"
            )
        if (
            self._exact_candidate_current_participants
            != self._exact_candidate_completed_participants
        ):
            raise ExactPublicationError(
                f"{provider} terminal cleanup found an incomplete exact participant"
            )
        if (
            self._exact_candidate_current_rows != self._exact_candidate_released_rows
            or self._exact_candidate_current_bytes != self._exact_candidate_released_bytes
        ):
            raise ExactPublicationError(
                f"{provider} terminal cleanup found an unreleased exact candidate"
            )
        if (
            len(self._exact_candidate_reservations) != self._exact_candidate_current_rows
            or len(self._exact_candidate_participants) != self._exact_candidate_current_participants
        ):
            raise ExactPublicationError(
                f"{provider} terminal cleanup found inconsistent exact candidate ownership"
            )
        if (
            self._exact_candidate_abort_pending_row is not None
            or self._exact_candidate_abort_registered_writers
        ):
            raise ExactPublicationError(
                f"{provider} terminal cleanup found incomplete exact abort publication"
            )
        self._exact_candidate_reservations.clear()
        self._exact_candidate_participants.clear()
        self._exact_candidate_current_rows = 0
        self._exact_candidate_current_bytes = 0
        self._exact_candidate_current_participants = 0
        self._exact_candidate_released_rows = 0
        self._exact_candidate_released_bytes = 0
        self._exact_candidate_completed_participants = 0
        self._exact_candidate_abort_participant_key = None


def validate_exact_candidate_receipts_before_abort_close(
    self: SourceOwner, *, provider: str
) -> bool:
    """Authenticate released exact candidates before abort may clear or render them."""

    with self._exact_publication_condition:
        retained = bool(
            self._exact_candidate_current_rows
            or self._exact_candidate_current_bytes
            or self._exact_candidate_current_participants
            or self._exact_candidate_released_rows
            or self._exact_candidate_released_bytes
            or self._exact_candidate_completed_participants
            or self._exact_candidate_reservations
            or self._exact_candidate_participants
        )
        if not retained:
            return False
        with self._file_lock:
            self._validate_exact_candidate_receipts_before_seal_unlocked()
        return True


def exact_candidate_abort_participant(
    self: SourceOwner, *, provider: str
) -> ExactPublicationParticipantKey:
    """Retain one authenticated candidate participant for exact abort publication."""

    with self._exact_publication_condition:
        retained = self._exact_candidate_abort_participant_key
        if retained is not None:
            if retained not in self._exact_candidate_participants:
                raise ExactPublicationError(
                    f"{provider} exact abort publication lost its candidate participant"
                )
            return retained
        if not self._exact_candidate_participants:
            raise ExactPublicationError(
                f"{provider} exact abort publication requires a retained participant"
            )
        retained = min(self._exact_candidate_participants)
        self._validate_exact_candidate_participant_key(retained)
        self._exact_candidate_abort_participant_key = retained
        return retained


def register_exact_candidate_abort_writer(
    self: SourceOwner,
    writer: _SingleHostWriter,
    participant_key: ExactPublicationParticipantKey,
    *,
    provider: str,
) -> None:
    """Fence one final writer under the retained abort participant."""

    writer_id = id(writer)
    retained = self._exact_candidate_abort_registered_writers.get(writer_id)
    if retained is not None:
        if retained is not writer:
            raise ExactPublicationError(
                f"{provider} exact abort publication changed a retained final writer"
            )
        return
    writer._register_exact_publication_batch(participant_key)
    self._exact_candidate_abort_registered_writers[writer_id] = writer


def mark_exact_candidate_abort_published_unlocked(self: SourceOwner, *, provider: str) -> None:
    """Durably mark a fully checkpointed abort cohort published."""

    connection = self._spool_conn
    if connection is None:
        raise SourceFinalizationError(f"{provider} source journal is not open")
    connection.execute(
        """UPDATE finalization_state SET phase = ?
           WHERE singleton = ? AND phase = ? AND published_rows = final_rows""",
        ("published", 1, "sealed"),
    )
    try:
        self._commit_journal_unlocked()
    except BaseException:
        if connection.in_transaction or str(self._journal_state_unlocked()[0]) != "published":
            self._rollback_journal_unlocked()
            raise
    if str(self._journal_state_unlocked()[0]) != "published":
        raise SourceFinalizationError(f"{provider} exact abort publication state was not durable")


def prepare_exact_candidate_abort_close_render(self: SourceOwner, *, provider: str) -> bool:
    """Resume authenticated abort rendering and report whether rows already rendered."""

    if self._exact_candidate_abort_close_render_complete:
        if (
            not self._exact_candidate_abort_close_rendering
            or not self._exact_candidate_abort_close_rows_rendered
        ):
            raise ExactPublicationError(
                f"{provider} abort close lost its exact render-completion owner"
            )
        return True
    if self._exact_candidate_abort_close_rows_rendered:
        if not self._exact_candidate_abort_close_rendering:
            raise ExactPublicationError(
                f"{provider} abort close retained rows without an exact render owner"
            )
        with self._file_lock:
            self._cleanup_spool_unlocked()
        if not self._exact_candidate_abort_close_render_complete:
            raise ExactPublicationError(
                f"{provider} abort close did not retain journal-cleanup completion"
            )
        return True
    if self._exact_candidate_abort_close_rendering:
        self._resume_exact_candidate_abort_render()
        return True
    retained = self._validate_exact_candidate_receipts_before_abort_close()
    if not retained:
        return False
    self._exact_candidate_abort_close_rendering = True
    self._resume_exact_candidate_abort_render()
    return True
