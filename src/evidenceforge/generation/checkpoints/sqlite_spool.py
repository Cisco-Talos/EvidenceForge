"""Row-delta checkpoint adapter for protected SQLite emitter spools."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "1"
_CHANGE_TABLE = "_eforge_checkpoint_changes"


@dataclass(frozen=True)
class _PreparedSQLiteDelta:
    sequence: int
    watermark: int
    schema_sha256: str
    segment_count: int
    seal: ParticipantSeal


def _identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _primitive(value: object) -> object:
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return value
    raise TypeError(f"SQLite checkpoint column has unsupported type {type(value).__name__}")


class SQLiteSpoolParticipant:
    """Persist row-level SQLite changes without copying the database file.

    This adapter is installed after the owning emitter creates its schema. It
    adds private dirty-row triggers to explicitly selected ordinary rowid tables.
    The first seal contains the schema and current rows; later seals contain only
    rows inserted, updated, or deleted since the prior committed watermark.
    """

    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("schema", "immutable-incremental-segments"),
        OwnerStateField("row_deltas", "immutable-incremental-segments"),
        OwnerStateField("change_watermark", "bounded-live-head"),
        OwnerStateField("connection", "deterministically-rebuilt"),
        OwnerStateField("open_transaction", "transient-empty-at-barrier"),
    )

    def __init__(
        self,
        *,
        owner: str,
        connection: Callable[[], sqlite3.Connection],
        tables: Sequence[str],
        initialize_tracking: bool = True,
        restore_complete: Callable[[], None] | None = None,
    ) -> None:
        if not owner:
            raise ValueError("SQLite spool checkpoint owner cannot be empty")
        if not tables or any(not table for table in tables):
            raise ValueError("SQLite spool participant requires explicit table names")
        if len(set(tables)) != len(tables) or _CHANGE_TABLE in tables:
            raise ValueError("SQLite spool checkpoint table names must be unique and external")
        self.checkpoint_owner = owner
        self._connection = connection
        self._tables = tuple(sorted(tables))
        self._restore_complete = restore_complete
        self._committed_watermark = 0
        self._schema_sha256 = ""
        self._segment_count = 0
        self._prepared: _PreparedSQLiteDelta | None = None
        self.last_rows_read = 0
        if initialize_tracking:
            self._install_change_tracking(self._connection())

    def _validate_tables(self, connection: sqlite3.Connection) -> None:
        available = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        missing = set(self._tables) - available
        if missing:
            raise ValueError(f"SQLite checkpoint tables do not exist: {sorted(missing)}")
        for table in self._tables:
            sql_row = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            if sql_row is None or sql_row[0] is None or "WITHOUT ROWID" in sql_row[0].upper():
                raise ValueError(f"SQLite checkpoint table must expose a stable rowid: {table}")

    def _install_change_tracking(self, connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            raise RuntimeError("SQLite checkpoint tracking requires a quiescent connection")
        self._validate_tables(connection)
        connection.execute(
            f"""CREATE TABLE IF NOT EXISTS {_identifier(_CHANGE_TABLE)} (
                change_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                rowid_value INTEGER NOT NULL,
                deleted INTEGER NOT NULL CHECK (deleted IN (0, 1))
            )"""
        )
        for table_index, table in enumerate(self._tables):
            quoted = _identifier(table)
            table_value = _literal(table)
            for operation, reference, deleted in (
                ("insert", "NEW", 0),
                ("update", "NEW", 0),
                ("delete", "OLD", 1),
            ):
                trigger = _identifier(f"_eforge_checkpoint_{table_index}_{operation}")
                connection.execute(
                    f"""CREATE TRIGGER IF NOT EXISTS {trigger}
                    AFTER {operation.upper()} ON {quoted}
                    BEGIN
                        INSERT INTO {_identifier(_CHANGE_TABLE)}
                            (table_name, rowid_value, deleted)
                        VALUES ({table_value}, {reference}.rowid, {deleted});
                    END"""
                )
        connection.commit()

    def _schema_document(self, connection: sqlite3.Connection) -> list[dict[str, object]]:
        names = set(self._tables)
        rows = connection.execute(
            """SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND type IN ('table', 'index')
            ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name"""
        ).fetchall()
        document: list[dict[str, object]] = []
        for kind, name, table_name, sql in rows:
            if table_name not in names or name.startswith("_eforge_checkpoint_"):
                continue
            document.append(
                {"name": str(name), "sql": str(sql), "table": str(table_name), "type": str(kind)}
            )
        table_definitions = {row["name"] for row in document if row["type"] == "table"}
        if table_definitions != names:
            raise RuntimeError("SQLite checkpoint schema table set changed")
        return document

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
        columns = [
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({_identifier(table)})")
        ]
        if not columns:
            raise RuntimeError(f"SQLite checkpoint table has no columns: {table}")
        return columns

    def _full_rows(self, connection: sqlite3.Connection) -> list[dict[str, object]]:
        changes: list[dict[str, object]] = []
        for table in self._tables:
            columns = self._columns(connection, table)
            projection = ", ".join(_identifier(column) for column in columns)
            for row in connection.execute(
                f"SELECT rowid, {projection} FROM {_identifier(table)} ORDER BY rowid"
            ):
                changes.append(
                    {
                        "columns": columns,
                        "deleted": False,
                        "rowid": int(row[0]),
                        "table": table,
                        "values": [_primitive(value) for value in row[1:]],
                    }
                )
        return changes

    def _changed_rows(
        self,
        connection: sqlite3.Connection,
        *,
        watermark: int,
    ) -> list[dict[str, object]]:
        latest = connection.execute(
            f"""SELECT changes.table_name, changes.rowid_value, changes.deleted
            FROM {_identifier(_CHANGE_TABLE)} AS changes
            JOIN (
                SELECT table_name, rowid_value, MAX(change_sequence) AS latest_sequence
                FROM {_identifier(_CHANGE_TABLE)}
                WHERE change_sequence > ?
                GROUP BY table_name, rowid_value
            ) AS newest ON newest.latest_sequence = changes.change_sequence
            ORDER BY changes.table_name, changes.rowid_value""",
            (watermark,),
        ).fetchall()
        changes: list[dict[str, object]] = []
        for table, rowid, deleted in latest:
            if table not in self._tables:
                raise RuntimeError("SQLite checkpoint change log named an undeclared table")
            columns = self._columns(connection, table)
            change: dict[str, object] = {
                "columns": columns,
                "deleted": bool(deleted),
                "rowid": int(rowid),
                "table": str(table),
                "values": [],
            }
            if not deleted:
                projection = ", ".join(_identifier(column) for column in columns)
                row = connection.execute(
                    f"SELECT {projection} FROM {_identifier(table)} WHERE rowid = ?", (rowid,)
                ).fetchone()
                if row is None:
                    change["deleted"] = True
                else:
                    change["values"] = [_primitive(value) for value in row]
            changes.append(change)
        return changes

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Seal current rows initially and only dirty rows thereafter."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("SQLite spool participant already prepared another sequence")
            return self._prepared.seal
        connection = self._connection()
        if connection.in_transaction:
            raise RuntimeError("SQLite checkpoint capture requires a quiescent connection")
        schema = self._schema_document(connection)
        schema_payload = dumps(schema)
        schema_sha256 = hashlib.sha256(schema_payload).hexdigest()
        if self._schema_sha256 and schema_sha256 != self._schema_sha256:
            raise RuntimeError("SQLite checkpoint schema changed after the first recovery point")
        watermark_row = connection.execute(
            f"SELECT COALESCE(MAX(change_sequence), 0) FROM {_identifier(_CHANGE_TABLE)}"
        ).fetchone()
        assert watermark_row is not None
        watermark = int(watermark_row[0])
        initial = not self._schema_sha256
        changes = (
            self._full_rows(connection)
            if initial
            else self._changed_rows(connection, watermark=self._committed_watermark)
        )
        self.last_rows_read = len(changes)
        segment_document: dict[str, object] = {
            "changes": changes,
            "kind": "base" if initial else "delta",
            "schema": schema if initial else [],
            "schema_sha256": schema_sha256,
        }
        segments = (
            (
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps(segment_document),
                    record_count=len(changes),
                    compression="zlib-1",
                ),
            )
            if initial or changes
            else ()
        )
        segment_count = self._segment_count + len(segments)
        head = HeadDraft(
            owner=self.checkpoint_owner,
            schema_version=self.checkpoint_schema_version,
            payload=dumps(
                {
                    "change_watermark": watermark,
                    "schema_sha256": schema_sha256,
                    "schema_version": self.checkpoint_schema_version,
                    "segment_count": segment_count,
                }
            ),
        )
        seal = ParticipantSeal(head=head, segments=segments)
        self._prepared = _PreparedSQLiteDelta(
            sequence=sequence,
            watermark=watermark,
            schema_sha256=schema_sha256,
            segment_count=segment_count,
            seal=seal,
        )
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance and prune the private dirty-row watermark."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("SQLite spool commit does not match its prepared sequence")
        self._committed_watermark = self._prepared.watermark
        self._schema_sha256 = self._prepared.schema_sha256
        self._segment_count = self._prepared.segment_count
        connection = self._connection()
        connection.execute(
            f"DELETE FROM {_identifier(_CHANGE_TABLE)} WHERE change_sequence <= ?",
            (self._committed_watermark,),
        )
        connection.commit()
        self._committed_watermark = 0
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retain the change log so a failed delta can be resealed exactly."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("SQLite spool abort does not match its prepared sequence")
        self._prepared = None

    @staticmethod
    def _validated_segment(payload: bytes) -> dict[str, object]:
        document = loads(payload)
        if type(document) is not dict:
            raise CheckpointCorruptionError("SQLite spool segment is invalid")
        if document.get("kind") not in {"base", "delta"}:
            raise CheckpointCorruptionError("SQLite spool segment kind is unsupported")
        if type(document.get("schema")) is not list or type(document.get("changes")) is not list:
            raise CheckpointCorruptionError("SQLite spool segment tables are invalid")
        return document

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Rebuild a fresh database by applying authenticated logical row deltas."""

        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
        ):
            raise CheckpointCorruptionError("SQLite spool head schema is unsupported")
        schema_sha256 = document.get("schema_sha256")
        segment_count = document.get("segment_count")
        if (
            type(schema_sha256) is not str
            or len(schema_sha256) != 64
            or type(segment_count) is not int
            or segment_count != len(segments)
            or not segments
        ):
            raise CheckpointCorruptionError("SQLite spool head metadata changed")
        decoded = [self._validated_segment(segment) for segment in segments]
        first = decoded[0]
        if first["kind"] != "base" or any(item["kind"] != "delta" for item in decoded[1:]):
            raise CheckpointCorruptionError("SQLite spool segment history is invalid")
        schema = first["schema"]
        if hashlib.sha256(dumps(schema)).hexdigest() != schema_sha256:
            raise CheckpointCorruptionError("SQLite spool schema hash changed")
        if any(item.get("schema_sha256") != schema_sha256 for item in decoded):
            raise CheckpointCorruptionError("SQLite spool delta schema changed")

        connection = self._connection()
        if connection.in_transaction:
            raise RuntimeError("SQLite checkpoint restore requires a quiescent connection")
        existing = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if row[0] != _CHANGE_TABLE
        }
        if existing and existing != set(self._tables):
            raise RuntimeError("SQLite checkpoint restore found an incompatible table set")
        create_schema = not existing
        if not create_schema:
            current_schema = self._schema_document(connection)
            if hashlib.sha256(dumps(current_schema)).hexdigest() != schema_sha256:
                raise RuntimeError("SQLite checkpoint restore found an incompatible schema")
        connection.execute("BEGIN IMMEDIATE")
        try:
            if create_schema:
                for raw in schema:
                    if type(raw) is not dict or raw.get("type") not in {"table", "index"}:
                        raise CheckpointCorruptionError("SQLite spool schema entry is invalid")
                    sql = raw.get("sql")
                    table = raw.get("table")
                    if type(sql) is not str or table not in self._tables:
                        raise CheckpointCorruptionError("SQLite spool schema entry changed")
                    connection.execute(sql)
            else:
                for table in reversed(self._tables):
                    connection.execute(f"DELETE FROM {_identifier(table)}")
            for segment in decoded:
                for raw in segment["changes"]:
                    if type(raw) is not dict:
                        raise CheckpointCorruptionError("SQLite spool row delta is invalid")
                    table = raw.get("table")
                    rowid = raw.get("rowid")
                    columns = raw.get("columns")
                    values = raw.get("values")
                    deleted = raw.get("deleted")
                    if (
                        table not in self._tables
                        or type(rowid) is not int
                        or type(columns) is not list
                        or any(type(column) is not str for column in columns)
                        or type(values) is not list
                        or type(deleted) is not bool
                    ):
                        raise CheckpointCorruptionError("SQLite spool row delta changed")
                    if deleted:
                        connection.execute(
                            f"DELETE FROM {_identifier(table)} WHERE rowid = ?", (rowid,)
                        )
                        continue
                    if len(columns) != len(values):
                        raise CheckpointCorruptionError("SQLite spool row width changed")
                    quoted_columns = ", ".join(_identifier(column) for column in columns)
                    placeholders = ", ".join("?" for _ in values)
                    connection.execute(
                        f"INSERT OR REPLACE INTO {_identifier(table)} "
                        f"(rowid, {quoted_columns}) VALUES (?, {placeholders})",
                        (rowid, *values),
                    )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._schema_sha256 = schema_sha256
        self._segment_count = segment_count
        self._committed_watermark = 0
        self._prepared = None
        self._install_change_tracking(connection)
        if self._restore_complete is not None:
            self._restore_complete()
