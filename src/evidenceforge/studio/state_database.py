"""Versioned SQLite contract, immutable migrations and independent fingerprints."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge import __version__
from evidenceforge.studio.state_io import StudioStateError, safe_path
from evidenceforge.studio.state_migrations import (
    LAYOUT_MIGRATIONS,
    SETTINGS_MIGRATIONS,
    ContractMigration,
    JsonChange,
    RecordChange,
    ordered_chain,
)
from evidenceforge.studio.state_schema import BASELINE_SQL, FTS_SQL, LEDGER_SQL, LEGACY_TABLE_SETS

DATABASE_VERSION = 2
FTS_TABLES = {
    "items_fts",
    "items_fts_data",
    "items_fts_idx",
    "items_fts_content",
    "items_fts_docsize",
    "items_fts_config",
}
DERIVED_TABLES = {"validations", "dependency_health", "resource_predictions"}


class ConditionalColumn(BaseModel):
    """A frozen legacy ALTER guarded by actual column presence."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    table: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    column: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    declaration: str


class Migration(ContractMigration):
    """One immutable database transition; checksum includes frozen SQL."""

    family: Literal["database"] = "database"
    sql: str
    ledger_sql: str = LEDGER_SQL
    conditional_columns: tuple[ConditionalColumn, ...] = ()
    records: tuple[RecordChange, ...] = ()


MIGRATIONS = (
    Migration(
        id="studio-db-0001",
        source=0,
        target=1,
        description="Adopt the existing Studio SQL and JSON contract",
        affected=("database",),
        sql=BASELINE_SQL + FTS_SQL,
        conditional_columns=(
            ConditionalColumn(
                table="items", column="search_entries", declaration="TEXT NOT NULL DEFAULT '[]'"
            ),
            ConditionalColumn(
                table="validations",
                column="dependency_sha256",
                declaration="TEXT NOT NULL DEFAULT ''",
            ),
        ),
    ),
    Migration(
        id="studio-db-0002",
        source=1,
        target=2,
        description="Preserve optional artifact titles and pre-authoring scenario titles",
        affected=("items", "conversations"),
        sql="",
        records=(
            RecordChange(
                table="items", changes=(JsonChange(action="default", field="display_name"),)
            ),
            RecordChange(
                table="conversations",
                changes=(JsonChange(action="default", field="draft_display_name"),),
            ),
        ),
    ),
)


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open an existing database without creating it."""
    safe_path(path)
    return sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, timeout=1)


def tables(connection: sqlite3.Connection) -> list[str]:
    """Return base tables, excluding SQLite and FTS implementation details."""
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        if not row[0].startswith("sqlite_") and row[0] not in FTS_TABLES
    ]


def database_digest(path: Path) -> str:
    """Hash logical authoritative state, including committed WAL data, in bounded memory."""
    digest = hashlib.sha256()
    with closing(open_readonly(path)) as connection:
        connection.execute("BEGIN")
        digest.update(str(connection.execute("PRAGMA user_version").fetchone()[0]).encode())
        for table in tables(connection):
            if table in DERIVED_TABLES:
                continue
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name=?", (table,)
            ).fetchone()[0]
            digest.update(schema.encode())
            if table == "studio_migrations":
                for row in connection.execute(
                    "SELECT id, checksum, applied_at, app_version, runtime_id "
                    "FROM studio_migrations ORDER BY id"
                ):
                    digest.update(json.dumps(row).encode())
                continue
            columns = len(connection.execute(f'SELECT * FROM "{table}" LIMIT 0').description)
            order = ",".join(str(index + 1) for index in range(columns))
            for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY {order}'):
                digest.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
    return digest.hexdigest()


def inspect_database(path: Path) -> int:
    """Recognize legacy state or verify a versioned database without changing it."""
    if not path.exists():
        return 0
    with closing(open_readonly(path)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise StudioStateError("Studio database is damaged; restore a verified backup")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in range(DATABASE_VERSION + 1):
            raise StudioStateError(
                f"Unsupported Studio database version {version}; use a compatible release"
            )
        # Derive accepted SQL shapes from the frozen baseline, never from today's store constructor.
        with closing(sqlite3.connect(":memory:")) as baseline:
            baseline.executescript(BASELINE_SQL)
            expected = set(tables(baseline))
            actual = set(tables(connection)) - {"studio_migrations"}
            recognized = (
                actual - DERIVED_TABLES in LEGACY_TABLE_SETS
                if version == 0
                else not (expected - actual - DERIVED_TABLES)
            )
            if actual - expected or not recognized:
                raise StudioStateError("Unrecognized legacy Studio database layout")
            for table in actual:
                if table in DERIVED_TABLES:
                    continue
                wanted = {
                    row[1]: row[2:] for row in baseline.execute(f'PRAGMA table_info("{table}")')
                }
                found = {
                    row[1]: row[2:] for row in connection.execute(f'PRAGMA table_info("{table}")')
                }
                optional = {"search_entries"} if table == "items" else set()
                if table == "validations":
                    optional = {"dependency_sha256"}
                if version == DATABASE_VERSION:
                    optional = set()
                if set(found) - set(wanted) or set(wanted) - set(found) - optional:
                    raise StudioStateError(f"Unrecognized Studio table: {table}")
                if any(
                    found[key][:2] != wanted[key][:2] or found[key][-1] != wanted[key][-1]
                    for key in found
                ):
                    raise StudioStateError(f"Unrecognized Studio column contract: {table}")
            if version >= 1:
                if expected - actual - DERIVED_TABLES:
                    raise StudioStateError("Versioned Studio database is missing required tables")
                if "studio_migrations" not in tables(connection):
                    raise StudioStateError("Studio migration ledger is missing")
                recorded = dict(connection.execute("SELECT id, checksum FROM studio_migrations"))
                required = {
                    entry.id: entry.checksum for entry in MIGRATIONS if entry.target <= version
                }
                known = {
                    entry.id: entry.checksum
                    for entry in (*MIGRATIONS, *SETTINGS_MIGRATIONS, *LAYOUT_MIGRATIONS)
                }
                valid = all(
                    recorded.get(identity) == checksum for identity, checksum in required.items()
                )
                for identity, checksum in recorded.items():
                    declaration, separator, workspace_id = identity.partition(":")
                    if separator and (
                        len(workspace_id) != 32
                        or any(char not in "0123456789abcdef" for char in workspace_id)
                        or declaration != "studio-workspace-layout-0001"
                    ):
                        valid = False
                    if known.get(declaration) != checksum:
                        valid = False
                    if declaration.startswith("studio-db-") and declaration not in required:
                        valid = False
                if not valid:
                    raise StudioStateError(
                        "Studio migration ledger does not match its declared version"
                    )
        validate_records(connection)
    return version


def validate_records(connection: sqlite3.Connection) -> None:
    """Check authoritative records without persisting defaults or regenerating identity."""
    from evidenceforge.studio.state_records_v1 import (
        CatalogItem,
        ControlIntent,
        Conversation,
        EvaluationJob,
        GenerationJob,
        ImportedBundle,
        LibraryPreferences,
        Project,
        SavedView,
    )

    if connection.execute("PRAGMA user_version").fetchone()[0] >= 2:
        from evidenceforge.studio.state_records_v2 import CatalogItem, Conversation

    models: dict[str, type[BaseModel]] = {
        "items": CatalogItem,
        "projects": Project,
        "conversations": Conversation,
        "imported_bundles": ImportedBundle,
        "views": SavedView,
        "library_preferences": LibraryPreferences,
        "control": ControlIntent,
    }
    existing = set(tables(connection))
    for table, model in models.items():
        if table not in existing:
            continue
        cursor = connection.execute(f'SELECT * FROM "{table}"')
        names = [column[0] for column in cursor.description]
        for values in cursor:
            row = dict(zip(names, values, strict=True))
            payload = decode_record(row["payload"], table)
            if table in {"items", "projects", "conversations", "imported_bundles"}:
                if payload.get("id") != row["id"] or payload.get("workspace") != row["workspace"]:
                    raise StudioStateError(f"Studio record identity mismatch in {table}")
            for field in {
                "items": ("kind", "path"),
                "projects": ("name",),
                "imported_bundles": ("root",),
                "views": ("name",),
            }.get(table, ()):
                if payload.get(field) != row[field]:
                    raise StudioStateError(f"Studio record projection mismatch in {table}")
            if table in {"projects", "conversations"}:
                timestamp = payload.get("updated_at")
                if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
                    raise StudioStateError(
                        f"Studio saved timestamp is missing or invalid in {table}"
                    )
            if table == "control" and (row["id"] != 1 or not isinstance(payload.get("id"), str)):
                raise StudioStateError("Studio control identity is invalid")
            model.model_validate(payload)
    if "jobs" in existing:
        for identity, kind, raw in connection.execute("SELECT id, kind, payload FROM jobs"):
            payload = decode_record(raw, "jobs")
            if payload.get("id") != identity or kind not in {"generation", "evaluation"}:
                raise StudioStateError("Studio job identity or kind is invalid")
            (GenerationJob if kind == "generation" else EvaluationJob).model_validate(payload)
    if "events" in existing:
        for (raw,) in connection.execute("SELECT payload FROM events"):
            decode_record(raw, "events")


def decode_record(raw: object, table: str) -> dict[str, object]:
    """Reject malformed cells and non-object JSON before accessing record fields."""
    if not isinstance(raw, str):
        raise StudioStateError(f"Studio record payload must be JSON text in {table}")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise StudioStateError(f"Studio record payload must be an object in {table}")
    return payload


def migrate_database(
    path: Path,
    runtime: str,
    observer: Callable[[str], None] = lambda _name: None,
    migrations: tuple[Migration, ...] = MIGRATIONS,
    app_version: str = __version__,
    receipts: tuple[ContractMigration, ...] = (),
    applied_at: str | None = None,
) -> None:
    """Apply consecutive transitions and publish ledger/version in the same transaction."""
    safe_path(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if not migrations:
            raise StudioStateError("Studio migration registry is empty")
        ordered_chain(migrations, "database", version, migrations[-1].target)
        connection.execute(migrations[0].ledger_sql)
        for entry in migrations:
            if entry.target <= version:
                continue
            if entry.source != version:
                raise StudioStateError("Studio migration chain has a gap")
            # executescript commits implicitly; execute each frozen statement instead.
            for statement in sql_statements(entry.sql):
                if statement.strip():
                    connection.execute(statement)
            for transformation in entry.records:
                for identity, raw in connection.execute(
                    f'SELECT rowid, "{transformation.column}" FROM "{transformation.table}"'
                ):
                    payload = json.loads(raw)
                    if not isinstance(payload, dict):
                        raise StudioStateError("Historical JSON record must be an object")
                    for change in transformation.changes:
                        payload = change.apply(payload)
                    connection.execute(
                        f'UPDATE "{transformation.table}" SET "{transformation.column}"=? WHERE rowid=?',
                        (json.dumps(payload, ensure_ascii=False), identity),
                    )
            for column in entry.conditional_columns:
                names = {
                    row[1] for row in connection.execute(f'PRAGMA table_info("{column.table}")')
                }
                if column.column not in names:
                    connection.execute(
                        f'ALTER TABLE "{column.table}" ADD COLUMN "{column.column}" {column.declaration}'
                    )
            connection.execute(
                "INSERT INTO studio_migrations VALUES (?, ?, COALESCE(?, datetime('now')), ?, ?)",
                (entry.id, entry.checksum, applied_at, app_version, runtime),
            )
            version = entry.target
            connection.execute(f"PRAGMA user_version={version}")
        for entry in receipts:
            record_receipt(connection, entry.id, entry.checksum, app_version, runtime, applied_at)
        observer("database.before_commit")
        connection.commit()
        observer("database.after_commit")


def sql_statements(sql: str) -> Iterator[str]:
    """Use SQLite's statement recognition so literals and triggers can contain semicolons."""
    pending: list[str] = []
    for character in sql:
        pending.append(character)
        if character == ";" and sqlite3.complete_statement("".join(pending)):
            yield "".join(pending)
            pending.clear()
    if "".join(pending).strip():
        yield "".join(pending)


def record_receipt(
    connection: sqlite3.Connection,
    identity: str,
    checksum: str,
    application: str,
    runtime: str,
    applied_at: str | None = None,
) -> None:
    """Record one immutable cross-contract receipt in the same SQLite ledger."""
    previous = connection.execute(
        "SELECT checksum FROM studio_migrations WHERE id=?", (identity,)
    ).fetchone()
    if previous and previous[0] != checksum:
        raise StudioStateError("Applied Studio migration checksum changed")
    connection.execute(
        "INSERT OR IGNORE INTO studio_migrations VALUES (?, ?, COALESCE(?, datetime('now')), ?, ?)",
        (identity, checksum, applied_at, application, runtime),
    )


def repair_derived(path: Path) -> None:
    """Rebuild owned search state and discard only unreadable derived records."""
    from pydantic import ValidationError

    from evidenceforge.studio.forecasts import PredictionRecord
    from evidenceforge.studio.imports import DependencyHealth
    from evidenceforge.studio.service import ValidationResult

    with closing(sqlite3.connect(path)) as connection, connection:
        with closing(sqlite3.connect(":memory:")) as baseline:
            baseline.executescript(BASELINE_SQL)
            for table in DERIVED_TABLES:
                expected = list(baseline.execute(f'PRAGMA table_info("{table}")'))
                observed = list(connection.execute(f'PRAGMA table_info("{table}")'))
                if observed != expected:
                    connection.execute(f'DROP TABLE IF EXISTS "{table}"')
                    declaration = baseline.execute(
                        "SELECT sql FROM sqlite_master WHERE name=?", (table,)
                    ).fetchone()[0]
                    connection.execute(declaration)
        validators: dict[str, type[BaseModel]] = {
            "validations": ValidationResult,
            "dependency_health": DependencyHealth,
            "resource_predictions": PredictionRecord,
        }
        for table, model in validators.items():
            for identity, raw in connection.execute(f"SELECT item_id, payload FROM {table}"):
                try:
                    model.model_validate_json(raw)
                except (ValueError, ValidationError):
                    connection.execute(f"DELETE FROM {table} WHERE item_id=?", (identity,))
        columns = {row[1] for row in connection.execute("PRAGMA table_info(items_fts)")}
        if columns != {"name", "description", "content"}:
            connection.execute("DROP TABLE IF EXISTS items_fts")
            connection.execute(
                "CREATE VIRTUAL TABLE items_fts USING fts5(name, description, content)"
            )
        connection.execute("DELETE FROM items_fts")
        for rowid, payload, content in connection.execute(
            "SELECT rowid, payload, content FROM items"
        ):
            item = json.loads(payload)
            connection.execute(
                "INSERT INTO items_fts (rowid,name,description,content) VALUES (?,?,?,?)",
                (rowid, item["name"], item.get("description", ""), content),
            )
