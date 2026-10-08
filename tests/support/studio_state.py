"""Frozen legacy fixtures and independent preservation inventories for Studio."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from evidenceforge.studio.paths import StudioPaths

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/studio-state"


def committed_wal(selected: StudioPaths) -> None:
    """Leave a committed row in WAL by exiting the fixture writer without SQLite cleanup."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,sqlite3,sys; db=sqlite3.connect(sys.argv[1]); "
            "db.execute('PRAGMA journal_mode=WAL'); "
            "db.execute(\"INSERT INTO removed_job_history VALUES ('wal-survivor')\"); "
            "db.commit(); os._exit(0)",
            str(selected.database_file),
        ],
        check=True,
        timeout=10,
    )
    assert selected.database_file.with_name(selected.database_file.name + "-wal").exists()


def paths(root: Path) -> StudioPaths:
    """Bind every private path to disposable storage."""
    return StudioPaths(
        config=root / "config",
        data=root / "data",
        state=root / "state",
        cache=root / "cache",
        logs=root / "logs",
    )


def legacy(root: Path, shape: str = "original") -> StudioPaths:
    """Create records from historical SQL/JSON, not current model serialization."""
    selected = paths(root / "private")
    selected.data.mkdir(parents=True)
    selected.config.mkdir(parents=True)
    raw = json.loads((FIXTURES / "records.json").read_text())
    payload = json.loads(json.dumps(raw).replace("@ROOT@", str(root).replace("\\", "\\\\")))
    selected.settings_file.write_text(json.dumps(payload["settings"], ensure_ascii=False))
    for name in ("workspace", "other"):
        (root / name).mkdir()
    scenario = Path(payload["items"][0]["path"])
    scenario.parent.mkdir(parents=True)
    scenario.write_bytes(b"engine-owned scenario: do not rewrite\n")
    (root / "immutable.yaml").write_bytes(b"immutable engine-owned resolved input\n")
    with closing(sqlite3.connect(selected.database_file)) as database, database:
        historical = f"{shape}.sql" if shape in {"preview", "imports", "history"} else "legacy.sql"
        database.executescript((FIXTURES / historical).read_text())
        existing = {
            row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if shape in {"dependency", "current"}:
            database.execute(
                "ALTER TABLE validations ADD COLUMN dependency_sha256 TEXT NOT NULL DEFAULT ''"
            )
        if shape == "current":
            database.execute(
                "ALTER TABLE items ADD COLUMN search_entries TEXT NOT NULL DEFAULT '[]'"
            )
        for table in ("projects", "conversations", "imported_bundles"):
            if table not in existing:
                continue
            for record in payload[table]:
                if table == "projects":
                    columns, values = (
                        "id,workspace,name,payload",
                        (record["id"], record["workspace"], record["name"], json.dumps(record)),
                    )
                elif table == "conversations":
                    columns, values = (
                        "id,workspace,item_id,payload",
                        (
                            record["id"],
                            record["workspace"],
                            record.get("item_id"),
                            json.dumps(record),
                        ),
                    )
                else:
                    columns, values = (
                        "id,workspace,root,payload",
                        (record["id"], record["workspace"], record["root"], json.dumps(record)),
                    )
                database.execute(f"INSERT INTO {table} ({columns}) VALUES (?,?,?,?)", values)
        for record in payload["items"]:
            database.execute(
                "INSERT INTO items (id,workspace,kind,path,payload,content) VALUES (?,?,?,?,?,?)",
                (
                    record["id"],
                    record["workspace"],
                    record["kind"],
                    record["path"],
                    json.dumps(record),
                    "search content",
                ),
            )
        for record in payload["jobs"]:
            database.execute(
                "INSERT INTO jobs VALUES (?,?,?,?)",
                (record["id"], record["workspace"], "generation", json.dumps(record)),
            )
        for record in payload["evaluation_jobs"]:
            database.execute(
                "INSERT INTO jobs VALUES (?,?,?,?)",
                (
                    record["id"],
                    record["workspace"],
                    "evaluation",
                    json.dumps(record),
                ),
            )
        database.execute("INSERT INTO control VALUES (1,?)", (json.dumps(payload["control"]),))
        columns = "item_id,source_sha256,completed_at,payload"
        database.execute(
            f"INSERT INTO validations ({columns}) VALUES (?,?,?,?)",
            (
                "scenario-a",
                "frozen-source-fingerprint",
                456,
                json.dumps(payload["validation_cache"]),
            ),
        )
        if "dependency_health" in existing:
            database.execute(
                "INSERT INTO dependency_health VALUES (?,?)",
                ("scenario-a", json.dumps(payload["dependency_cache"])),
            )
        for record in payload["views"]:
            database.execute(
                "INSERT INTO views VALUES (?,?,?)",
                (str(root / "workspace"), record["name"], json.dumps(record)),
            )
        database.execute("INSERT INTO folders VALUES (?,?)", (str(root / "workspace"), "Exercises"))
        if "library_preferences" in existing:
            database.execute(
                "INSERT INTO library_preferences VALUES (?,?)",
                (str(root / "workspace"), json.dumps(payload["library_preferences"])),
            )
        if "removed_job_history" in existing:
            database.execute("INSERT INTO removed_job_history VALUES (?)", ("removed-job",))
        database.execute(
            "INSERT INTO workspace_preferences VALUES (?,?)",
            (str(root / "workspace"), str(root / "exports")),
        )
    return selected


def inventory(database: Path) -> dict[str, list[tuple[object, ...]]]:
    """Read preserved base columns independently of implementation fingerprints."""
    result: dict[str, list[tuple[object, ...]]] = {}
    with (
        closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as connection,
        connection,
    ):
        for (table,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ):
            if table.startswith(("sqlite_", "studio_", "items_fts")):
                continue
            columns = [
                row[1]
                for row in connection.execute(f'PRAGMA table_info("{table}")')
                if row[1] not in {"search_entries", "dependency_sha256"}
            ]
            query = ",".join(f'"{name}"' for name in columns)
            rows = list(connection.execute(f'SELECT {query} FROM "{table}" ORDER BY 1'))
            # Compare historical facts independently of the reviewed version-2 null defaults.
            if table in {"items", "conversations"} and "payload" in columns:
                position = columns.index("payload")
                field = "display_name" if table == "items" else "draft_display_name"
                for index, row in enumerate(rows):
                    payload = json.loads(row[position])
                    if payload.get(field) is None:
                        payload.pop(field, None)
                    values = list(row)
                    values[position] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
                    rows[index] = tuple(values)
            result[table] = rows
    for table in (
        "imported_bundles",
        "removed_job_history",
        "library_preferences",
        "dependency_health",
        "resource_predictions",
    ):
        result.setdefault(table, [])
    return result
