"""Synthetic future contracts exercise consecutive SQL, JSON, settings and file upgrades."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.studio.state_database import MIGRATIONS, Migration, migrate_database
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.state_migrations import (
    SETTINGS_MIGRATIONS,
    FileMove,
    FilesystemMigration,
    JsonChange,
    RecordChange,
    SettingsMigration,
    ordered_chain,
)
from evidenceforge.studio.state_upgrade import StateCoordinator
from tests.support.studio_state import legacy

MOVES = (
    FilesystemMigration(
        id="test-layout-0002",
        source=1,
        target=2,
        description="Relocate saved Studio view files",
        affected=(".eforge/studio/old/view.json", ".eforge/studio/intermediate/view.json"),
        moves=(
            FileMove(
                source=".eforge/studio/old/view.json",
                target=".eforge/studio/intermediate/view.json",
            ),
        ),
    ),
    FilesystemMigration(
        id="test-layout-0003",
        source=2,
        target=3,
        description="Relocate files into final Studio convention",
        affected=(".eforge/studio/intermediate/view.json", ".eforge/studio/current/view.json"),
        moves=(
            FileMove(
                source=".eforge/studio/intermediate/view.json",
                target=".eforge/studio/current/view.json",
            ),
        ),
    ),
)


def test_consecutive_sql_and_json_transforms_preserve_ids_and_timestamps(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    migrations = (
        *MIGRATIONS,
        Migration(
            id="test-db-0002",
            source=1,
            target=2,
            description="Rename a historical JSON field",
            sql="CREATE TABLE test_metadata (name TEXT PRIMARY KEY)",
            records=(
                RecordChange(
                    table="conversations",
                    changes=(JsonChange(action="rename", field="title", target="label"),),
                ),
            ),
        ),
        Migration(
            id="test-db-0003",
            source=2,
            target=3,
            description="Add a frozen semantic default",
            sql="ALTER TABLE test_metadata ADD COLUMN revision INTEGER DEFAULT 3",
            records=(
                RecordChange(
                    table="conversations",
                    changes=(JsonChange(action="default", field="archived", literal="false"),),
                ),
            ),
        ),
    )
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        before = [
            json.loads(row[0])
            for row in connection.execute("SELECT payload FROM conversations ORDER BY id")
        ]
    migrate_database(selected.database_file, "test-runtime", migrations=migrations)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        after = [
            json.loads(row[0])
            for row in connection.execute("SELECT payload FROM conversations ORDER BY id")
        ]
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert dict(connection.execute("SELECT id,checksum FROM studio_migrations")) == {
            entry.id: entry.checksum for entry in migrations
        }
    for old, new in zip(before, after, strict=True):
        assert new == {
            **{key: value for key, value in old.items() if key != "title"},
            "label": old["title"],
            "archived": False,
        }
    migrate_database(selected.database_file, "test-runtime", migrations=migrations)
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        assert [
            json.loads(row[0])
            for row in connection.execute("SELECT payload FROM conversations ORDER BY id")
        ] == after


def test_settings_chain_uses_frozen_literals_and_retains_unspecified_values() -> None:
    second = SettingsMigration(
        id="test-settings-0002",
        source=1,
        target=2,
        description="Rename envelope key",
        changes=(
            JsonChange(action="rename", field="settings", target="preferences"),
            JsonChange(action="default", field="migration_epoch", literal="123"),
        ),
    )
    third = SettingsMigration(
        id="test-settings-0003",
        source=2,
        target=3,
        description="Add new version marker",
        changes=(
            JsonChange(action="rename", field="schema_version", target="previous_version"),
            JsonChange(action="default", field="schema_version", literal="3"),
        ),
    )
    chain = (*SETTINGS_MIGRATIONS, second, third)
    selected = ordered_chain(chain, "settings", 0, 3)
    values: dict[str, object] = {"workspace": "/Ünicode", "custom": None, "timestamp": 456}
    expected = dict(values)
    for migration in selected:
        assert isinstance(migration, SettingsMigration)
        values = migration.apply(values)
    assert values == {
        "preferences": expected,
        "previous_version": 1,
        "schema_version": 3,
        "migration_epoch": 123,
    }
    with pytest.raises(StudioStateError, match="gap"):
        ordered_chain((chain[0], chain[2]), "settings", 0, 3)


@pytest.mark.parametrize("restore", [False, True])
def test_consecutive_directory_relocations_are_backed_up_and_recoverable(
    tmp_path: Path, restore: bool
) -> None:
    selected = legacy(tmp_path)
    workspace = tmp_path / "workspace"
    baseline = StateCoordinator(selected, workspace)
    assert baseline.apply(baseline.status.operation_id).state == "ready"
    old_marker = baseline.layout.read_bytes()
    baseline.close()
    original = workspace / MOVES[0].moves[0].source
    original.parent.mkdir()
    original.write_bytes(b'{"id":"stable-view","name":"Unicode \\u00dc","timestamp":456}')
    original_bytes = original.read_bytes()
    engine = (tmp_path / "immutable.yaml").read_bytes()
    destination = workspace / MOVES[1].moves[0].target
    fired = False

    def observer(name: str) -> None:
        nonlocal fired
        if (
            name == f"{StateCoordinator.file_key(MOVES[1].moves[0].target)}.after_replace"
            and not fired
        ):
            fired = True
            raise OSError("Interrupted filesystem step publication")

    coordinator = StateCoordinator(selected, workspace, observer=observer, file_migrations=MOVES)
    identity = coordinator.status.operation_id
    assert coordinator.apply(identity).state == "failed"
    assert coordinator.layout.read_bytes() == old_marker  # Marker advances only after every step.
    coordinator.close()
    resumed = StateCoordinator(selected, workspace, file_migrations=MOVES)
    assert resumed.apply(identity, restore=restore).state == ("restored" if restore else "ready")
    if restore:
        assert original.read_bytes() == original_bytes and not destination.exists()
        assert resumed.layout.read_bytes() == old_marker
    else:
        assert not original.exists() and destination.read_bytes() == original_bytes
        marker = json.loads(resumed.layout.read_bytes())
        assert marker["layout_version"] == 3
        assert marker["identity"] == json.loads(old_marker)["identity"]
        assert all(marker["applied_migrations"][entry.id] == entry.checksum for entry in MOVES)
    assert (tmp_path / "immutable.yaml").read_bytes() == engine
    resumed.close()


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/absolute",
        ".eforge/studio/../../outside",
        "scenarios/scenario.yaml",
        ".eforge/studio/layout.json",
        ".eforge/studio/owner.lock",
    ],
)
def test_file_declarations_cannot_include_engine_or_external_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        FileMove(source=path, target=".eforge/studio/current/view.json")


def test_sql_registry_preserves_semicolons_in_literals_and_trigger_bodies(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    extra = Migration(
        id="test-db-0002",
        source=1,
        target=2,
        description="Exercise SQLite statement boundaries",
        sql="""
        CREATE TABLE test_values(value TEXT);
        CREATE TABLE test_audit(value TEXT);
        CREATE TRIGGER test_insert AFTER INSERT ON test_values BEGIN
            INSERT INTO test_audit VALUES ('first;second');
            INSERT INTO test_audit VALUES (new.value);
        END;
        INSERT INTO test_values VALUES ('preserved;literal');
        """,
    )
    migrate_database(selected.database_file, "test-runtime", migrations=(*MIGRATIONS, extra))
    with closing(sqlite3.connect(selected.database_file)) as connection:
        assert connection.execute("SELECT value FROM test_audit").fetchall() == [
            ("first;second",),
            ("preserved;literal",),
        ]


@pytest.mark.slow
def test_many_affected_files_use_bounded_copy_and_survive_restart(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    workspace = tmp_path / "workspace"
    baseline = StateCoordinator(selected, workspace)
    assert baseline.apply(baseline.status.operation_id).state == "ready"
    baseline.close()
    moves = tuple(
        FileMove(
            source=f".eforge/studio/old/{index}.bin",
            target=f".eforge/studio/new/{index}.bin",
        )
        for index in range(100)
    )
    content = b"owned UI state" * 10000
    for move in moves:
        source = workspace / move.source
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(content)
    migration = FilesystemMigration(
        id="test-layout-0002",
        source=1,
        target=2,
        description="Relocate many UI files",
        affected=tuple(path for move in moves for path in (move.source, move.target)),
        moves=moves,
    )
    coordinator = StateCoordinator(selected, workspace, file_migrations=(migration,))
    assert coordinator.apply(coordinator.status.operation_id).state == "ready"
    coordinator.close()
    reopened = StateCoordinator(selected, workspace, file_migrations=(migration,))
    assert reopened.status.state == "ready"
    assert all(
        not (workspace / move.source).exists() and (workspace / move.target).read_bytes() == content
        for move in moves
    )
    reopened.close()
