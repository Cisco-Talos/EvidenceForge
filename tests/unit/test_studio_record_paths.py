"""SQL/JSON path identity stays consistent without resetting existing records."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from evidenceforge.desktop.library import LibraryItem
from evidenceforge.studio.state_database import (
    DATABASE_VERSION,
    _same_record_path,
    database_digest,
    inspect_database,
)
from evidenceforge.studio.state_io import StudioStateError, private_directory
from evidenceforge.studio.store import Conversation, ImportedBundle, Project, StudioStore

PROJECTIONS = {
    "items": ("id", "workspace", "kind", "path"),
    "projects": ("id", "workspace", "name"),
    "conversations": ("id", "workspace"),
    "imported_bundles": ("id", "workspace", "root"),
}


@pytest.mark.parametrize(
    ("left", "right", "equivalent"),
    [
        (r"c:\Users\david\EvidenceForge", r"C:\Users\david\EvidenceForge", True),
        (r"d:\Missing\Historical", r"D:\Missing\Historical", True),
        (r"c:\Users\david", r"D:\Users\david", False),
        (r"C:\Users\david", r"c:\Users\David", False),
        (r"C:\Users\david", r"c:\Users\david\other", False),
        (r"C:\Users\david", r"c:\Users\other\..\david", False),
        (r"C:relative", r"c:relative", False),
        ("K:\\Data", "K:\\Data", False),
        (r"\\server\Share", r"\\SERVER\Share", False),
        ("/Users/david", "/users/david", False),
        (None, r"C:\Users\david", False),
    ],
)
def test_only_absolute_windows_drive_letter_case_is_an_alias(
    left: object, right: object, equivalent: bool
) -> None:
    assert _same_record_path(left, right, windows=True) is equivalent
    assert not _same_record_path(left, right, windows=False)


def _write_records(store: StudioStore, workspace: Path) -> dict[str, str]:
    source = workspace / "scenario.yaml"
    source.write_text("name: record-identity-test\ndescription: test\n")
    item = store.upsert_item(workspace, "scenario", LibraryItem(path=source, name="test"))
    item.hidden = True
    store.save_item(item)
    project = Project(workspace=workspace, name="Test project")
    store.save_project(project)
    conversation = Conversation(workspace=workspace, item_id=item.id)
    store.save_conversation(conversation)
    bundle = ImportedBundle(
        workspace=workspace,
        root=workspace / "bundle",
        scenario_name="test",
        created_at=1.0,
        size_bytes=0,
        manifest_sha256="test",
    )
    store.save_imported_bundle(bundle)
    return {
        "items": item.id,
        "projects": project.id,
        "conversations": conversation.id,
        "imported_bundles": bundle.id,
    }


def test_writers_persist_resolved_paths_in_both_sql_and_json(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "nested").mkdir(parents=True)
    private = tmp_path / "private"
    private_directory(private)
    database = private / "studio.sqlite"
    store = StudioStore(database)
    try:
        identities = _write_records(store, workspace / "nested" / "..")
    finally:
        store.close()
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        for table, fields in PROJECTIONS.items():
            row = connection.execute(f"SELECT * FROM {table}").fetchone()
            payload = json.loads(row["payload"])
            assert row["id"] == identities[table]
            assert all(row[field] == payload[field] for field in fields)
            assert payload["workspace"] == str(workspace.resolve())
    assert inspect_database(database) == DATABASE_VERSION


@pytest.mark.skipif(os.name != "nt", reason="Existing native Windows drive aliases")
def test_existing_drive_case_aliases_reopen_without_rewriting_or_losing_identity(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    private = tmp_path / "private"
    private_directory(private)
    database = private / "studio.sqlite"
    store = StudioStore(database)
    try:
        lower_workspace = Path(str(workspace.resolve())[0].lower() + str(workspace.resolve())[1:])
        identities = _write_records(store, lower_workspace)
    finally:
        store.close()
    with closing(sqlite3.connect(database)) as connection, connection:
        for table, fields in PROJECTIONS.items():
            connection.row_factory = sqlite3.Row
            row = connection.execute(f"SELECT * FROM {table}").fetchone()
            payload = json.loads(row["payload"])
            assert all(row[field] == payload[field] for field in fields)
            for field in set(fields) & {"workspace", "path", "root"}:
                original = payload[field]
                payload[field] = original[0].lower() + original[1:]
                assert payload[field] != original
            connection.execute(f"UPDATE {table} SET payload=?", (json.dumps(payload),))
    before = database_digest(database)
    assert inspect_database(database) == DATABASE_VERSION
    assert database_digest(database) == before
    store = StudioStore(database)
    try:
        assert store.item(identities["items"]).hidden
        assert store.project(identities["projects"]).id == identities["projects"]
        assert store.conversations(workspace)[0].id == identities["conversations"]
        assert store.imported_bundles(workspace)[0].id == identities["imported_bundles"]
    finally:
        store.close()
    assert database_digest(database) == before
    # Equivalent path spelling never permits a different stable record identity.
    with closing(sqlite3.connect(database)) as connection, connection:
        payload = json.loads(connection.execute("SELECT payload FROM items").fetchone()[0])
        payload["id"] = "other-record"
        connection.execute("UPDATE items SET payload=?", (json.dumps(payload),))
    with pytest.raises(StudioStateError, match="identity mismatch"):
        inspect_database(database)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows Studio restart")
def test_studio_startup_recovers_legacy_lowercase_workspace_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.studio.service import create_app
    from tests.support.studio_state import paths

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = paths(tmp_path / "app")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    first = create_app(selected, "record-case-test")
    studio = first.state.studio
    assert studio is not None
    try:
        identities = _write_records(studio.store, workspace)
    finally:
        studio.store.close()
        studio.workspace_coordinator.close()
        studio.coordinator.close()
    with closing(sqlite3.connect(selected.database_file)) as connection, connection:
        for table in ("items", "conversations"):
            for identity, raw in connection.execute(f"SELECT id,payload FROM {table}").fetchall():
                payload = json.loads(raw)
                value = payload["workspace"]
                payload["workspace"] = value[0].lower() + value[1:]
                connection.execute(
                    f"UPDATE {table} SET payload=? WHERE id=?", (json.dumps(payload), identity)
                )
    reopened = create_app(selected, "record-case-test")
    studio = reopened.state.studio
    assert studio is not None, "Equivalent drive spelling must not block service startup"
    try:
        assert studio.store.item(identities["items"]).id == identities["items"]
        assert studio.store.conversations(workspace)[0].id == identities["conversations"]
    finally:
        studio.store.close()
        studio.workspace_coordinator.close()
        studio.coordinator.close()
