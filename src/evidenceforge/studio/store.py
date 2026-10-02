"""SQLite metadata and replayable events for the local desktop service."""

from __future__ import annotations

import hashlib
import json
import shlex
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.desktop.library import LibraryItem
from evidenceforge.desktop.state import EvaluationJob, GenerationJob


class CatalogItem(BaseModel):
    """Indexed scenario or pack; its source file remains authoritative."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace: Path
    kind: Literal["scenario", "industry_pack", "organization_pack"]
    path: Path
    name: str
    description: str = ""
    version: str = ""
    publisher: str = ""
    publisher_display_name: str = ""
    requires_evidenceforge: str = ""
    pack_source: str = ""
    modified_at: float = 0.0
    source_sha256: str = ""
    users: int = 0
    systems: int = 0
    events: int = 0
    folder: str | None = None
    project_id: str | None = None
    hidden: bool = False
    imported: bool = False


class Project(BaseModel):
    """A workspace-local group of scenarios and packs, independent of file paths."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    workspace: Path
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)
    updated_at: float = Field(default_factory=time.time)


class ImportedBundle(BaseModel):
    """A complete external CLI bundle indexed for read-only inspection."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    workspace: Path
    root: Path
    scenario_name: str
    created_at: float
    size_bytes: int
    manifest_sha256: str


class Conversation(BaseModel):
    """One Codex thread associated with a scenario, pack, or draft."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    workspace: Path
    item_id: str | None = None
    draft_kind: Literal["scenario", "industry_pack", "organization_pack"] | None = None
    draft_path: Path | None = None
    draft_project_id: str | None = None
    draft_name: str | None = None
    thread_id: str | None = None
    title: str = "New conversation"
    model_id: str | None = None
    reasoning_effort: str | None = None
    active: bool = False
    needs_attention: bool = False
    connection_note: str | None = None
    updated_at: float = Field(default_factory=time.time)


class StudioEvent(BaseModel):
    """One monotonically numbered change for reconnecting clients."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    entity_id: str
    kind: str
    payload: dict[str, Any]


class SavedView(BaseModel):
    """A named workspace library query."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    kind: Literal["scenario", "packs", "industry_pack", "organization_pack"] = "scenario"
    search: str = ""
    folder: str | None = None
    project_id: str | None = None
    ungrouped: bool = False
    show_hidden: bool = False
    publisher: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=80)
    pack_source: Literal["", "bundled", "workspace"] = ""


class StudioStore:
    """Single-writer metadata store shared by service request handlers."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                payload TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                UNIQUE (workspace, kind, path)
            );
            CREATE TABLE IF NOT EXISTS folders (
                workspace TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                name TEXT NOT NULL COLLATE NOCASE,
                payload TEXT NOT NULL,
                UNIQUE (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                item_id TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS removed_job_history (
                job_id TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS imported_bundles (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                root TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE (workspace, root)
            );
            CREATE TABLE IF NOT EXISTS validations (
                item_id TEXT PRIMARY KEY,
                source_sha256 TEXT NOT NULL,
                completed_at REAL NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dependency_health (
                item_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS views (
                workspace TEXT NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS workspace_preferences (
                workspace TEXT PRIMARY KEY,
                export_directory TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS items_workspace_idx ON items(workspace, kind);
            CREATE INDEX IF NOT EXISTS projects_workspace_idx ON projects(workspace);
            CREATE INDEX IF NOT EXISTS conversations_item_idx ON conversations(item_id);
            CREATE INDEX IF NOT EXISTS jobs_workspace_idx ON jobs(workspace, kind);
            CREATE INDEX IF NOT EXISTS imported_bundles_workspace_idx ON imported_bundles(workspace);
            """
        )
        self._db.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5(name, description, content)"
        )
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(validations)")}
        if "dependency_sha256" not in columns:
            self._db.execute(
                "ALTER TABLE validations ADD COLUMN dependency_sha256 TEXT NOT NULL DEFAULT ''"
            )
        self._db.commit()

    def close(self) -> None:
        """Close the owned SQLite connection."""
        with self._lock:
            self._db.close()

    def export_directory(self, workspace: Path) -> Path | None:
        """Return the last native export folder for one workspace."""
        with self._lock:
            row = self._db.execute(
                "SELECT export_directory FROM workspace_preferences WHERE workspace = ?",
                (str(workspace.resolve()),),
            ).fetchone()
        return Path(row["export_directory"]) if row and row["export_directory"] else None

    def set_export_directory(self, workspace: Path, directory: Path) -> None:
        """Remember a successful export folder without changing authored content."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO workspace_preferences(workspace, export_directory) VALUES (?, ?) "
                "ON CONFLICT(workspace) DO UPDATE SET export_directory = excluded.export_directory",
                (str(workspace.resolve()), str(directory.resolve())),
            )

    def publish(self, entity_id: str, kind: str, payload: dict[str, Any]) -> StudioEvent:
        """Save one event before it is sent to connected clients."""
        with self._lock, self._db:
            cursor = self._db.execute(
                "INSERT INTO events(entity_id, kind, payload) VALUES (?, ?, ?)",
                (entity_id, kind, json.dumps(payload, separators=(",", ":"))),
            )
            return StudioEvent(
                seq=int(cursor.lastrowid), entity_id=entity_id, kind=kind, payload=payload
            )

    def events_after(self, seq: int, limit: int = 500) -> list[StudioEvent]:
        """Load a bounded event page after a client cursor."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?", (seq, limit)
            ).fetchall()
        return [
            StudioEvent(
                seq=row["seq"],
                entity_id=row["entity_id"],
                kind=row["kind"],
                payload=json.loads(row["payload"]),
            )
            for row in rows
        ]

    def latest_seq(self) -> int:
        """Return the current event cursor."""
        with self._lock:
            row = self._db.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM events").fetchone()
        return int(row["seq"])

    def save_control(self, payload: BaseModel) -> None:
        """Durably hand off the active close or resume instruction."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO control(id, payload) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (payload.model_dump_json(),),
            )

    def load_control(self) -> dict[str, Any] | None:
        """Return the last acknowledged controller instruction."""
        with self._lock:
            row = self._db.execute("SELECT payload FROM control WHERE id=1").fetchone()
        return json.loads(row["payload"]) if row else None

    def upsert_item(
        self,
        workspace: Path,
        kind: Literal["scenario", "industry_pack", "organization_pack"],
        source: LibraryItem,
        *,
        imported: bool = False,
    ) -> CatalogItem:
        """Refresh file facts while preserving its stable ID and GUI organization."""
        workspace_key = str(workspace.resolve())
        path_key = str(source.path.resolve())
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT rowid, payload, content FROM items WHERE workspace=? AND kind=? AND path=?",
                (workspace_key, kind, path_key),
            ).fetchone()
            old = CatalogItem.model_validate_json(row["payload"]) if row else None
            item = CatalogItem(
                id=old.id if old else uuid4().hex,
                workspace=workspace,
                kind=kind,
                path=source.path,
                name=source.name,
                description=source.description,
                version=source.version,
                publisher=source.publisher,
                publisher_display_name=source.publisher_display_name,
                requires_evidenceforge=source.requires_evidenceforge,
                pack_source=source.pack_source,
                modified_at=source.modified_at,
                source_sha256=hashlib.sha256(source.path.read_bytes()).hexdigest(),
                users=source.users,
                systems=source.systems,
                events=source.events,
                folder=old.folder if old else None,
                project_id=old.project_id if old else None,
                hidden=old.hidden if old else False,
                imported=imported or (old.imported if old else False),
            )
            if row and item == old and source.search_text == row["content"]:
                return item
            self._db.execute(
                "INSERT INTO items(id, workspace, kind, path, payload, content) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "payload=excluded.payload, content=excluded.content",
                (
                    item.id,
                    workspace_key,
                    kind,
                    path_key,
                    item.model_dump_json(),
                    source.search_text,
                ),
            )
            item_row = self._db.execute("SELECT rowid FROM items WHERE id=?", (item.id,)).fetchone()
            self._db.execute("DELETE FROM items_fts WHERE rowid=?", (item_row["rowid"],))
            self._db.execute(
                "INSERT INTO items_fts(rowid, name, description, content) VALUES (?, ?, ?, ?)",
                (item_row["rowid"], item.name, item.description, source.search_text),
            )
        return item

    def item(self, item_id: str) -> CatalogItem | None:
        """Read one catalog item by stable identity."""
        with self._lock:
            row = self._db.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()
        return CatalogItem.model_validate_json(row["payload"]) if row else None

    def save_imported_bundle(self, bundle: ImportedBundle) -> ImportedBundle:
        """Keep one stable identity for each workspace-local external bundle path."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT id FROM imported_bundles WHERE workspace=? AND root=?",
                (str(bundle.workspace.resolve()), str(bundle.root.resolve())),
            ).fetchone()
            if row:
                bundle.id = row["id"]
            self._db.execute(
                "INSERT INTO imported_bundles(id, workspace, root, payload) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (
                    bundle.id,
                    str(bundle.workspace.resolve()),
                    str(bundle.root.resolve()),
                    bundle.model_dump_json(),
                ),
            )
        return bundle

    def imported_bundle(self, bundle_id: str) -> ImportedBundle | None:
        """Read one external bundle by its Studio identity."""
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM imported_bundles WHERE id=?", (bundle_id,)
            ).fetchone()
        return ImportedBundle.model_validate_json(row["payload"]) if row else None

    def imported_bundles(self, workspace: Path) -> list[ImportedBundle]:
        """List external bundles indexed in the selected workspace."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM imported_bundles WHERE workspace=? ORDER BY root",
                (str(workspace.resolve()),),
            ).fetchall()
        return [ImportedBundle.model_validate_json(row["payload"]) for row in rows]

    def remove_imported_bundle(self, bundle_id: str) -> None:
        """Forget a bundle without touching its files."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM imported_bundles WHERE id=?", (bundle_id,))

    def items(self, workspace: Path, kind: str | None = None) -> list[CatalogItem]:
        """List indexed items in one workspace."""
        query = "SELECT payload FROM items WHERE workspace=?"
        args: tuple[str, ...] = (str(workspace.resolve()),)
        if kind:
            query += " AND kind=?"
            args += (kind,)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return sorted(
            (CatalogItem.model_validate_json(row["payload"]) for row in rows),
            key=lambda item: item.name.casefold(),
        )

    def save_item(self, item: CatalogItem) -> None:
        """Update GUI metadata without rewriting an authored file."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE items SET payload=? WHERE id=?", (item.model_dump_json(), item.id)
            )

    def projects(self, workspace: Path) -> list[Project]:
        """List projects in a workspace without scanning source directories."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM projects WHERE workspace=? ORDER BY name COLLATE NOCASE",
                (str(workspace.resolve()),),
            ).fetchall()
        return [Project.model_validate_json(row["payload"]) for row in rows]

    def project(self, project_id: str) -> Project | None:
        """Read one project by its stable identity."""
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM projects WHERE id=?", (project_id,)
            ).fetchone()
        return Project.model_validate_json(row["payload"]) if row else None

    def save_project(self, project: Project) -> None:
        """Create or update a project, enforcing unique names per workspace."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO projects(id, workspace, name, payload) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, payload=excluded.payload",
                (
                    project.id,
                    str(project.workspace.resolve()),
                    project.name,
                    project.model_dump_json(),
                ),
            )

    def delete_project(
        self, project: Project
    ) -> tuple[list[CatalogItem], list[Conversation], list[SavedView]]:
        """Delete project metadata and ungroup its items, drafts, and views atomically."""
        changed: list[CatalogItem] = []
        changed_drafts: list[Conversation] = []
        changed_views: list[SavedView] = []
        with self._lock, self._db:
            rows = self._db.execute(
                "SELECT payload FROM items WHERE workspace=?",
                (str(project.workspace.resolve()),),
            ).fetchall()
            for row in rows:
                item = CatalogItem.model_validate_json(row["payload"])
                if item.project_id == project.id:
                    item.project_id = None
                    self._db.execute(
                        "UPDATE items SET payload=? WHERE id=?", (item.model_dump_json(), item.id)
                    )
                    changed.append(item)
            draft_rows = self._db.execute(
                "SELECT payload FROM conversations WHERE workspace=? AND item_id IS NULL",
                (str(project.workspace.resolve()),),
            ).fetchall()
            for row in draft_rows:
                conversation = Conversation.model_validate_json(row["payload"])
                if conversation.draft_project_id == project.id:
                    conversation.draft_project_id = None
                    self._db.execute(
                        "UPDATE conversations SET payload=? WHERE id=?",
                        (conversation.model_dump_json(), conversation.id),
                    )
                    changed_drafts.append(conversation)
            view_rows = self._db.execute(
                "SELECT name, payload FROM views WHERE workspace=?",
                (str(project.workspace.resolve()),),
            ).fetchall()
            for row in view_rows:
                view = SavedView.model_validate_json(row["payload"])
                if view.project_id == project.id:
                    view.project_id = None
                    view.ungrouped = True
                    self._db.execute(
                        "UPDATE views SET payload=? WHERE workspace=? AND name=?",
                        (view.model_dump_json(), str(project.workspace.resolve()), view.name),
                    )
                    changed_views.append(view)
            self._db.execute("DELETE FROM projects WHERE id=?", (project.id,))
        return changed, changed_drafts, changed_views

    def search_items(self, workspace: Path, query: str) -> list[CatalogItem]:
        """Search names, descriptions, and indexed YAML with optional field scopes."""
        try:
            terms = shlex.split(query.casefold())
        except ValueError:
            terms = query.casefold().split()
        if not terms:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT payload, content FROM items WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchall()
        found: list[CatalogItem] = []
        for row in rows:
            item = CatalogItem.model_validate_json(row["payload"])
            fields = {
                "name": item.name.casefold(),
                "description": item.description.casefold(),
                "yaml": row["content"].casefold(),
                "author": item.publisher_display_name.casefold(),
                "publisher": item.publisher.casefold(),
                "version": item.version.casefold(),
                "type": item.kind.removesuffix("_pack"),
                "location": item.pack_source,
                "compatibility": item.requires_evidenceforge.casefold(),
            }
            for term in terms:
                scope, separator, value = term.partition(":")
                if separator and scope in fields:
                    if value not in fields[scope]:
                        break
                elif not any(term in text for text in fields.values()):
                    break
            else:
                found.append(item)
                if len(found) == 200:
                    break
        return sorted(found, key=lambda item: item.name.casefold())

    def folders(self, workspace: Path) -> list[str]:
        """Return virtual folder names in display order."""
        with self._lock:
            rows = self._db.execute(
                "SELECT name FROM folders WHERE workspace=? ORDER BY name COLLATE NOCASE",
                (str(workspace.resolve()),),
            ).fetchall()
        return [str(row["name"]) for row in rows]

    def save_folder(self, workspace: Path, name: str) -> None:
        """Create an empty virtual folder without moving source files."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO folders(workspace, name) VALUES (?, ?)",
                (str(workspace.resolve()), name),
            )

    def rename_folder(self, workspace: Path, old_name: str, new_name: str) -> None:
        """Rename the folder and every indexed assignment atomically."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE folders SET name=? WHERE workspace=? AND name=?",
                (new_name, str(workspace.resolve()), old_name),
            )
            rows = self._db.execute(
                "SELECT id, payload FROM items WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchall()
            for row in rows:
                item = CatalogItem.model_validate_json(row["payload"])
                if item.folder == old_name:
                    item.folder = new_name
                    self._db.execute(
                        "UPDATE items SET payload=? WHERE id=?",
                        (item.model_dump_json(), item.id),
                    )
            view_rows = self._db.execute(
                "SELECT name, payload FROM views WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchall()
            for row in view_rows:
                view = SavedView.model_validate_json(row["payload"])
                if view.folder == old_name:
                    view.folder = new_name
                    self._db.execute(
                        "UPDATE views SET payload=? WHERE workspace=? AND name=?",
                        (view.model_dump_json(), str(workspace.resolve()), view.name),
                    )

    def delete_folder(self, workspace: Path, name: str) -> None:
        """Remove a virtual folder while retaining its source files."""
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM folders WHERE workspace=? AND name=?",
                (str(workspace.resolve()), name),
            )
            rows = self._db.execute(
                "SELECT id, payload FROM items WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchall()
            for row in rows:
                item = CatalogItem.model_validate_json(row["payload"])
                if item.folder == name:
                    item.folder = None
                    self._db.execute(
                        "UPDATE items SET payload=? WHERE id=?",
                        (item.model_dump_json(), item.id),
                    )
            view_rows = self._db.execute(
                "SELECT name, payload FROM views WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchall()
            for row in view_rows:
                view = SavedView.model_validate_json(row["payload"])
                if view.folder == name:
                    view.folder = None
                    self._db.execute(
                        "UPDATE views SET payload=? WHERE workspace=? AND name=?",
                        (view.model_dump_json(), str(workspace.resolve()), view.name),
                    )

    def views(self, workspace: Path) -> list[SavedView]:
        """Read saved library queries for one workspace."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM views WHERE workspace=? ORDER BY name COLLATE NOCASE",
                (str(workspace.resolve()),),
            ).fetchall()
        return [SavedView.model_validate_json(row["payload"]) for row in rows]

    def save_view(self, workspace: Path, view: SavedView) -> None:
        """Create or update a named workspace view."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO views(workspace, name, payload) VALUES (?, ?, ?) "
                "ON CONFLICT(workspace, name) DO UPDATE SET payload=excluded.payload",
                (str(workspace.resolve()), view.name, view.model_dump_json()),
            )

    def delete_view(self, workspace: Path, name: str) -> None:
        """Delete one saved view without changing its underlying items."""
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM views WHERE workspace=? AND name=?",
                (str(workspace.resolve()), name),
            )

    def save_conversation(self, conversation: Conversation) -> None:
        """Persist a conversation independently of its selected UI view."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO conversations(id, workspace, item_id, payload) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET item_id=excluded.item_id, payload=excluded.payload",
                (
                    conversation.id,
                    str(conversation.workspace.resolve()),
                    conversation.item_id,
                    conversation.model_dump_json(),
                ),
            )

    def conversations(self, workspace: Path, item_id: str | None = None) -> list[Conversation]:
        """List saved chats for a workspace or one scenario/pack."""
        query = "SELECT payload FROM conversations WHERE workspace=?"
        args: tuple[str, ...] = (str(workspace.resolve()),)
        if item_id is not None:
            query += " AND item_id=?"
            args += (item_id,)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return sorted(
            (Conversation.model_validate_json(row["payload"]) for row in rows),
            key=lambda chat: chat.updated_at,
            reverse=True,
        )

    def conversation(self, conversation_id: str) -> Conversation | None:
        """Read one saved conversation."""
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM conversations WHERE id=?", (conversation_id,)
            ).fetchone()
        return Conversation.model_validate_json(row["payload"]) if row else None

    def delete_conversation(self, conversation_id: str) -> None:
        """Remove one Studio conversation association and its local preferences."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM conversations WHERE id=?", (conversation_id,))

    def conversation_for_thread(self, thread_id: str) -> Conversation | None:
        """Resolve Codex events without depending on the current UI workspace."""
        with self._lock:
            rows = self._db.execute("SELECT payload FROM conversations").fetchall()
        return next(
            (
                conversation
                for row in rows
                if (conversation := Conversation.model_validate_json(row["payload"])).thread_id
                == thread_id
            ),
            None,
        )

    def active_conversations(self) -> list[Conversation]:
        """List active turns across workspaces for the quit policy."""
        with self._lock:
            rows = self._db.execute("SELECT payload FROM conversations").fetchall()
        return [
            conversation
            for row in rows
            if (conversation := Conversation.model_validate_json(row["payload"])).active
        ]

    def save_job(
        self, job_id: str, workspace: Path, kind: str, payload: GenerationJob | EvaluationJob
    ) -> None:
        """Durably publish a generation or evaluation job record."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO jobs(id, workspace, kind, payload) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (job_id, str(workspace.resolve()), kind, payload.model_dump_json()),
            )
            if payload.status in {"queued", "running", "paused"}:
                self._db.execute("DELETE FROM removed_job_history WHERE job_id=?", (job_id,))

    def delete_job(self, job_id: str) -> None:
        """Remove a job record after its app-owned bundle is safely deleted."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM removed_job_history WHERE job_id=?", (job_id,))
            self._db.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def remove_job_history(self, job_ids: list[str]) -> None:
        """Hide terminal jobs in Job center without losing run or scorecard metadata."""
        with self._lock, self._db:
            self._db.executemany(
                "INSERT OR IGNORE INTO removed_job_history(job_id) VALUES (?)",
                [(job_id,) for job_id in job_ids],
            )

    def removed_job_ids(self, workspace: Path) -> list[str]:
        """List history entries removed within the selected workspace."""
        with self._lock:
            rows = self._db.execute(
                "SELECT jobs.id FROM jobs JOIN removed_job_history ON jobs.id=job_id "
                "WHERE workspace=? ORDER BY jobs.id",
                (str(workspace.resolve()),),
            ).fetchall()
        return [row["id"] for row in rows]

    def save_validation(
        self, item_id: str, source_sha256: str, payload: BaseModel, dependency_sha256: str = ""
    ) -> None:
        """Retain the last validation and the exact authored file it checked."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO validations(item_id, source_sha256, completed_at, payload, dependency_sha256) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET "
                "source_sha256=excluded.source_sha256, completed_at=excluded.completed_at, "
                "payload=excluded.payload, dependency_sha256=excluded.dependency_sha256",
                (item_id, source_sha256, time.time(), payload.model_dump_json(), dependency_sha256),
            )

    def validations(self, item_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return saved validation records for the visible catalog items."""
        if not item_ids:
            return {}
        placeholders = ",".join("?" for _ in item_ids)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM validations WHERE item_id IN (" + placeholders + ")", item_ids
            ).fetchall()
        return {
            str(row["item_id"]): {
                "source_sha256": row["source_sha256"],
                "dependency_sha256": row["dependency_sha256"],
                "completed_at": row["completed_at"],
                "result": json.loads(row["payload"]),
            }
            for row in rows
        }

    def save_dependency_health(self, item_id: str, payload: BaseModel) -> None:
        """Persist dependency readiness for reopening a scenario workspace."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO dependency_health(item_id, payload) VALUES (?, ?) ON CONFLICT(item_id) DO UPDATE SET payload=excluded.payload",
                (item_id, payload.model_dump_json()),
            )

    def dependency_health(self, item_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return dependency checks scoped to visible catalog identities."""
        if not item_ids:
            return {}
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM dependency_health WHERE item_id IN ("
                + ",".join("?" for _ in item_ids)
                + ")",
                item_ids,
            ).fetchall()
        return {row["item_id"]: json.loads(row["payload"]) for row in rows}

    def job_payloads(
        self, workspace: Path | None = None, kind: str | None = None
    ) -> list[dict[str, Any]]:
        """Return JSON-compatible job records for API and reconciliation."""
        query = "SELECT payload FROM jobs WHERE 1=1"
        args: list[str] = []
        if workspace is not None:
            query += " AND workspace=?"
            args.append(str(workspace.resolve()))
        if kind is not None:
            query += " AND kind=?"
            args.append(kind)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return [json.loads(row["payload"]) for row in rows]
