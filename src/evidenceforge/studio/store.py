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
from evidenceforge.studio.search import SearchMatch, index_sources, matching_excerpts, yaml_entries


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
    search_excerpt: str = ""
    search_field: str = ""
    search_matches: list[SearchMatch] = Field(default_factory=list)
    search_match_count: int = 0
    search_revision: str = ""


class Project(BaseModel):
    """A workspace-local group of scenarios and packs, independent of file paths."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    workspace: Path
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)
    overlay_enabled: bool = False
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


class CodexTurnOutcome(BaseModel):
    """Terminal outcome observed from Codex, retained independently of its rollout."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["completed", "failed", "interrupted"]
    error: dict[str, Any] | None = None


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
    sort: Literal["name", "updated", "project"] = "name"
    expanded_groups: list[str] = Field(default_factory=list, max_length=1000)


class LibraryView(BaseModel):
    """Last selected library controls, independent of authored content."""

    model_config = ConfigDict(extra="forbid")

    search: str = Field(default="", max_length=256)
    project_id: str | None = None
    show_hidden: bool = False
    sort: Literal["name", "updated", "project"] = "name"
    pack_kind: Literal["packs", "industry_pack", "organization_pack"] = "packs"
    publisher: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=80)
    pack_source: Literal["", "bundled", "workspace"] = ""
    expanded_groups: list[str] = Field(default_factory=list, max_length=1000)


class LibraryPreferences(BaseModel):
    """Workspace-specific recall preference and independent library selections."""

    model_config = ConfigDict(extra="forbid")

    remember_view: bool = True
    scenarios: LibraryView = Field(default_factory=LibraryView)
    packs: LibraryView = Field(default_factory=LibraryView)


class StudioStore:
    """Single-writer metadata store shared by service request handlers."""

    def __init__(self, path: Path) -> None:
        from evidenceforge.studio.ownership import secure_directory

        secure_directory(path.parent)
        from evidenceforge.studio.runtime import runtime_id
        from evidenceforge.studio.state_database import (
            inspect_database,
            migrate_database,
            repair_derived,
        )
        from evidenceforge.studio.state_io import StudioStateError

        if path.exists():
            if inspect_database(path) != 1:
                raise StudioStateError("Studio database needs a backed-up upgrade before opening")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            migrate_database(path, runtime_id())
        repair_derived(path)
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")

    def close(self) -> None:
        """Close the owned SQLite connection."""
        with self._lock:
            self._db.close()

    def registered_workspaces(self) -> set[Path]:
        """Retain workspace identity beyond the bounded recent-selection list."""
        from evidenceforge.studio.state_database import tables

        registered: set[Path] = set()
        with self._lock:
            for table in tables(self._db):
                columns = {row[1] for row in self._db.execute(f'PRAGMA table_info("{table}")')}
                if "workspace" in columns:
                    registered.update(
                        Path(row[0]).absolute()
                        for row in self._db.execute(f'SELECT DISTINCT workspace FROM "{table}"')
                    )
            for (raw,) in self._db.execute("SELECT payload FROM jobs"):
                workspace = json.loads(raw).get("workspace")
                if workspace:
                    registered.add(Path(workspace).absolute())
        return registered

    def record_workspace_migrations(self, marker: Path) -> None:
        """Record completed workspace declarations without storing external conversation history."""
        from evidenceforge.studio.runtime import runtime_id
        from evidenceforge.studio.state_database import record_receipt
        from evidenceforge.studio.state_upgrade import LayoutDocument, read_json

        layout = LayoutDocument.model_validate(read_json(marker))
        with self._lock, self._db:
            for identity, checksum in layout.applied_migrations.items():
                record_receipt(
                    self._db,
                    f"{identity}:{layout.identity}",
                    checksum,
                    layout.app_version,
                    runtime_id(),
                )

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

    def library_preferences(self, workspace: Path) -> LibraryPreferences:
        """Read library recall settings for exactly one workspace."""
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM library_preferences WHERE workspace=?",
                (str(workspace.resolve()),),
            ).fetchone()
        return (
            LibraryPreferences.model_validate_json(row["payload"]) if row else LibraryPreferences()
        )

    def save_library_preferences(self, workspace: Path, preferences: LibraryPreferences) -> None:
        """Save GUI library preferences without changing export location or files."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO library_preferences(workspace, payload) VALUES (?, ?) "
                "ON CONFLICT(workspace) DO UPDATE SET payload=excluded.payload",
                (str(workspace.resolve()), preferences.model_dump_json()),
            )

    def set_library_recall(self, workspace: Path, remember_view: bool) -> LibraryPreferences:
        """Change recall without overwriting a concurrently saved library view."""
        with self._lock:
            preferences = self.library_preferences(workspace)
            preferences.remember_view = remember_view
            self.save_library_preferences(workspace, preferences)
            return preferences

    def save_library_view(
        self, workspace: Path, kind: Literal["scenarios", "packs"], view: LibraryView
    ) -> None:
        """Save one library's controls while preserving the other library and recall flag."""
        with self._lock:
            preferences = self.library_preferences(workspace)
            if kind == "scenarios":
                preferences.scenarios = view
            else:
                preferences.packs = view
            self.save_library_preferences(workspace, preferences)

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

    def codex_turn_outcomes(
        self, conversation_id: str, thread_id: str
    ) -> dict[str, CodexTurnOutcome]:
        """Recover terminal notifications that Codex history may omit or misclassify."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM events WHERE entity_id=? AND kind='conversation.event' "
                "ORDER BY seq",
                (conversation_id,),
            ).fetchall()
        outcomes: dict[str, CodexTurnOutcome] = {}
        for row in rows:
            event = json.loads(row["payload"])
            params = event.get("params", {})
            if event.get("method") != "turn/completed" or params.get("threadId") != thread_id:
                continue
            turn = params.get("turn", {})
            if not isinstance(turn, dict) or not isinstance(turn.get("id"), str):
                continue
            if turn.get("status") not in {"completed", "failed", "interrupted"}:
                continue
            error = turn.get("error")
            outcomes[turn["id"]] = CodexTurnOutcome.model_validate(
                {"status": turn["status"], "error": error if isinstance(error, dict) else None}
            )
        return outcomes

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
        sources = index_sources(source.path, source.search_text, kind == "scenario")
        content = "\n".join(sources.values())
        entries = json.dumps([entry.model_dump() for entry in yaml_entries(sources)])
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT rowid, payload, content, search_entries FROM items WHERE workspace=? AND kind=? AND path=?",
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
                search_revision=hashlib.sha256(content.encode()).hexdigest(),
                users=source.users,
                systems=source.systems,
                events=source.events,
                folder=old.folder if old else None,
                project_id=old.project_id if old else None,
                hidden=old.hidden if old else False,
                imported=imported or (old.imported if old else False),
            )
            if (
                row
                and item == old
                and content == row["content"]
                and entries == row["search_entries"]
            ):
                return item
            self._db.execute(
                "INSERT INTO items(id, workspace, kind, path, payload, content, search_entries) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "payload=excluded.payload, content=excluded.content, search_entries=excluded.search_entries",
                (
                    item.id,
                    workspace_key,
                    kind,
                    path_key,
                    item.model_dump_json(),
                    content,
                    entries,
                ),
            )
            item_row = self._db.execute("SELECT rowid FROM items WHERE id=?", (item.id,)).fetchone()
            self._db.execute("DELETE FROM items_fts WHERE rowid=?", (item_row["rowid"],))
            self._db.execute(
                "INSERT INTO items_fts(rowid, name, description, content) VALUES (?, ?, ?, ?)",
                (item_row["rowid"], item.name, item.description, content),
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

    def remove_pack(self, item_id: str) -> None:
        """Remove a retired pack's local associations, preserving Codex and run files."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT rowid, kind FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if row is None or row["kind"] not in {"industry_pack", "organization_pack"}:
                raise ValueError("Choose an indexed pack")
            self._db.execute("DELETE FROM items_fts WHERE rowid=?", (row["rowid"],))
            self._db.execute("DELETE FROM conversations WHERE item_id=?", (item_id,))
            self._db.execute("DELETE FROM validations WHERE item_id=?", (item_id,))
            self._db.execute("DELETE FROM dependency_health WHERE item_id=?", (item_id,))
            self._db.execute("DELETE FROM resource_predictions WHERE item_id=?", (item_id,))
            self._db.execute("DELETE FROM items WHERE id=?", (item_id,))

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

    def search_items(
        self, workspace: Path, query: str, match_limit: int = 5, kind: str | None = None
    ) -> list[CatalogItem]:
        """Search names, descriptions, and indexed YAML with optional field scopes."""
        try:
            terms = shlex.split(query.casefold())
        except ValueError:
            terms = query.casefold().split()
        if not terms:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT payload, content, search_entries FROM items WHERE workspace=?"
                + (" AND kind=?" if kind is not None else ""),
                (str(workspace.resolve()), kind)
                if kind is not None
                else (str(workspace.resolve()),),
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
                scoped_terms: list[tuple[str, str]] = []
                for term in terms:
                    scope, separator, value = term.partition(":")
                    scoped_terms.append(
                        (scope, value) if separator and scope in fields else ("", term)
                    )
                entries = [
                    SearchMatch.model_validate(entry) for entry in json.loads(row["search_entries"])
                ]
                entries.extend(
                    SearchMatch(field=key.title(), kind="metadata", excerpt=value)
                    for key, value in {
                        "name": item.name,
                        "description": item.description,
                        "author": item.publisher_display_name,
                        "publisher": item.publisher,
                        "version": item.version,
                        "type": item.kind.removesuffix("_pack"),
                        "location": item.pack_source,
                        "compatibility": item.requires_evidenceforge,
                    }.items()
                    if value
                )
                if not any(scope == "yaml" for scope, _ in scoped_terms):
                    matching_metadata = {
                        entry.field.casefold()
                        for entry in entries
                        if entry.kind == "metadata"
                        and any(
                            value in entry.excerpt.casefold()
                            for scope, value in scoped_terms
                            if not scope or scope == entry.field.casefold()
                        )
                    }
                    entries = [
                        entry
                        for entry in entries
                        if entry.kind == "metadata" or entry.field not in matching_metadata
                    ]
                matches, count = matching_excerpts(entries, scoped_terms, match_limit)
                found.append(
                    item.model_copy(
                        update={
                            "search_matches": matches,
                            "search_match_count": count,
                            "search_excerpt": matches[0].excerpt if matches else "",
                            "search_field": "YAML"
                            if matches and matches[0].kind != "metadata"
                            else matches[0].field
                            if matches
                            else "",
                        }
                    )
                )
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

    def save_resource_prediction(self, item_id: str, payload: BaseModel) -> None:
        """Persist a revision-bound prediction independently of validation."""
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO resource_predictions(item_id, payload) VALUES (?, ?) ON CONFLICT(item_id) DO UPDATE SET payload=excluded.payload",
                (item_id, payload.model_dump_json()),
            )

    def resource_predictions(self, item_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Read only the predictions belonging to these catalog identities."""
        if not item_ids:
            return {}
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM resource_predictions WHERE item_id IN ("
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
