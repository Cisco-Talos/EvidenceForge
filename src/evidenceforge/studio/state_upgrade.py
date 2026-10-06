"""Studio-only backup, automatic upgrade and pre-use recovery coordinator."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import shutil
import sqlite3
import stat
import threading
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

import psutil
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evidenceforge import __version__
from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.runtime import runtime_id
from evidenceforge.studio.state_database import (
    MIGRATIONS,
    database_digest,
    decode_record,
    inspect_database,
    migrate_database,
    open_readonly,
)
from evidenceforge.studio.state_io import (
    StateIO,
    StateLock,
    StudioStateError,
    file_checksum,
    private_directory,
    read_bytes,
    safe_path,
)
from evidenceforge.studio.state_migrations import (
    LAYOUT_MIGRATIONS,
    SETTINGS_MIGRATIONS,
    FilesystemMigration,
    ordered_chain,
)

logger = logging.getLogger(__name__)


def state_error(error: BaseException) -> str:
    """Report schema locations without copying saved user values into diagnostics."""
    if isinstance(error, ValidationError):
        locations = ", ".join(".".join(map(str, issue["loc"])) for issue in error.errors())
        return f"Invalid Studio state fields: {locations}; inspect or restore a verified backup"
    return str(error)


class VersionedDocument(BaseModel):
    """Strict integer version headers, including rejection of bool and float aliases."""

    @field_validator(
        "schema_version", "manifest_version", "layout_version", mode="before", check_fields=False
    )
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("State versions must be integers")
        return value


class LayoutDocument(VersionedDocument):
    """Current physical contract without changing any engine-owned format."""

    model_config = ConfigDict(extra="forbid")
    manifest_version: Literal[1] = 1
    layout_version: int = Field(default=1, ge=1)
    identity: str = Field(pattern=r"^[a-f0-9]{32}$")
    app_version: str
    runtime_id: str
    applied_migrations: dict[str, str] = Field(default_factory=dict)


class UpgradeStatus(BaseModel):
    """Public maintenance state, available independently of normal service stores."""

    model_config = ConfigDict(extra="forbid")
    state: Literal["ready", "pending", "running", "failed", "restored", "blocked"]
    scope: Literal["private", "workspace"] = "private"
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    phase: str = "Inspecting saved state"
    completed_steps: int = 0
    total_steps: int = 5
    incompatible: bool = False
    warning: str | None = None
    error: str | None = None
    backup_path: str | None = None
    can_retry: bool = False
    can_restore: bool = False
    versions: dict[str, int] = Field(default_factory=dict)
    target_versions: dict[str, int] = Field(default_factory=dict)


class OperationRequest(BaseModel):
    """Bind a maintenance request to the exact prepared operation."""

    model_config = ConfigDict(extra="forbid")
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class FileBackup(BaseModel):
    """Declarative destination with immutable before/after images."""

    model_config = ConfigDict(extra="forbid")
    key: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    existed: bool
    before: str | None
    after: str | None
    before_checksum: str | None
    after_checksum: str | None
    mode: int = 0o600


class BackupManifest(VersionedDocument):
    """Sealed package. Destinations are derived from scope, never accepted from this file."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    scope: Literal["private", "workspace"]
    root: str
    files: list[FileBackup]
    app_version: str
    runtime_id: str
    migrations: dict[str, str]
    original_locations: dict[str, str]
    source_versions: dict[str, int]
    target_versions: dict[str, int]
    created_at: str
    directories: dict[str, tuple[int, int]]


class OperationJournal(VersionedDocument):
    """Small durable record independent of the potentially changing database."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    status: UpgradeStatus
    manifest_sha256: str | None = None
    restoring: bool = False
    initial_settings: dict[str, object] | None = None
    initial_layout: LayoutDocument | None = None
    workspace_initialized: bool = False
    updated_at: str = ""


def sha(content: bytes) -> str:
    """Fingerprint one file image."""
    return hashlib.sha256(content).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    """Read a bounded regular state document without resolving links away."""
    safe_path(path)
    value = json.loads(read_bytes(path, 8 * 1024 * 1024))
    if not isinstance(value, dict):
        raise StudioStateError("Studio state document must be an object")
    return value


def json_bytes(value: BaseModel | dict[str, object]) -> bytes:
    """Serialize stable UTF-8 state."""
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2).encode()


def settings_document(path: Path) -> tuple[int, dict[str, object]]:
    """Decode the disk envelope before loading current settings models."""
    from evidenceforge.studio.state_records_v1 import StudioSettings

    if not path.exists():
        from evidenceforge.studio.settings import StudioSettings as CurrentSettings

        return 0, CurrentSettings().model_dump(mode="json")
    raw = read_json(path)
    version = raw.get("schema_version", 0)
    if type(version) is not int or version not in (0, 1):
        raise StudioStateError(
            f"Unsupported Studio settings version {version}; use a compatible release"
        )
    if version == 1:
        if set(raw) != {"schema_version", "settings"} or not isinstance(raw["settings"], dict):
            raise StudioStateError("Invalid versioned Studio settings envelope")
        values = raw["settings"]
    else:
        values = raw
    StudioSettings.model_validate(values)
    return version, values


def check_workers(database: Path) -> None:
    """Reject verified live or indeterminate retained workers; never terminate them."""
    if not database.exists():
        return
    with closing(open_readonly(database)) as connection:
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name='conversations'").fetchone():
            for (raw,) in connection.execute("SELECT payload FROM conversations"):
                if decode_record(raw, "conversations").get("active"):
                    raise StudioStateError(
                        "Retained authoring ownership is uncertain; finish it in the compatible "
                        "Studio build before upgrading"
                    )
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE name='jobs'").fetchone():
            return
        for (raw,) in connection.execute("SELECT payload FROM jobs"):
            job = decode_record(raw, "jobs")
            pid = job.get("pid", 0)
            if type(pid) is not int or pid < 0:
                raise StudioStateError(
                    "Retained worker PID is invalid; verify ownership before upgrading"
                )
            if not pid:
                if job.get("status", "running") == "running":
                    raise StudioStateError(
                        "Running job has no verifiable worker identity; resolve its ownership "
                        "in the compatible Studio build before upgrading"
                    )
                continue
            try:
                process = psutil.Process(pid)
                created = process.create_time()
                expected = job.get("process_created_at", 0)
                if (
                    type(expected) not in (int, float)
                    or not math.isfinite(expected)
                    or expected <= 0
                ):
                    raise StudioStateError(
                        "Retained worker ownership is uncertain; verify it before upgrading"
                    )
                if abs(created - expected) < 0.01 and process.status() != psutil.STATUS_ZOMBIE:
                    raise StudioStateError(
                        "A retained Studio worker is still running; finish or pause it first"
                    )
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as error:
                raise StudioStateError(
                    "Cannot verify a retained worker; retry when ownership is available"
                ) from error


class StateCoordinator:
    """Own one private or workspace contract until the normal application can use it."""

    def __init__(
        self,
        paths: StudioPaths,
        workspace: Path | None = None,
        observer: Callable[[str], None] = lambda _name: None,
        file_migrations: tuple[FilesystemMigration, ...] = (),
        io: StateIO | None = None,
    ) -> None:
        from evidenceforge.studio.ownership import validate_private_paths

        ownership_error: str | None = None
        try:
            validate_private_paths(paths)
        except (OSError, StudioStateError) as error:
            ownership_error = state_error(error)
        self.paths = paths
        self.workspace = workspace.absolute() if workspace is not None else None
        self.root = self.workspace or paths.data.absolute()
        self.scope: Literal["private", "workspace"] = "workspace" if workspace else "private"
        self.layout = (
            self.root / ".eforge/studio/layout.json"
            if workspace
            else self.root / "studio-state.json"
        )
        self.control_root = paths.data / "studio-upgrades"
        # Workspace journals are private and do not force writes into an unavailable workspace.
        self.pointer = self.control_root / (
            f"workspace-{sha(os.fsencode(self.root))[:24]}.json" if workspace else "active.json"
        )
        self.owner = StateLock(
            self.root / ".eforge/studio/owner.lock"
            if workspace
            else paths.state / "studio-data.lock"
        )
        self.observer = observer
        self.io = io or StateIO()
        self._bindings: dict[str, Path] | None = None
        self._ancestors: set[Path] | None = None
        self.file_migrations = file_migrations
        if file_migrations and not workspace:
            raise StudioStateError("Workspace file migrations require a workspace scope")
        self.layout_target = file_migrations[-1].target if file_migrations else 1
        self.database_receipts = (
            SETTINGS_MIGRATIONS[0],
            next(entry for entry in LAYOUT_MIGRATIONS if entry.family == "private_layout"),
        )
        ordered_chain(file_migrations, "workspace_layout", 1, self.layout_target)
        self.mutex = threading.RLock()
        self.runtime = runtime_id()
        self.status = UpgradeStatus(
            state="blocked",
            scope=self.scope,
            operation_id=uuid4().hex,
            target_versions={"workspace_layout": self.layout_target}
            if workspace
            else {
                "database": 1,
                "settings": 1,
                "private_layout": 1,
            },
        )
        self.journal = OperationJournal(status=self.status)
        self.prepared_inputs: dict[str, str | None] | None = None
        if ownership_error:
            self.status.error = ownership_error
            return
        self.inspect()
        if self.status.state == "pending" and not self.pointer.exists():
            try:
                self.prepared_inputs = {
                    key: self.snapshot_digest(key, path)
                    for key, path in self.destinations().items()
                }
            except (OSError, ValueError, sqlite3.Error, StudioStateError) as error:
                self.status.state = "blocked"
                self.status.error = state_error(error)
                self.status.can_retry = False

    def recheck_prepared_inputs(self) -> None:
        """Refuse a changed inspection rather than upgrading an obsolete prepared operation."""
        if self.prepared_inputs is not None and self.prepared_inputs != {
            key: self.snapshot_digest(key, path) for key, path in self.destinations().items()
        }:
            raise StudioStateError("Prepared state changed; reopen Studio to inspect it again")

    def prepare(self) -> None:
        """Hold ownership and recheck before the frontend displays an upgrade warning."""
        if self.status.state != "pending":
            return
        try:
            self.owner.acquire()
            self.recheck_prepared_inputs()
            check_workers(self.paths.database_file)
        except (OSError, ValueError, sqlite3.Error, StudioStateError) as error:
            self.status.state = "failed"
            self.status.error = state_error(error)
            self.status.can_retry = True

    def destinations(self) -> dict[str, Path]:
        """Return code-owned file bindings for this scope."""
        if self._bindings is not None:
            return self._bindings
        if self.workspace:
            files = {
                self.file_key(relative): self.root / relative
                for entry in self.file_migrations
                for move in entry.moves
                for relative in (move.source, move.target)
            }
            self._bindings = {**files, "layout": self.layout}
            return self._bindings
        self._bindings = {
            "settings": self.paths.settings_file,
            "layout": self.layout,
            "database": self.paths.database_file,
        }
        return self._bindings

    @staticmethod
    def file_key(relative: str) -> str:
        """Use a stable opaque key; recovery paths always come from declarations."""
        return f"file-{sha(relative.encode())}"

    def declared_migrations(self) -> dict[str, str]:
        """Return the exact code-owned declarations accepted by this operation."""
        layout = next(
            entry for entry in LAYOUT_MIGRATIONS if entry.family == f"{self.scope}_layout"
        )
        entries = (
            (layout, *self.file_migrations)
            if self.workspace
            else (
                *MIGRATIONS,
                *SETTINGS_MIGRATIONS,
                layout,
            )
        )
        return {entry.id: entry.checksum for entry in entries}

    def read_layout(self) -> LayoutDocument:
        """Reject unknown versions and verify recorded immutable declarations."""
        document = LayoutDocument.model_validate(read_json(self.layout))
        versions = {1, *(entry.target for entry in self.file_migrations)}
        if document.layout_version not in versions:
            raise StudioStateError("Unsupported Studio layout version; use a compatible release")
        declared = {
            entry.id: entry.checksum
            for entry in (*LAYOUT_MIGRATIONS, *self.file_migrations)
            if entry.family == f"{self.scope}_layout" and entry.target <= document.layout_version
        }
        if document.applied_migrations != declared:
            raise StudioStateError("Studio layout migration declarations changed")
        return document

    @property
    def package(self) -> Path:
        """Locate exactly one bound operation package."""
        return self.control_root / self.status.operation_id

    def close(self) -> None:
        """Release coordinator ownership."""
        self.owner.close()

    def boundary(self, name: str) -> None:
        """Provide a deterministic test observation boundary, never an environment hook."""
        self.observer(name)

    def inspect(self) -> None:
        """Inspect versions and retained recovery state without rewriting protected data."""
        completed_operation = False
        try:
            safe_path(self.root)
            if self.workspace and not self.root.is_dir():
                raise StudioStateError("Workspace is unavailable; choose an existing workspace")
            if self.pointer.exists():
                self.journal = OperationJournal.model_validate(read_json(self.pointer))
                self.status = self.journal.status
                package_journal = self.package / "journal.json"
                if package_journal.exists():
                    latest = OperationJournal.model_validate(read_json(package_journal))
                    if (
                        latest.status.operation_id != self.status.operation_id
                        or latest.status.scope != self.scope
                        or self.journal.manifest_sha256 is not None
                        and latest.manifest_sha256 != self.journal.manifest_sha256
                    ):
                        raise StudioStateError(
                            "Recovery journals disagree about operation ownership"
                        )
                    self.journal = latest
                    self.status = latest.status
                if self.status.scope != self.scope:
                    raise StudioStateError("Recovery scope does not match this state")
                if self.status.state not in {"ready", "restored"}:
                    self.status.state = "pending"
                    self.status.can_retry = True
                    if self.journal.manifest_sha256:
                        self.verify_backup()
                        self.status.can_restore = True
                    return
                if self.status.state == "restored":
                    self.status.can_retry = True
                    return
                self.status.warning = None
                self.status.incompatible = False
                completed_operation = True
            if self.layout.exists():
                layout = self.read_layout()
                if self.workspace:
                    self.status.versions = {"workspace_layout": layout.layout_version}
                if self.workspace and layout.layout_version == self.layout_target:
                    self.status.state = "ready"
                    return
            if self.workspace:
                version = self.read_layout().layout_version if self.layout.exists() else 0
                self.status.versions = {"workspace_layout": version}
                self.status.incompatible = any(entry.incompatible for entry in self.file_migrations)
            if not self.workspace:
                database = inspect_database(self.paths.database_file)
                settings, _values = settings_document(self.paths.settings_file)
                if self.layout.exists() and (not database or not settings):
                    raise StudioStateError(
                        "Versioned Studio state is incomplete; inspect its recovery backup"
                    )
                self.status.versions = {
                    "database": database,
                    "settings": settings,
                    "private_layout": self.read_layout().layout_version
                    if self.layout.exists()
                    else 0,
                }
                if database == settings == 1 and self.layout.exists():
                    self.verify_private_receipts()
                    self.status.state = "ready"
                    return
                self.status.incompatible = bool(
                    self.paths.settings_file.exists()
                    and settings == 0
                    or self.paths.database_file.exists()
                    and database == 0
                )
            if completed_operation:
                # A later release needs its own package, never the previous successful
                # operation's seal or original images.
                self.status.operation_id = uuid4().hex
                self.status.backup_path = None
                self.status.error = None
                self.status.can_restore = False
                self.status.completed_steps = 0
                self.status.target_versions = (
                    {"workspace_layout": self.layout_target}
                    if self.workspace
                    else {"database": 1, "settings": 1, "private_layout": 1}
                )
                self.journal = OperationJournal(status=self.status)
            self.status.state = "pending"
            self.status.can_retry = True
            if self.status.incompatible:
                self.status.warning = (
                    "Studio will upgrade your saved UI state. Earlier unversioned Studio builds "
                    "cannot safely use it. A verified recovery backup will be kept."
                )
                if self.workspace:
                    self.status.warning = (
                        "Studio will upgrade this workspace's UI conventions. Earlier Studio "
                        "builds cannot use the new layout. A verified recovery backup will be kept."
                    )
        except (OSError, ValueError, sqlite3.Error, StudioStateError) as error:
            self.status.state = "blocked"
            self.status.error = state_error(error)
            self.status.can_retry = False
            self.status.can_restore = False

    def verify_private_receipts(self) -> None:
        """A completed private layout must agree with its shared database ledger."""
        with closing(open_readonly(self.paths.database_file)) as connection:
            recorded = dict(connection.execute("SELECT id,checksum FROM studio_migrations"))
        if any(recorded.get(entry.id) != entry.checksum for entry in self.database_receipts):
            raise StudioStateError(
                "Studio private contracts are missing their migration ledger receipts"
            )

    def initialize_if_fresh(self) -> None:
        """Initialize brand-new contracts without a compatibility warning or backup."""
        if self.status.state != "pending" or self.pointer.exists():
            return
        if self.workspace or self.paths.database_file.exists():
            return
        if self.paths.settings_file.exists():
            return
        try:
            self.owner.acquire()
            if any(path.exists() for path in self.destinations().values()):
                raise StudioStateError("State appeared during initialization; reinspect it")
            self.journal.initial_settings = settings_document(self.paths.settings_file)[1]
            self.journal.initial_layout = LayoutDocument(
                identity=uuid4().hex,
                app_version=__version__,
                runtime_id=self.runtime,
                applied_migrations={
                    entry.id: entry.checksum
                    for entry in LAYOUT_MIGRATIONS
                    if entry.family == "private_layout"
                },
            )
            self.persist()
            self._fresh()
        except (OSError, ValueError, sqlite3.Error, StudioStateError) as error:
            self.status.state = "failed"
            self.status.error = state_error(error)
            self.status.can_retry = True

    def _fresh(self) -> None:
        """Resume only an empty new database and the frozen initial document images."""
        from evidenceforge.studio.state_database import tables

        layout, values = self.journal.initial_layout, self.journal.initial_settings
        if layout is None or values is None:
            raise StudioStateError("Fresh initialization has no frozen input proof")
        settings_image = json_bytes({"schema_version": 1, "settings": values})
        layout_image = json_bytes(layout)
        for path in self.destinations().values():
            safe_path(path)
        for path, expected in (
            (self.paths.settings_file, settings_image),
            (self.layout, layout_image),
        ):
            if path.exists() and read_bytes(path) != expected:
                raise StudioStateError("New state changed independently during initialization")
        private_directory(self.root)
        if self.paths.database_file.exists() and database_digest(self.paths.database_file) != sha(
            b"0"
        ):
            inspect_database(self.paths.database_file)
            with closing(open_readonly(self.paths.database_file)) as connection:
                if any(
                    connection.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone()
                    for table in tables(connection)
                    if table != "studio_migrations"
                ):
                    raise StudioStateError("New database contains independently added records")
        migrate_database(
            self.paths.database_file,
            layout.runtime_id,
            self.observer,
            receipts=self.database_receipts,
            app_version=layout.app_version,
        )
        self.boundary("settings.before_replace")
        self.io.write(self.paths.settings_file, settings_image)
        self.boundary("settings.after_replace")
        self.boundary("layout.before_replace")
        self.io.write(self.layout, layout_image)
        self.boundary("layout.after_replace")
        inspect_database(self.paths.database_file)
        settings_document(self.paths.settings_file)
        self.read_layout()
        self.verify_private_receipts()
        self.boundary("completion.before")
        terminal = self.status.model_copy(
            update={
                "state": "ready",
                "phase": "Studio is ready",
                "can_retry": False,
                "completed_steps": self.status.total_steps,
                "versions": dict(self.status.target_versions),
            }
        )
        self.journal.status = terminal
        self.persist()
        self.boundary("completion.after")
        self.status = terminal

    def initialize_workspace_if_fresh(self, created: bool) -> None:
        """Initialize only a workspace this UI just explicitly created, without a backup."""
        if (
            not created
            or not self.workspace
            or self.status.state != "pending"
            or self.pointer.exists()
        ):
            return
        self.owner.acquire()
        check_workers(self.paths.database_file)
        if self.layout.exists():
            raise StudioStateError("Workspace state appeared during initialization; reinspect it")
        document = LayoutDocument(
            identity=uuid4().hex,
            app_version=__version__,
            runtime_id=self.runtime,
            applied_migrations=self.declared_migrations(),
        )
        self.io.write(self.layout, json_bytes(document))
        self.read_layout()
        self.status.state = "ready"
        self.status.phase = "Studio is ready"
        self.status.versions = {"workspace_layout": 1}
        self.status.can_retry = False

    def persist(self) -> None:
        """Publish the operation journal independently of all protected files."""
        progress = self.journal.status
        label = (
            f"journal.{'restore' if self.journal.restoring else 'upgrade'}."
            f"{progress.state}.{progress.completed_steps}"
        )
        self.boundary(f"{label}.before_write")
        self.boundary("journal.before_write")
        self.journal.updated_at = datetime.now(UTC).isoformat()
        content = json_bytes(self.journal)
        publications = {"pointer": self.pointer}
        if self.package.is_dir():
            publications = {"package": self.package / "journal.json", **publications}
        for name, path in publications.items():
            self.boundary(f"{label}.{name}.before_write")
            self.io.write(path, content)
            self.boundary(f"{label}.{name}.after_write")
        self.boundary("journal.after_write")
        self.boundary(f"{label}.after_write")

    def snapshot_digest(self, key: str, path: Path) -> str | None:
        """Recognize protected absence or exact before/after content."""
        safe_path(path)
        if not path.exists():
            return None
        return database_digest(path) if key == "database" else file_checksum(path)

    def create_backup(self) -> None:
        """Stage verified before and after images before publishing an active journal."""
        self.owner.acquire()
        if not self.workspace:
            private_directory(self.paths.config)
        private_directory(self.package)
        migration_time = datetime.now(UTC).isoformat()
        files: list[FileBackup] = []
        self.boundary("backup.before_create")
        proposed_files: dict[str, Path | None] = {}
        if self.file_migrations:
            original = {
                relative: self.root / relative if (self.root / relative).exists() else None
                for entry in self.file_migrations
                for move in entry.moves
                for relative in (move.source, move.target)
            }
            source_version = self.read_layout().layout_version if self.layout.exists() else 1
            for entry in self.file_migrations:
                if entry.target > source_version:
                    original = entry.stage(original)
            proposed_files = {
                self.file_key(relative): content for relative, content in original.items()
            }
        for key, path in self.destinations().items():
            before = self.snapshot_digest(key, path)
            mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
            target = self.package / f"{key}.before"
            proposed = self.package / f"{key}.after"
            if key == "database":
                self.io.write(proposed, b"")
                if before:
                    self.io.write(target, b"")
                    with (
                        closing(open_readonly(path)) as source,
                        closing(sqlite3.connect(target)) as output,
                    ):
                        self.io.backup(source, output)
                    # Publish database bytes durably after closing the backup connection.
                    self.io.flush(target)
                    self.io.copy(proposed, target)
                    if database_digest(target) != before:
                        raise StudioStateError(
                            "Database changed while backing up; retry after writers stop"
                        )
                migrate_database(
                    proposed,
                    self.runtime,
                    receipts=self.database_receipts,
                    applied_at=migration_time,
                )
                self.io.flush(proposed)
                after = database_digest(proposed)
            else:
                if before:
                    self.io.copy(target, path)
                if key in proposed_files:
                    proposal = proposed_files[key]
                    if proposal is not None:
                        self.io.copy(proposed, proposal)
                    after = file_checksum(proposed) if proposal is not None else None
                elif key == "settings":
                    _version, values = settings_document(path)
                    content = json_bytes(SETTINGS_MIGRATIONS[0].apply(values))
                    self.io.write(proposed, content)
                    after = sha(content)
                else:
                    previous = self.read_layout() if before else None
                    content = json_bytes(
                        LayoutDocument(
                            identity=previous.identity if previous else uuid4().hex,
                            app_version=__version__,
                            runtime_id=self.runtime,
                            layout_version=self.layout_target,
                            applied_migrations={
                                entry.id: entry.checksum
                                for entry in (*LAYOUT_MIGRATIONS, *self.file_migrations)
                                if entry.family == f"{self.scope}_layout"
                            },
                        )
                    )
                    self.io.write(proposed, content)
                    after = sha(content)
            if self.snapshot_digest(key, path) != before:
                raise StudioStateError(
                    "Protected state changed during backup; no upgrade was applied"
                )
            files.append(
                FileBackup(
                    key=key,
                    existed=before is not None,
                    before=before,
                    after=after,
                    mode=mode,
                    before_checksum=file_checksum(target) if before is not None else None,
                    after_checksum=file_checksum(proposed) if after is not None else None,
                )
            )
        manifest = BackupManifest(
            operation_id=self.status.operation_id,
            scope=self.scope,
            root=str(self.root),
            files=files,
            app_version=__version__,
            runtime_id=self.runtime,
            migrations=self.declared_migrations(),
            original_locations={key: str(path) for key, path in self.destinations().items()},
            source_versions=self.status.versions,
            target_versions=self.status.target_versions,
            created_at=migration_time,
            directories={
                str(path): self.directory_identity(path)
                for path in self.guarded_ancestors()
                if path.is_dir()
            },
        )
        self.boundary("backup.after_create")
        self.io.write(self.package / "manifest.json", json_bytes(manifest))
        self.journal.manifest_sha256 = sha(json_bytes(manifest))
        self.boundary("backup.before_verify")
        self.verify_backup()
        self.boundary("backup.after_verify")
        self.status.backup_path = str(self.package)
        self.status.total_steps = len(files) + 2
        self.status.can_restore = True
        self.boundary("backup.before_publish")
        self.persist()
        self.boundary("backup.after_publish")

    def verify_backup(self) -> BackupManifest:
        """Validate the complete seal and code-owned destination set."""
        manifest_path = self.package / "manifest.json"
        safe_path(manifest_path)
        if sha(read_bytes(manifest_path)) != self.journal.manifest_sha256:
            raise StudioStateError("Recovery manifest checksum mismatch")
        manifest = BackupManifest.model_validate(read_json(manifest_path))
        if (
            manifest.operation_id != self.status.operation_id
            or manifest.scope != self.scope
            or manifest.root != str(self.root)
            or sorted(entry.key for entry in manifest.files) != sorted(self.destinations())
            or manifest.migrations != self.declared_migrations()
            or manifest.original_locations
            != {key: str(path) for key, path in self.destinations().items()}
            or not set(manifest.directories) <= {str(path) for path in self.guarded_ancestors()}
            or str(self.root) not in manifest.directories
        ):
            raise StudioStateError(
                "Recovery package does not match the declared state destinations"
            )
        self.check_directories(manifest)
        for entry in manifest.files:
            for suffix, checksum in (
                ("before", entry.before_checksum),
                ("after", entry.after_checksum),
            ):
                path = self.package / f"{entry.key}.{suffix}"
                exists = entry.before is not None if suffix == "before" else entry.after is not None
                if (
                    exists != (checksum is not None)
                    or checksum is not None
                    and file_checksum(path) != checksum
                ):
                    raise StudioStateError(
                        "Recovery file checksum mismatch or incomplete image seal"
                    )
            for suffix, expected in (("before", entry.before), ("after", entry.after)):
                path = self.package / f"{entry.key}.{suffix}"
                if expected is not None and self.snapshot_digest(entry.key, path) != expected:
                    raise StudioStateError(
                        f"Recovery image is missing or corrupt: {entry.key}.{suffix}"
                    )
            if entry.existed != (entry.before is not None):
                raise StudioStateError("Recovery absence record is inconsistent")
        return manifest

    def guarded_ancestors(self) -> set[Path]:
        """Derive the exact allowed directory set from code-owned roots and files."""
        if self._ancestors is not None:
            return self._ancestors
        roots = (
            {self.root, self.paths.data}
            if self.workspace
            else {self.root, self.paths.config, self.paths.state}
        )
        directories = set(roots) | {self.control_root, self.package}
        for destination in (*self.destinations().values(), self.pointer):
            for parent in destination.parents:
                if any(parent.is_relative_to(root) for root in roots):
                    directories.add(parent)
        self._ancestors = directories
        return directories

    @staticmethod
    def directory_identity(path: Path) -> tuple[int, int]:
        """Capture native directory ownership without accepting links or reparse points."""
        safe_path(path)
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise StudioStateError("A Studio directory was replaced by another entry")
        return metadata.st_dev, metadata.st_ino

    def check_directories(self, manifest: BackupManifest) -> None:
        """Stop if a registered directory was replaced, even with a regular directory."""
        for location, identity in manifest.directories.items():
            if self.directory_identity(Path(location)) != identity:
                raise StudioStateError(
                    "Studio directory changed independently; recovery will not overwrite it"
                )

    def check_conflicts(self, manifest: BackupManifest) -> None:
        """Refuse independent edits rather than overwrite an unrelated state image."""
        self.check_directories(manifest)
        for entry in manifest.files:
            observed = self.snapshot_digest(entry.key, self.destinations()[entry.key])
            absent_database = (
                entry.key == "database" and entry.before is None and observed == sha(b"0")
            )
            if observed not in (entry.before, entry.after) and not absent_database:
                raise StudioStateError(
                    f"{entry.key} changed independently; recovery will not overwrite it"
                )

    def apply(self, operation_id: str, restore: bool = False) -> UpgradeStatus:
        """Upgrade or restore the bound operation; duplicate callers observe its result."""
        with self.mutex:
            if operation_id != self.status.operation_id:
                raise StudioStateError(
                    "The prepared operation is obsolete; refresh maintenance status"
                )
            if self.status.state in {"ready", "running"}:
                if restore:
                    raise StudioStateError("Restore is unavailable after successful preparation")
                return self.status
            if self.status.state == "blocked":
                raise StudioStateError(self.status.error or "State is unsupported")
            try:
                self.owner.acquire()
                check_workers(self.paths.database_file)
                if self.workspace and not self.root.is_dir():
                    raise StudioStateError("Workspace disappeared; restore will not recreate it")
                if self.journal.initial_layout is not None and not self.journal.manifest_sha256:
                    if restore:
                        raise StudioStateError(
                            "Fresh initialization has no previous state to restore"
                        )
                    self._fresh()
                    return self.status
                if not self.journal.manifest_sha256:
                    # Reinspect legacy inputs under ownership before staging images.
                    self.recheck_prepared_inputs()
                    if not self.workspace:
                        inspect_database(self.paths.database_file)
                        settings_document(self.paths.settings_file)
                    self.status.phase = "Creating and verifying recovery backup"
                    self.create_backup()
                manifest = self.verify_backup()
                self.check_conflicts(manifest)
                if self.status.state == "restored":
                    self.journal.restoring = False
                self.journal.restoring = restore or self.journal.restoring
                self.status.state = "running"
                self.status.error = None
                self.status.completed_steps = 0
                self.status.phase = (
                    "Restoring UI state" if self.journal.restoring else "Upgrading UI state"
                )
                self.persist()
                for index, entry in enumerate(manifest.files):
                    self.status.phase = (
                        f"{'Restoring' if self.journal.restoring else 'Upgrading'} {entry.key}"
                    )
                    destination = self.destinations()[entry.key]
                    current = self.snapshot_digest(entry.key, destination)
                    expected = entry.before if self.journal.restoring else entry.after
                    if current != expected:
                        self.boundary(f"{entry.key}.before_replace")
                        self.check_directories(manifest)
                        if self.snapshot_digest(entry.key, destination) != current:
                            raise StudioStateError(
                                "State changed independently immediately before publication"
                            )

                        def publication_guard(
                            key: str = entry.key,
                            target: Path = destination,
                            digest: str | None = current,
                        ) -> None:
                            self.check_directories(manifest)
                            if self.snapshot_digest(key, target) != digest:
                                raise StudioStateError(
                                    "State changed independently during publication"
                                )

                        image = (
                            self.package
                            / f"{entry.key}.{'before' if self.journal.restoring else 'after'}"
                        )
                        if entry.key == "database" and destination.exists():
                            # Materialize committed WAL pages before removing sidecars. A failed
                            # replacement must leave the original logical state retryable.
                            publication_guard()
                            self.boundary("database.before_checkpoint")
                            with closing(sqlite3.connect(destination, timeout=0)) as connection:
                                busy, _, _ = connection.execute(
                                    "PRAGMA wal_checkpoint(TRUNCATE)"
                                ).fetchone()
                                if busy:
                                    raise StudioStateError(
                                        "Database is in use; close the independent reader or writer "
                                        "before retrying the upgrade"
                                    )
                            self.io.flush(destination)
                            publication_guard()
                            self.boundary("database.after_checkpoint")
                            for suffix in ("-wal", "-shm"):
                                self.io.remove(destination.with_name(destination.name + suffix))
                        if expected is None:
                            self.io.remove(destination, precondition=publication_guard)
                        elif entry.key == "database" and not self.journal.restoring:
                            # Execute in a private image, then publish through pinned filesystem
                            # handles. SQLite's path-based VFS must not follow a swapped workspace
                            # or settings ancestor into an unrelated destination.
                            working = self.package / "database.working"
                            if entry.before is None:
                                self.io.write(working, b"")
                            else:
                                self.io.copy(working, self.package / "database.before")
                            migrate_database(
                                working,
                                manifest.runtime_id,
                                self.observer,
                                app_version=manifest.app_version,
                                receipts=self.database_receipts,
                                applied_at=manifest.created_at,
                            )
                            self.io.flush(working)
                            if database_digest(working) != entry.after:
                                raise StudioStateError("Database transformation failed validation")
                            publication_guard()
                            for suffix in ("-wal", "-shm"):
                                self.io.remove(destination.with_name(destination.name + suffix))
                            self.io.copy(
                                destination, working, entry.mode, precondition=publication_guard
                            )
                        else:
                            if entry.key == "database":
                                for suffix in ("-wal", "-shm"):
                                    self.io.remove(destination.with_name(destination.name + suffix))
                            self.io.copy(
                                destination, image, entry.mode, precondition=publication_guard
                            )
                        self.boundary(f"{entry.key}.after_replace")
                    if self.snapshot_digest(entry.key, destination) != expected:
                        raise StudioStateError("State publication did not match its verified image")
                    self.check_directories(manifest)
                    self.status.completed_steps = index + 1
                    self.persist()
                self.boundary("validation.before")
                if not self.journal.restoring and not self.workspace:
                    inspect_database(self.paths.database_file)
                    settings_document(self.paths.settings_file)
                    self.verify_private_receipts()
                if not self.journal.restoring:
                    if self.read_layout().layout_version != self.layout_target:
                        raise StudioStateError(
                            "Layout version was not advanced after its operations"
                        )
                self.boundary("validation.after")
                terminal = self.status.model_copy(
                    update={
                        "phase": "Previous UI state restored"
                        if self.journal.restoring
                        else "Studio is ready",
                        "state": "restored" if self.journal.restoring else "ready",
                        "can_restore": False,
                        "can_retry": self.journal.restoring,
                        "completed_steps": self.status.total_steps,
                    }
                )
                self.boundary("completion.before")
                self.journal.status = terminal
                self.persist()
                self.boundary("completion.after")
                self.status = terminal
                if self.status.state == "ready":
                    try:
                        self.prune()
                    except (OSError, ValueError, StudioStateError):
                        logger.warning(
                            "Backup retention could not finish; all recovery packages retained"
                        )
                return self.status
            except (OSError, ValueError, sqlite3.Error, StudioStateError) as error:
                self.journal.status = self.status
                self.status.state = "failed"
                self.status.error = state_error(error)
                self.status.can_retry = True
                self.status.can_restore = False
                if self.journal.manifest_sha256:
                    try:
                        self.verify_backup()
                        self.status.can_restore = True
                    except (OSError, ValueError, sqlite3.Error, StudioStateError):
                        pass  # Keep the original failure; a damaged seal cannot offer restoration.
                # A launch that lost ownership must not change the owner's active journal.
                if self.owner.descriptor is not None:
                    try:
                        self.persist()
                    except (OSError, StudioStateError):
                        logger.error(
                            "Could not persist Studio recovery error; original package retained"
                        )
                return self.status

    def prune(self) -> None:
        """Retain unresolved packages and the newest three completed backups."""
        self.io.write(self.package / "completed.json", json_bytes(self.status))
        completed: list[Path] = []
        for candidate in self.control_root.iterdir():
            if (
                len(candidate.name) == 32
                and all(character in "0123456789abcdef" for character in candidate.name)
                and candidate.is_dir()
                and (candidate / "completed.json").is_file()
            ):
                safe_path(candidate)
                terminal = UpgradeStatus.model_validate(read_json(candidate / "completed.json"))
                if terminal.state == "ready" and terminal.operation_id == candidate.name:
                    completed.append(candidate)
        completed.sort(key=lambda path: (path / "completed.json").stat().st_mtime_ns, reverse=True)
        for candidate in completed[3:]:
            try:
                shutil.rmtree(candidate)
            except OSError:
                logger.warning("Could not prune an old Studio backup; recovery remains available")
