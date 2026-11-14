"""Explicit, inventoried cleanup of one unelevated Windows account during uninstall."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge._windows_paths import filesystem_path
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StateLock, StudioStateError, open_regular, safe_path

Category = Literal["private", "skills", "work"]
logger = logging.getLogger(__name__)
LABELS: dict[Category, str] = {
    "private": "Studio settings, credentials, caches and retained runtimes",
    "skills": "EvidenceForge skills and global publisher identity (also used by the CLI)",
    "work": "Authored scenarios/packs and generated output in known workspaces",
}


class UserLocations(BaseModel):
    """Known folders resolved for the actual process token, never inherited overrides."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: Path
    local: Path
    documents: Path
    account: str

    @property
    def private(self) -> Path:
        """Return this account's default private Studio root."""
        return self.local / "EvidenceForge"


class FileIdentity(BaseModel):
    """One no-follow inventory entry; directory timestamps are deliberately volatile."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    relative: str
    device: int
    inode: int
    directory: bool
    size: int = 0
    modified_ns: int = 0


class CleanupTarget(BaseModel):
    """An exact owned namespace entry approved for removal, never a workspace root."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    category: Category
    path: Path
    entries: tuple[FileIdentity, ...]

    @property
    def directory(self) -> bool:
        """Read the root entry independently of child filename ordering."""
        return next(entry.directory for entry in self.entries if entry.relative == ".")


class CleanupPlan(BaseModel):
    """The complete account-specific review shown before any destructive action."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    locations: UserLocations
    targets: tuple[CleanupTarget, ...] = ()
    preserved: tuple[str, ...] = ()
    workspaces: tuple[Path, ...] = ()
    full_cleanup: bool = False
    control_locks: tuple[Path, ...] = ()


class CleanupProgress(BaseModel):
    """Phase-local work counts; an unknown total is explicitly indeterminate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Literal["checking", "preparing", "removing", "finishing", "restoring", "complete"]
    completed: int = Field(default=0, ge=0)
    total: int | None = Field(default=None, ge=1)
    path: Path | None = None

    @property
    def message(self) -> str:
        """Describe real work without claiming the whole uninstall has finished."""
        title = {
            "checking": "Step 1 of 4: Checking the reviewed files",
            "preparing": "Step 2 of 4: Preparing selected data for removal",
            "removing": "Step 3 of 4: Removing selected files",
            "finishing": "Step 4 of 4: Finishing folder cleanup",
            "restoring": "Restoring files after a cleanup error",
            "complete": "Selected data cleanup finished",
        }[self.phase]
        detail = (
            f"\n{self.completed:,} of {self.total:,} entries" if self.total else "\nPlease wait…"
        )
        return title + detail + (f"\nFolder: {self.path}" if self.path else "")


class _CleanupReporter:
    """Throttle display updates; a lost display must not interrupt approved cleanup."""

    def __init__(self, callback: Callable[[CleanupProgress], None] | None) -> None:
        self.callback = callback
        self.phase: str | None = None
        self.last_update = 0.0
        self.last_completed = 0

    def update(
        self,
        phase: str,
        completed: int = 0,
        total: int | None = None,
        path: Path | None = None,
        *,
        force: bool = False,
    ) -> None:
        if self.callback is None:
            return
        now = time.monotonic()
        if (
            not force
            and phase == self.phase
            and now - self.last_update < 0.25
            and not (completed > 0 and self.last_completed == 0)
            and not (total is not None and completed == total)
        ):
            return
        self.phase, self.last_update = phase, now
        self.last_completed = completed
        progress = CleanupProgress(phase=phase, completed=completed, total=total, path=path)
        try:
            self.callback(progress)
        except OSError:
            logger.debug("Uninstall progress display disconnected; completing approved cleanup")
            self.callback = None


def _ownership_lock(path: Path, private_root: Path | None = None) -> bool:
    """Recognize reserved protocol files, not arbitrary authored .lock files."""
    return (
        (
            (path.parent == private_root if private_root else path.parent.name == "EvidenceForge")
            and path.name in {"service-start.lock", "service-instance.lock", "studio-data.lock"}
        )
        or (
            (
                path.parent == private_root / "runtimes"
                if private_root
                else path.parent.name == "runtimes"
            )
            and path.name == "install.lock"
        )
        or (
            path.parent.name == "leases"
            and path.parent.parent.name == "runtimes"
            and (private_root is None or path.parent == private_root / "runtimes/leases")
            and path.suffix == ".lock"
        )
        or (
            path.parent.name == "artifacts"
            and path.parent.parent.name == ".eforge"
            and path.name == "publication.lock"
        )
        or (
            path.parent.name == "studio"
            and path.parent.parent.name == ".eforge"
            and path.name == "owner.lock"
        )
        or (path.parent.name == ".eforge-generation" and path.name == "run.lock")
    )


def _windows_inventory(
    path: Path,
    check_cancelled: Callable[[], None],
    webview_root: Path | None,
    record_lock: Callable[[Path], None],
    private_root: Path | None,
) -> tuple[FileIdentity, ...]:
    """Pin ancestry once, then inspect each child through its opened parent."""
    from evidenceforge.utils import windows_filesystem as fs

    entries: list[FileIdentity] = []
    frames: list[tuple[Path, int, Iterator[str]]] = []
    webview_capabilities: frozenset[str] | None = None

    def inspect(relative: Path, descriptor: int) -> bool:
        nonlocal webview_capabilities
        check_cancelled()
        current = path / relative
        metadata = os.fstat(descriptor)
        directory = stat.S_ISDIR(metadata.st_mode)
        if not directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
            raise StudioStateError(
                f"Cleanup refuses a non-file or multiply linked entry: {current}"
            )
        capabilities: frozenset[str] = frozenset()
        if webview_root is not None and current.is_relative_to(webview_root):
            # This OS identity is independent of scenario configuration. Keep it
            # within this scan, outside the provider's derived-config cache graph.
            if webview_capabilities is None:
                webview_capabilities = fs.capability_sids("lpacEdgeStableNetworkSandbox")
            capabilities = webview_capabilities
        try:
            fs.require_private(
                descriptor, allow_read_access=True, cleanup_capabilities=capabilities
            )
        except OSError as error:
            raise StudioStateError(
                f"Cannot safely inspect cleanup path {current}: {error}"
            ) from error
        if not directory and _ownership_lock(current, private_root):
            record_lock(current)
        else:
            entries.append(
                FileIdentity(
                    relative=relative.as_posix(),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    directory=directory,
                    size=0 if directory else metadata.st_size,
                    modified_ns=0 if directory else metadata.st_mtime_ns,
                )
            )
        return directory

    metadata = filesystem_path(path).lstat()
    descriptor: int | None = (
        fs.open_directory(path)
        if stat.S_ISDIR(metadata.st_mode)
        else fs.open_file(path, os.O_RDONLY)
    )
    try:
        if inspect(Path("."), descriptor):
            frames.append((Path("."), descriptor, iter(fs.list_directory(descriptor))))
            descriptor = None
        while frames:
            relative, parent, names = frames[-1]
            name = next(names, None)
            if name is None:
                frames.pop()
                os.close(parent)
                continue
            child: int | None = fs.open_child(parent, name, os.O_RDONLY, directory=None)
            try:
                child_relative = relative / name
                if inspect(child_relative, child):
                    frames.append((child_relative, child, iter(fs.list_directory(child))))
                    child = None
            finally:
                if child is not None:
                    os.close(child)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for _relative, parent, _names in reversed(frames):
            os.close(parent)
    return tuple(sorted(entries, key=lambda item: item.relative))


def _inventory(
    path: Path,
    check_cancelled: Callable[[], None] = lambda: None,
    *,
    webview_root: Path | None = None,
    record_lock: Callable[[Path], None] = lambda path: None,
    private_root: Path | None = None,
) -> tuple[FileIdentity, ...]:
    """Reject links, hard links, foreign/writable objects and unsupported filesystems."""
    safe_path(filesystem_path(path))
    if not filesystem_path(path).exists():
        return ()
    if os.name == "nt":
        return _windows_inventory(path, check_cancelled, webview_root, record_lock, private_root)
    entries: list[FileIdentity] = []
    pending = [path]
    while pending:
        check_cancelled()
        current = pending.pop()
        safe_path(filesystem_path(current))
        metadata = filesystem_path(current).lstat()
        directory = stat.S_ISDIR(metadata.st_mode)
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise StudioStateError(f"Cleanup refuses a non-file entry: {current}")
        # Ownership locks may be acquired after review. They contain no user data;
        # inspect their safety but exclude volatile contents from the snapshot.
        if not directory and _ownership_lock(current, private_root):
            record_lock(current)
        else:
            entries.append(
                FileIdentity(
                    relative=current.relative_to(path).as_posix(),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    directory=directory,
                    size=0 if directory else metadata.st_size,
                    modified_ns=0 if directory else metadata.st_mtime_ns,
                )
            )
        if directory:
            pending.extend(
                current / child.name
                for child in sorted(filesystem_path(current).iterdir(), reverse=True)
            )
    return tuple(sorted(entries, key=lambda item: item.relative))


def _skill_files(profile: Path, *, complete_roots: bool = False) -> list[Path]:
    """Identify only EvidenceForge's known files, preserving other skills and additions."""
    from evidenceforge.cli.install_skills import (
        _collect_command_files,
        _collect_reference_files,
        _collect_source_files,
        _get_data_root,
        _references_for_chatgpt_skill,
    )

    manifest = _collect_source_files(_get_data_root())
    commands = _collect_command_files(manifest)
    references = _collect_reference_files(manifest)
    if complete_roots:
        return [profile / ".claude/commands/eforge"] + [
            profile / agent / "skills" / f"eforge-{name}"
            for agent in (".agents", ".codex")
            for name in commands
        ]
    paths = [profile / ".claude/commands/eforge" / relative for relative in manifest]
    for parent in (profile / ".agents/skills", profile / ".codex/skills"):
        for name in commands:
            root = parent / f"eforge-{name}"
            # A copied/custom unrelated directory with this name is not sufficient.
            marker = root / "SKILL.md"
            safe_path(filesystem_path(marker))
            if not filesystem_path(marker).is_file():
                continue
            text = filesystem_path(marker).read_text(encoding="utf-8")
            if "EvidenceForge" not in text or f"name: eforge-{name}\n" not in text:
                continue
            paths.append(marker)
            paths.extend(
                root / relative for relative in _references_for_chatgpt_skill(name, references)
            )
    return paths


def _run_roots(
    parent: Path, check_cancelled: Callable[[], None] = lambda: None
) -> tuple[list[Path], list[str]]:
    """Find registered bundles under Studio's nested runs layout, without following links."""
    runs: list[Path] = []
    preserved: list[str] = []
    pending = [parent]
    while pending:
        check_cancelled()
        current = pending.pop()
        safe_path(filesystem_path(current))
        if current != parent and (
            filesystem_path(current / "RESOLVED_SCENARIO.yaml").is_file()
            or filesystem_path(current / ".eforge-generation").is_dir()
        ):
            runs.append(current)
            continue
        for physical in filesystem_path(current).iterdir():
            child = current / physical.name
            safe_path(filesystem_path(child))
            if filesystem_path(child).is_dir():
                pending.append(child)
            else:
                preserved.append(f"Unregistered output content: {child}")
    return runs, preserved


def _read_cleanup_settings(path: Path) -> dict[str, object]:
    """Read owned settings for deletion review, allowing read-only grants, never writers.

    Cleanup does not reopen the running private service. This explicit owner/mutation
    policy matches the cleanup inventory without changing ordinary settings reads.
    """
    descriptor = open_regular(filesystem_path(path), os.O_RDONLY)
    try:
        if os.name == "nt":
            from evidenceforge.utils import windows_filesystem as fs

            fs.require_private(descriptor, allow_read_access=True)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(8 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(payload) > 8 * 1024 * 1024:
        raise StudioStateError(f"Cleanup settings exceed the inspection limit: {path}")
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise StudioStateError(f"Cleanup settings must contain an object: {path}")
    return raw


def build_plan(
    locations: UserLocations,
    categories: set[Category] | None = None,
    *,
    check_cancelled: Callable[[], None] = lambda: None,
    report_target: Callable[[Path], None] = lambda path: None,
    full_cleanup: bool = False,
) -> CleanupPlan:
    """Inventory independently selectable categories without creating or changing data."""
    import yaml

    from evidenceforge.composition.publisher import PublisherIdentity
    from evidenceforge.studio.state_upgrade import decode_settings_document

    selected = set(LABELS) if categories is None else categories
    if full_cleanup and selected != set(LABELS):
        raise StudioStateError("Full cleanup requires all three categories to be selected")
    if not selected:
        return CleanupPlan(locations=locations)

    candidates: list[tuple[Category, Path]] = [
        ("private", locations.private),
        ("private", locations.local / "org.evidenceforge.studio"),
    ]
    candidates.append(
        ("work", locations.profile / (".eforge" if full_cleanup else ".eforge/releases"))
    )
    if "skills" in selected:
        candidates.extend(
            ("skills", path)
            for path in _skill_files(locations.profile, complete_roots=full_cleanup)
        )
    publisher = locations.profile / ".eforge/publisher.yaml"
    if "skills" in selected:
        safe_path(filesystem_path(publisher))
    if "skills" in selected and not full_cleanup and filesystem_path(publisher).is_file():
        PublisherIdentity.model_validate(
            yaml.safe_load(filesystem_path(publisher).read_text(encoding="utf-8"))
        )
        candidates.append(("skills", publisher))
    workspaces: set[Path] = (
        {
            locations.profile / "EvidenceForge",
            locations.documents / "EvidenceForge",  # Previous preview default remains discoverable.
        }
        if selected & {"skills", "work"}
        else set()
    )
    settings = locations.private / "settings.json"
    if workspaces:
        safe_path(filesystem_path(settings))
    values: dict[str, object] = {}
    if workspaces and filesystem_path(settings).is_file():
        try:
            _version, values = decode_settings_document(_read_cleanup_settings(settings))
        except (OSError, ValueError, EvidenceForgeError) as error:
            raise StudioStateError(
                f"Cannot inspect workspace settings {settings}: {error}"
            ) from error
        workspaces.add(Path(str(values["workspace"])))
        workspaces.update(Path(str(value)) for value in values.get("recent_workspaces", []))
    preserved: list[str] = []
    if values:
        for output in values.get("output_parents", {}).values():
            preserved.append(f"Custom output parent is preserved: {output}")
    admitted_workspaces: list[Path] = []
    for workspace in sorted(workspaces):
        check_cancelled()
        # No arbitrary drive/profile/application roots, external exports or other profiles.
        if (
            not workspace.is_absolute()
            or ".." in workspace.parts
            or not workspace.is_relative_to(locations.profile)
            or workspace == locations.profile
            or workspace.is_relative_to(locations.local)
        ):
            preserved.append(f"Workspace outside the account's Documents/profile area: {workspace}")
            continue
        safe_path(filesystem_path(workspace))
        if not filesystem_path(workspace).is_dir():
            continue
        admitted_workspaces.append(workspace)
        if full_cleanup and workspace in {
            locations.profile / "EvidenceForge",
            locations.documents / "EvidenceForge",
        }:
            candidates.append(("work", workspace))
            continue
        if full_cleanup:
            preserved.append(
                f"Custom workspace keeps its container and unrecognized files: {workspace}"
            )
        # Only app-managed namespaces; never recursively delete the workspace itself.
        if "skills" in selected:
            candidates.extend(
                ("skills", path) for path in _skill_files(workspace, complete_roots=full_cleanup)
            )
        if "work" not in selected:
            continue
        for relative in (
            ".eforge/artifacts",
            ".eforge/studio",
            ".eforge/config",
            ".eforge/packs",
            ".eforge/releases",
            ".eforge/deletions",
        ):
            candidates.append(("work", workspace / relative))
        project_publisher = workspace / ".eforge/publisher.yaml"
        safe_path(filesystem_path(project_publisher))
        if filesystem_path(project_publisher).is_file():
            PublisherIdentity.model_validate(
                yaml.safe_load(filesystem_path(project_publisher).read_text(encoding="utf-8"))
            )
            candidates.append(("work", project_publisher))
        for name in ("scenarios", "runs"):
            parent = workspace / name
            safe_path(filesystem_path(parent))
            if not filesystem_path(parent).is_dir():
                continue
            if name == "runs":
                roots, kept = _run_roots(parent, check_cancelled)
                candidates.extend(("work", root) for root in roots)
                preserved.extend(kept)
                continue
            for physical in filesystem_path(parent).iterdir():
                child = parent / physical.name
                safe_path(filesystem_path(child))
                if filesystem_path(child).is_file() and child.suffix in {".yaml", ".yml"}:
                    try:
                        document = yaml.safe_load(
                            filesystem_path(child).read_text(encoding="utf-8")
                        )
                    except yaml.YAMLError:
                        document = None
                    if isinstance(document, dict) and {"name", "schema_version"} <= document.keys():
                        candidates.append(("work", child))
                        continue
                preserved.append(f"Unregistered workspace content: {child}")
    targets: list[CleanupTarget] = []
    control_locks: set[Path] = set()
    ordered_candidates = sorted(
        set(candidates), key=lambda item: (len(item[1].parts), str(item[1]))
    )
    for category, path in ordered_candidates:
        if category not in selected:
            continue
        if full_cleanup and any(
            path.is_relative_to(target.path) for target in targets if target.directory
        ):
            continue
        check_cancelled()
        report_target(path)
        entries = _inventory(
            path,
            check_cancelled,
            webview_root=locations.local / "org.evidenceforge.studio/EBWebView",
            record_lock=control_locks.add,
            private_root=locations.private,
        )
        if entries:
            targets.append(CleanupTarget(category=category, path=path, entries=entries))
    return CleanupPlan(
        locations=locations,
        targets=tuple(targets),
        preserved=tuple(preserved),
        workspaces=tuple(admitted_workspaces),
        full_cleanup=full_cleanup,
        control_locks=tuple(sorted(control_locks)),
    )


def describe(plan: CleanupPlan, selected: set[Category]) -> str:
    """Show exact deletion roots and the independent shared-CLI impact."""
    lines = [
        f"Account: {plan.locations.account}",
        f"Profile: {plan.locations.profile}",
        "",
        "The application will be uninstalled.",
    ]
    if not selected:
        lines.append("All user data and skills will be preserved (the default).")
    if plan.full_cleanup:
        lines.extend(
            (
                "",
                "FULL CLEAN: Entire listed EvidenceForge folders and all their contents will be removed, including manually added files.",
                "Shared application/agent parents and unrelated custom workspace content stay.",
            )
        )
    for category, label in LABELS.items():
        if category not in selected:
            continue
        lines.extend(("", f"DELETE: {label}"))
        paths = [str(target.path) for target in plan.targets if target.category == category]
        lines.extend(paths or ["No matching data was found."])
        if category == "skills":
            lines.append(
                "Entire listed EvidenceForge skill folders, including local additions, will be removed."
                if plan.full_cleanup
                else "Known EvidenceForge skill files include any local edits. Other files stay."
            )
    if plan.preserved:
        lines.extend(("", "PRESERVE / not included:", *plan.preserved))
    lines.extend(("", "Other accounts, Codex/sign-in, unrelated skills and external exports stay."))
    return "\r\n".join(lines)


def confirmation(plan: CleanupPlan, selected: set[Category]) -> str:
    """Summarize the exact reviewed choices before authorizing permanent deletion."""
    lines = [
        "Are you sure you want to uninstall Studio and permanently delete the selected content?",
        "",
        *(f"• {label}" for category, label in LABELS.items() if category in selected),
        "",
        f"User profile: {plan.locations.profile}",
    ]
    if "private" in selected:
        lines.extend(
            (
                f"Studio data: {plan.locations.private}",
                f"Browser data: {plan.locations.local / 'org.evidenceforge.studio'}",
            )
        )
    if "work" in selected:
        lines.extend(("Workspaces:", *(str(path) for path in plan.workspaces)))
    if plan.full_cleanup:
        lines.extend(
            (
                "",
                "All three choices are selected. Entire dedicated EvidenceForge folders and "
                "everything inside them, including manually added files, will be removed. "
                "Custom workspace containers retain unrelated content.",
            )
        )
    lines.extend(
        (
            "",
            "Other accounts, Codex/sign-in and unrelated skills will be preserved.",
            "This cannot be undone. Choose No to return without removing anything.",
        )
    )
    return "\n".join(lines)


def _move(source: Path, target: Path, *, directory: bool) -> None:
    if os.name == "nt":
        from evidenceforge.utils import windows_filesystem as fs

        source_parent = fs.open_directory(source.parent)
        try:
            target_parent = fs.open_directory(target.parent)
            try:
                fs.replace_child(
                    source_parent,
                    source.name,
                    target_parent,
                    target.name,
                    replace=False,
                    directory=directory,
                )
            finally:
                os.close(target_parent)
        finally:
            os.close(source_parent)
    else:
        source.rename(target)


def _check_workers_snapshot(database: Path) -> None:
    """Inspect retained jobs without SQLite creating journals in the reviewed tree."""
    from evidenceforge.studio.state_io import canonical_path, private_directory
    from evidenceforge.studio.state_upgrade import check_workers

    try:
        safe_path(filesystem_path(database))
        if not filesystem_path(database).exists():
            check_workers(database)
            return
        if not filesystem_path(database).is_file():
            raise StudioStateError("Studio's job database is not a regular file")
        # Read-only WAL connections can create -wal/-shm in the source directory.
        # Copy the main database and committed WAL under the already-held ownership
        # locks. SQLite rebuilds its disposable shared-memory index in this private
        # snapshot, preserving the original inventory and the full WAL-backed view.
        with tempfile.TemporaryDirectory(prefix="eforge-uninstall-probe-") as temporary:
            root = canonical_path(Path(temporary))
            private_directory(root)
            snapshot = root / database.name
            for suffix in ("", "-wal"):
                source = database.with_name(database.name + suffix)
                safe_path(filesystem_path(source))
                if filesystem_path(source).exists():
                    if not filesystem_path(source).is_file():
                        raise StudioStateError(
                            f"Studio database journal is not a regular file: {source}"
                        )
                    shutil.copyfile(
                        filesystem_path(source),
                        filesystem_path(snapshot.with_name(snapshot.name + suffix)),
                    )
            check_workers(snapshot)
    except (OSError, sqlite3.Error) as error:
        raise StudioStateError(
            f"Could not verify retained Studio work; no cleanup was started: {error}"
        ) from error


def execute(
    plan: CleanupPlan,
    selected: set[Category],
    *,
    report_progress: Callable[[CleanupProgress], None] | None = None,
) -> None:
    """Lock/recheck, stage exact selected entries, then remove only that staged inventory."""
    if not selected:
        return
    if plan.full_cleanup and selected != set(LABELS):
        raise StudioStateError("Full cleanup choices changed; review the folders again")
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import current_user_sid

        if current_user_sid() != plan.locations.account:
            raise StudioStateError("Uninstall account changed after review; cleanup refused")
    from evidenceforge.generation.checkpoints.store import RunLock

    targets = [target for target in plan.targets if target.category in selected]
    reporter = _CleanupReporter(report_progress)
    entry_count = sum(len(target.entries) for target in targets)
    reporter.update("checking")
    staged: list[tuple[Path, Path]] = []
    containers: list[Path] = []
    original_directories: list[Path] = []
    directory_identities: dict[Path, tuple[int, int]] = {}
    file_identities = {
        target.path / entry.relative: (entry.device, entry.inode)
        for target in targets
        for entry in target.entries
        if not entry.directory
    }
    held: list[StateLock] = []
    with ExitStack() as stack:
        private = plan.locations.private
        locks = [
            private / name
            for name in ("service-start.lock", "service-instance.lock", "studio-data.lock")
        ]
        locks.append(private / "runtimes/install.lock")
        leases = private / "runtimes/leases"
        if filesystem_path(leases).exists():
            locks.extend(leases / path.name for path in filesystem_path(leases).glob("*.lock"))
        for workspace in plan.workspaces:
            locks.extend(
                (
                    workspace / ".eforge/studio/owner.lock",
                    workspace / ".eforge/artifacts/publication.lock",
                )
            )
        locks.extend(
            path
            for path in plan.control_locks
            if path.parent.name != ".eforge-generation"
            and any(path.is_relative_to(target.path) for target in targets if target.directory)
        )
        for path in sorted(set(locks)):
            if filesystem_path(path.parent).is_dir():
                held.append(stack.enter_context(StateLock(path)))
        _check_workers_snapshot(private / "studio.sqlite")
        checked = 0
        for target in targets:
            target_checks = 0

            def checking(current: CleanupTarget = target, base: int = checked) -> None:
                nonlocal target_checks
                target_checks += 1
                # Volatile protocol locks are checked but excluded from the
                # reviewed entry list. Do not let them inflate the progress total.
                reporter.update(
                    "checking",
                    base + min(target_checks, len(current.entries)),
                    entry_count or 1,
                    current.path,
                )

            if (
                _inventory(
                    target.path,
                    checking,
                    webview_root=plan.locations.local / "org.evidenceforge.studio/EBWebView",
                    private_root=plan.locations.private,
                )
                != target.entries
            ):
                raise StudioStateError(
                    f"Files changed after review; reopen uninstall: {target.path}"
                )
            checked += len(target.entries)
            for entry in target.entries:
                if entry.directory and Path(entry.relative).name == ".eforge-generation":
                    lock = RunLock(target.path / entry.relative)
                    lock.acquire()  # Refuses active/remote/uncertain external CLI ownership.
                    stack.callback(lock.release)
        try:
            prepared = 0
            reporter.update("preparing", 0, entry_count or 1)
            for target in targets:
                destination = target.path.with_name(f".eforge-uninstall-{uuid4().hex}")
                if target.directory:
                    # Windows cannot rename a directory containing open ownership
                    # handles. Keep those handles/names alive and stage only its
                    # inventoried files. Original directories are reclaimed only
                    # when empty, so concurrent new startup data is never removed.
                    from evidenceforge.studio.state_io import private_directory

                    private_directory(filesystem_path(destination))
                    containers.append(destination)
                    for entry in sorted(
                        target.entries, key=lambda item: (not item.directory, item.relative)
                    ):
                        source = target.path / entry.relative
                        stage = destination / entry.relative
                        if entry.directory:
                            private_directory(filesystem_path(stage))
                            original_directories.append(source)
                            directory_identities[source] = (entry.device, entry.inode)
                        else:
                            _move(source, stage, directory=False)
                            staged.append((source, stage))
                        prepared += 1
                        reporter.update("preparing", prepared, entry_count or 1, target.path)
                else:
                    _move(target.path, destination, directory=False)
                    staged.append((target.path, destination))
                    prepared += 1
                    reporter.update("preparing", prepared, entry_count or 1, target.path)
            if os.name == "nt":
                from evidenceforge.utils import windows_filesystem as fs

                for lock in held:
                    if any(
                        lock.path.is_relative_to(target.path)
                        for target in targets
                        if target.directory
                    ):
                        # Mark only our own control handle's file delete-pending.
                        # New startup cannot reopen it until ownership is released.
                        parent = fs.open_directory(lock.path.parent)
                        try:
                            identity = os.fstat(lock.descriptor)
                            fs.remove_child(
                                parent,
                                lock.path.name,
                                expected_identity=(identity.st_dev, identity.st_ino),
                            )
                        finally:
                            os.close(parent)
        except (OSError, EvidenceForgeError):
            reporter.update("restoring", 0, len(staged) or 1)
            for index, (source, destination) in enumerate(reversed(staged), 1):
                _move(destination, source, directory=False)
                reporter.update("restoring", index, len(staged) or 1, source.parent)
            reporter.update("restoring", force=True)
            for directory in reversed(containers):
                if os.name == "nt":
                    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

                    WindowsCheckpointIO().remove_tree(directory)
                else:
                    shutil.rmtree(directory)
            raise
    # All ownership handles have closed before unlinking their original skeleton.
    # POSIX doesn't have delete-pending names, so remove only our own lock files.
    if os.name != "nt":
        for lock in held:
            if any(lock.path.is_relative_to(target.path) for target in targets if target.directory):
                lock.path.unlink(missing_ok=True)
    reporter.update("removing", 0, len(staged) or 1)
    for index, (_source, destination) in enumerate(staged, 1):
        try:
            if os.name == "nt":
                from evidenceforge.utils import windows_filesystem as fs

                parent = fs.open_directory(destination.parent)
                try:
                    fs.remove_child(
                        parent,
                        destination.name,
                        expected_identity=file_identities[_source],
                        clear_readonly=True,
                    )
                finally:
                    os.close(parent)
            else:
                filesystem_path(destination).unlink()
        except OSError as error:
            raise StudioStateError(
                f"Selected data remains staged at {destination}; close file users and retry: {error}"
            ) from error
        reporter.update("removing", index, len(staged) or 1, _source.parent)
    reporter.update("finishing")
    for directory in containers:
        reporter.update("finishing", path=directory, force=True)
        if os.name == "nt":
            from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

            WindowsCheckpointIO().remove_tree(directory)
        else:
            shutil.rmtree(directory)
    for directory in sorted(
        set(original_directories), key=lambda item: len(item.parts), reverse=True
    ):
        reporter.update("finishing", path=directory)
        try:
            if os.name == "nt":
                from evidenceforge.utils import windows_filesystem as fs

                parent = fs.open_directory(directory.parent)
                try:
                    fs.remove_child(
                        parent,
                        directory.name,
                        directory=True,
                        expected_identity=directory_identities[directory],
                        clear_readonly=True,
                    )
                finally:
                    os.close(parent)
            else:
                filesystem_path(directory).rmdir()  # Never remove fresh/unlisted contents.
        except OSError:
            pass
    # Remove empty owned containers only; never shared parents or unrelated files.
    for target in targets:
        if target.category != "skills":
            continue
        parent = target.path.parent
        while parent != plan.locations.profile and parent.name not in {
            "skills",
            "commands",
            ".eforge",
        }:
            try:
                filesystem_path(parent).rmdir()
            except OSError:
                break
            parent = parent.parent
    if plan.full_cleanup:
        remaining = [
            str(target.path) for target in targets if filesystem_path(target.path).exists()
        ]
        if remaining:
            raise StudioStateError(
                "Reviewed data was removed, but new or locked contents remain at: "
                + "; ".join(remaining)
                + ". These contents were preserved. Review cleanup again."
            )
    reporter.update("complete", 1, 1, force=True)


def main() -> None:
    """Provide no silent destructive command; deletion always requires the native review."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--expected-account")
    parser.add_argument("--worker-pipe")
    parser.add_argument("--server-pid", type=int)
    parser.add_argument("--wizard-window", type=int)
    parser.add_argument("--page-window", type=int)
    parser.add_argument("--wizard-pid", type=int)
    parser.add_argument("--controls", type=int, nargs=5)
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Use this module only from the native Windows uninstaller")
    from evidenceforge.studio.windows_uninstall_native import broker, interactive
    from evidenceforge.studio.windows_uninstall_wizard import WizardControls, run_wizard, worker

    if arguments.wizard_window:
        if arguments.broker or arguments.interactive or arguments.worker_pipe:
            parser.error("Conflicting uninstall modes")
        run_wizard(
            WizardControls(
                arguments.wizard_window,
                arguments.page_window,
                arguments.controls,
                arguments.wizard_pid,
            )
        )
        return
    if arguments.worker_pipe:
        if not arguments.server_pid or arguments.interactive:
            parser.error("Invalid uninstall worker mode")
        if arguments.broker:
            raise SystemExit(broker(arguments.worker_pipe, arguments.server_pid))
        if not arguments.expected_account:
            parser.error("Uninstall worker account is required")
        raise SystemExit(
            worker(arguments.worker_pipe, arguments.server_pid, arguments.expected_account)
        )
    if arguments.broker == arguments.interactive:
        parser.error("Select one uninstall mode")
    raise SystemExit(broker() if arguments.broker else interactive(arguments.expected_account))


if __name__ == "__main__":
    main()
