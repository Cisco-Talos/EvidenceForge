"""Explicit, inventoried cleanup of one unelevated Windows account during uninstall."""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from evidenceforge._windows_paths import filesystem_path
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StateLock, StudioStateError, safe_path

Category = Literal["private", "skills", "work"]
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


def _ownership_lock(path: Path) -> bool:
    """Recognize reserved protocol files, not arbitrary authored .lock files."""
    return (
        (
            path.parent.name == "EvidenceForge"
            and path.name in {"service-start.lock", "service-instance.lock", "studio-data.lock"}
        )
        or (path.parent.name == "runtimes" and path.name == "install.lock")
        or (
            path.parent.name == "leases"
            and path.parent.parent.name == "runtimes"
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


def _inventory(path: Path) -> tuple[FileIdentity, ...]:
    """Reject links, hard links, foreign/writable objects and unsupported filesystems."""
    safe_path(filesystem_path(path))
    if not filesystem_path(path).exists():
        return ()
    entries: list[FileIdentity] = []
    pending = [path]
    while pending:
        current = pending.pop()
        safe_path(filesystem_path(current))
        metadata = filesystem_path(current).lstat()
        directory = stat.S_ISDIR(metadata.st_mode)
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise StudioStateError(f"Cleanup refuses a non-file entry: {current}")
        if os.name == "nt":
            from evidenceforge.utils import windows_filesystem as fs

            descriptor = (
                fs.open_directory(current) if directory else fs.open_file(current, os.O_RDONLY)
            )
            try:
                fs.require_private(descriptor, allow_read_access=True)
            finally:
                os.close(descriptor)
        # Ownership locks may be acquired after review. They contain no user data;
        # inspect their safety but exclude volatile contents from the snapshot.
        if directory or not _ownership_lock(current):
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


def _skill_files(profile: Path) -> list[Path]:
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


def _run_roots(parent: Path) -> tuple[list[Path], list[str]]:
    """Find registered bundles under Studio's nested runs layout, without following links."""
    runs: list[Path] = []
    preserved: list[str] = []
    pending = [parent]
    while pending:
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


def build_plan(locations: UserLocations) -> CleanupPlan:
    """Inventory independently selectable categories without creating or changing data."""
    import yaml

    from evidenceforge.composition.publisher import PublisherIdentity
    from evidenceforge.studio.state_upgrade import settings_document

    candidates: list[tuple[Category, Path]] = [
        ("private", locations.private),
        ("private", locations.local / "org.evidenceforge.studio"),
        ("work", locations.profile / ".eforge/releases"),
    ]
    candidates.extend(("skills", path) for path in _skill_files(locations.profile))
    publisher = locations.profile / ".eforge/publisher.yaml"
    safe_path(filesystem_path(publisher))
    if filesystem_path(publisher).is_file():
        PublisherIdentity.model_validate(
            yaml.safe_load(filesystem_path(publisher).read_text(encoding="utf-8"))
        )
        candidates.append(("skills", publisher))
    workspaces: set[Path] = {locations.documents / "EvidenceForge"}
    settings = locations.private / "settings.json"
    safe_path(filesystem_path(settings))
    if filesystem_path(settings).is_file():
        _version, values = settings_document(filesystem_path(settings))
        workspaces.add(Path(str(values["workspace"])))
        workspaces.update(Path(str(value)) for value in values.get("recent_workspaces", []))
    preserved: list[str] = []
    if filesystem_path(settings).is_file():
        for output in values.get("output_parents", {}).values():
            preserved.append(f"Custom output parent is preserved: {output}")
    admitted_workspaces: list[Path] = []
    for workspace in sorted(workspaces):
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
        # Only app-managed namespaces; never recursively delete the workspace itself.
        candidates.extend(("skills", path) for path in _skill_files(workspace))
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
                roots, kept = _run_roots(parent)
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
    for category, path in sorted(set(candidates), key=lambda item: (item[0], str(item[1]))):
        entries = _inventory(path)
        if entries:
            targets.append(CleanupTarget(category=category, path=path, entries=entries))
    return CleanupPlan(
        locations=locations,
        targets=tuple(targets),
        preserved=tuple(preserved),
        workspaces=tuple(admitted_workspaces),
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
    for category, label in LABELS.items():
        if category not in selected:
            continue
        lines.extend(("", f"DELETE: {label}"))
        paths = [str(target.path) for target in plan.targets if target.category == category]
        lines.extend(paths or ["No matching data was found."])
        if category == "skills":
            lines.append(
                "Known EvidenceForge skill files include any local edits. Other files stay."
            )
    if plan.preserved:
        lines.extend(("", "PRESERVE / not included:", *plan.preserved))
    lines.extend(("", "Other accounts, Codex/sign-in, unrelated skills and external exports stay."))
    return "\r\n".join(lines)


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


def execute(plan: CleanupPlan, selected: set[Category]) -> None:
    """Lock/recheck, stage exact selected entries, then remove only that staged inventory."""
    if not selected:
        return
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import current_user_sid

        if current_user_sid() != plan.locations.account:
            raise StudioStateError("Uninstall account changed after review; cleanup refused")
    from evidenceforge.generation.checkpoints.store import RunLock

    targets = [target for target in plan.targets if target.category in selected]
    staged: list[tuple[Path, Path]] = []
    containers: list[Path] = []
    original_directories: list[Path] = []
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
        for path in sorted(set(locks)):
            if filesystem_path(path.parent).is_dir():
                held.append(stack.enter_context(StateLock(path)))
        _check_workers_snapshot(private / "studio.sqlite")
        for target in targets:
            if _inventory(target.path) != target.entries:
                raise StudioStateError(
                    f"Files changed after review; reopen uninstall: {target.path}"
                )
            for entry in target.entries:
                if entry.directory and Path(entry.relative).name == ".eforge-generation":
                    lock = RunLock(target.path / entry.relative)
                    lock.acquire()  # Refuses active/remote/uncertain external CLI ownership.
                    stack.callback(lock.release)
        try:
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
                        else:
                            _move(source, stage, directory=False)
                            staged.append((source, stage))
                else:
                    _move(target.path, destination, directory=False)
                    staged.append((target.path, destination))
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
            for source, destination in reversed(staged):
                _move(destination, source, directory=False)
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
    for _source, destination in staged:
        try:
            filesystem_path(destination).unlink()
        except OSError as error:
            raise StudioStateError(
                f"Selected data remains staged at {destination}; close file users and retry: {error}"
            ) from error
    for directory in containers:
        if os.name == "nt":
            from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

            WindowsCheckpointIO().remove_tree(directory)
        else:
            shutil.rmtree(directory)
    for directory in sorted(
        set(original_directories), key=lambda item: len(item.parts), reverse=True
    ):
        try:
            filesystem_path(directory).rmdir()  # Never recursively remove fresh/unlisted entries.
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


def main() -> None:
    """Provide no silent destructive command; deletion always requires the native review."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--expected-account")
    arguments = parser.parse_args()
    if sys.platform != "win32" or arguments.broker == arguments.interactive:
        parser.error("Use this module only from the native Windows uninstaller")
    from evidenceforge.studio.windows_uninstall_native import broker, interactive

    raise SystemExit(broker() if arguments.broker else interactive(arguments.expected_account))


if __name__ == "__main__":
    main()
