"""Root review and one-pass removal for the original-account NSIS cleanup worker.

Approval covers the current contents of selected directories, not an enumerated
snapshot. Shared locations still select individual known files. Descendant ACLs
are enforced by Windows using the original account; cleanup never grants access.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from evidenceforge._windows_paths import filesystem_path
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StateLock, StudioStateError, safe_path
from evidenceforge.studio.windows_uninstall import (
    Category,
    CleanupPlan,
    CleanupProgress,
    CleanupTarget,
    FileIdentity,
    _check_workers_snapshot,
    _CleanupReporter,
    _ownership_lock,
    _run_roots,
)


def review_root(path: Path) -> tuple[FileIdentity, ...]:
    """Validate only the selected object; never list a directory's descendants."""
    safe_path(filesystem_path(path))
    try:
        metadata = filesystem_path(path).lstat()
    except FileNotFoundError:
        return ()
    directory = stat.S_ISDIR(metadata.st_mode)
    if not directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
        raise StudioStateError(f"Cleanup requires an ordinary file or directory: {path}")
    if os.name == "nt":
        from evidenceforge.utils import windows_filesystem as fs

        descriptor = fs.open_directory(path) if directory else fs.open_file(path, os.O_RDONLY)
        try:
            fs.require_private(descriptor, allow_read_access=True)
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    return (
        FileIdentity(
            relative=".",
            device=metadata.st_dev,
            inode=metadata.st_ino,
            directory=directory,
            size=0 if directory else metadata.st_size,
            modified_ns=0 if directory else metadata.st_mtime_ns,
        ),
    )


@dataclass
class _Frame:
    path: Path
    descriptor: int
    names: Iterator[tuple[str, bool]]
    identity: tuple[int, int]
    retained: bool = False


def _open(parent: int, name: str, *, directory: bool) -> int:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import open_cleanup_child

        return open_cleanup_child(parent, name, directory=directory)
    return os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)


def _names(descriptor: int) -> list[tuple[str, bool]]:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import list_directory_types

        return list_directory_types(descriptor)
    return [
        (name, stat.S_ISDIR(os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode))
        for name in os.listdir(descriptor)
    ]


def _parent(path: Path) -> int:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import open_directory

        return open_directory(path)
    safe_path(path)
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _delete_file(descriptor: int, parent: int, name: str) -> None:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import remove_open_cleanup_entry

        remove_open_cleanup_entry(descriptor)
    else:
        os.unlink(name, dir_fd=parent)


def _delete_directory(parent: int, name: str, identity: tuple[int, int]) -> None:
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import remove_child

        remove_child(parent, name, directory=True, expected_identity=identity, clear_readonly=True)
    else:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != identity:
            raise StudioStateError(f"Cleanup folder changed: {name}")
        os.rmdir(name, dir_fd=parent)


def _remove_target(
    target: CleanupTarget,
    fence: Callable[[Path, bool, int], bool],
    removed: Callable[[], None],
) -> list[tuple[Path, tuple[int, int]]]:
    """Visit each descendant once and defer only ancestors of owned lock files."""
    deferred: list[tuple[Path, tuple[int, int]]] = []
    frames: list[_Frame] = []
    parent = _parent(target.path.parent)
    child: int | None = None

    def enter(path: Path, descriptor: int) -> bool:
        metadata = os.fstat(descriptor)
        directory = stat.S_ISDIR(metadata.st_mode)
        if not directory and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
            raise StudioStateError(f"Cleanup refuses a link or special file: {path}")
        if path == target.path:
            original = target.entries[0]
            if (metadata.st_dev, metadata.st_ino, directory) != (
                original.device,
                original.inode,
                original.directory,
            ):
                raise StudioStateError(f"Selected cleanup root changed: {path}")
        if fence(path, directory, descriptor):
            if frames:
                frames[-1].retained = True
            return False
        if directory:
            frames.append(
                _Frame(
                    path, descriptor, iter(_names(descriptor)), (metadata.st_dev, metadata.st_ino)
                )
            )
            return True
        _delete_file(descriptor, frames[-1].descriptor if frames else parent, path.name)
        removed()
        return False

    try:
        try:
            child = _open(parent, target.path.name, directory=target.directory)
        except FileNotFoundError:
            return []
        if enter(target.path, child):
            child = None
        else:
            os.close(child)
            child = None
        while frames:
            frame = frames[-1]
            entry = next(frame.names, None)
            if entry is not None:
                name, directory = entry
                child = _open(frame.descriptor, name, directory=directory)
                if enter(frame.path / name, child):
                    child = None
                else:
                    os.close(child)
                    child = None
                continue
            if frame.retained:
                deferred.append((frame.path, frame.identity))
                if len(frames) > 1:
                    frames[-2].retained = True
            else:
                os.close(frame.descriptor)
                frame.descriptor = -1
                _delete_directory(
                    frames[-2].descriptor if len(frames) > 1 else parent,
                    frame.path.name,
                    frame.identity,
                )
                removed()
            frames.pop()
            if frame.descriptor != -1:
                os.close(frame.descriptor)
    finally:
        if child is not None:
            os.close(child)
        for frame in reversed(frames):
            if frame.descriptor != -1:
                os.close(frame.descriptor)
        os.close(parent)
    return deferred


def remove_selected(
    plan: CleanupPlan,
    selected: set[Category],
    *,
    report_progress: Callable[[CleanupProgress], None] | None = None,
) -> None:
    """Fence writers, recheck roots, and remove approved content without staging."""
    from evidenceforge.generation.checkpoints.store import RunLock

    targets = [target for target in plan.targets if target.category in selected]
    reporter = _CleanupReporter(report_progress)
    count = 0
    reporter.update("removing", force=True)

    def removed() -> None:
        nonlocal count
        count += 1
        reporter.update("removing", count)

    held: dict[Path, StateLock] = {}
    runs: set[Path] = set()
    deferred: list[tuple[Path, tuple[int, int]]] = []
    private = plan.locations.private

    def selected_path(path: Path) -> bool:
        return any(
            path == target.path or (target.directory and path.is_relative_to(target.path))
            for target in targets
        )

    try:
        with ExitStack() as stack:

            def state_lock(path: Path) -> None:
                if path not in held and filesystem_path(path.parent).is_dir():
                    held[path] = stack.enter_context(StateLock(path))

            def run_lock(path: Path) -> None:
                if path not in runs:
                    lock = RunLock(path)
                    lock.acquire()
                    stack.callback(lock.release)
                    runs.add(path)

            for name in (
                "service-start.lock",
                "service-instance.lock",
                "studio-data.lock",
                "runtimes/install.lock",
            ):
                state_lock(private / name)
            leases = private / "runtimes/leases"
            safe_path(filesystem_path(leases))
            if filesystem_path(leases).is_dir():
                for physical in filesystem_path(leases).glob("*.lock"):
                    state_lock(leases / physical.name)
            for workspace in plan.workspaces:
                state_lock(workspace / ".eforge/studio/owner.lock")
                state_lock(workspace / ".eforge/artifacts/publication.lock")
                parent = workspace / "runs"
                if filesystem_path(parent).is_dir() and any(
                    target.category == "work"
                    and (target.path.is_relative_to(parent) or parent.is_relative_to(target.path))
                    for target in targets
                ):
                    # Discover run boundaries, not files inside checkpoint/data trees.
                    for root in _run_roots(parent)[0]:
                        checkpoint = root / ".eforge-generation"
                        if filesystem_path(checkpoint).is_dir():
                            run_lock(checkpoint)
            _check_workers_snapshot(private / "studio.sqlite")
            for target in targets:
                current = review_root(target.path)
                if current and (current[0].device, current[0].inode, current[0].directory) != (
                    target.entries[0].device,
                    target.entries[0].inode,
                    target.directory,
                ):
                    raise StudioStateError(f"Selected cleanup root changed: {target.path}")

            def fence(path: Path, directory: bool, descriptor: int) -> bool:
                if directory and path.name == ".eforge-generation":
                    run_lock(path)
                if not directory and _ownership_lock(path, private):
                    if path.parent in runs and path.name == "run.lock":
                        return True
                    state_lock(path)
                    if os.name == "nt":
                        from evidenceforge.utils import windows_filesystem as fs

                        fs.remove_open_cleanup_entry(descriptor)
                    return True
                return False

            for target in targets:
                deferred.extend(_remove_target(target, fence, removed))
        # Only small lock-bearing skeletons remain. Do not traverse again or
        # remove content created after the writer fences were released.
        if os.name != "nt":
            for path in held:
                if selected_path(path):
                    path.unlink(missing_ok=True)
        for path, identity in deferred:
            parent = _parent(path.parent)
            try:
                _delete_directory(parent, path.name, identity)
                removed()
            finally:
                os.close(parent)
    except (OSError, EvidenceForgeError) as error:
        raise StudioStateError(
            f"Cleanup stopped after removing {count:,} entries: {error}. "
            "Some selected content may already be gone. Close applications using these "
            "folders and review cleanup again; the application has not been uninstalled."
        ) from error
    reporter.update("complete", 1, 1, force=True)
