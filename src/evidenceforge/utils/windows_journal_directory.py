"""Windows-only directory lifecycle for Bash-history and Snort SQLite journals."""

from __future__ import annotations

import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from evidenceforge.generation.emitters.base import ExactPublicationError
from evidenceforge.utils import windows_filesystem as filesystem
from evidenceforge.utils.windows_journals import validate_ancestry

if TYPE_CHECKING:
    from evidenceforge.generation.emitters.bash_history import _PrivateJournalDirectory as BashOwner
    from evidenceforge.generation.emitters.snort import _PrivateJournalDirectory as SnortOwner

    DirectoryOwner = BashOwner | SnortOwner


def open_spool_root(base_dir: Path) -> tuple[Path, int]:
    """Validate a disjoint native spool root without resolving reparse points."""
    configured = os.environ.get("EFORGE_SPOOL_DIR")
    root = Path(
        os.path.abspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
    )
    output = Path(os.path.abspath(base_dir))
    if root == output or root.is_relative_to(output):
        raise ExactPublicationError("Windows private spool must be outside public output")
    ancestor = root
    while not ancestor.exists():
        ancestor = ancestor.parent
    validate_ancestry(ancestor)
    descriptor = filesystem.open_directory(root, create=configured is not None)
    try:
        validate_ancestry(root)
        return root, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def create(owner: DirectoryOwner, *, prefix: str) -> None:
    """Allocate a private leaf and retain retry ownership before initialization."""
    if owner._closed:
        raise ExactPublicationError("Windows private spool is already terminal")
    if owner.path is not None or owner._parent_descriptor is not None:
        owner.validate()
        return
    root, parent = open_spool_root(owner._base_dir)
    owner._parent_descriptor = parent
    for _attempt in range(128):
        name = prefix + secrets.token_hex(16)
        owner.path = root / name
        owner._directory_name = name
        owner._initialization_pending = True
        try:
            filesystem.mkdir_child(parent, name)
        except FileExistsError:
            owner.path = None
            owner._directory_name = None
            owner._initialization_pending = False
            continue
        except BaseException as error:
            owner._initialization_error = error
            return
        break
    else:
        os.close(parent)
        owner._parent_descriptor = None
        raise ExactPublicationError("Unable to allocate a unique Windows private spool")
    try:
        owner._finish_initialization()
    except BaseException as error:
        owner._initialization_error = error


def retained_identity(
    owner: DirectoryOwner,
) -> tuple[os.stat_result, os.stat_result, os.stat_result]:
    """Authenticate retained and reopened handles with real native ownership and ACLs."""
    if owner._closed or owner._unlinked:
        raise ExactPublicationError("Windows private spool is already terminal")
    path, parent, name = owner.path, owner._parent_descriptor, owner._directory_name
    if path is None or parent is None or name is None:
        raise ExactPublicationError("Windows private spool lost its identity")
    reopened = filesystem.open_child(parent, name, os.O_RDONLY, directory=True)
    lexical = None
    try:
        filesystem.require_private(reopened)
        current = os.fstat(reopened)
        if owner._directory_descriptor is None:
            owner._directory_descriptor = os.dup(reopened)
        filesystem.require_private(owner._directory_descriptor)
        retained = os.fstat(owner._directory_descriptor)
        lexical = filesystem.open_directory(path)
        filesystem.require_private(lexical)
        spelled = os.fstat(lexical)
        identity = (int(retained.st_dev), int(retained.st_ino))
        if owner._identity is None:
            owner._identity = identity
        if any(
            not stat.S_ISDIR(metadata.st_mode)
            or (int(metadata.st_dev), int(metadata.st_ino)) != owner._identity
            for metadata in (current, retained, spelled)
        ):
            raise ExactPublicationError("Windows private spool identity changed")
        return current, retained, spelled
    finally:
        if lexical is not None:
            os.close(lexical)
        os.close(reopened)


def finish_initialization(owner: DirectoryOwner) -> None:
    """Validate an empty private directory before making the allocation usable."""
    retained_identity(owner)
    if filesystem.list_directory(owner._directory_descriptor):
        raise ExactPublicationError("Windows private spool was not created empty")
    owner._fsync_parent(owner._parent_descriptor)
    owner._initialization_pending = False


def validate(owner: DirectoryOwner) -> None:
    """Preserve one-shot initialization errors and revalidate the native directory."""
    error = owner._initialization_error
    if error is not None:
        owner._initialization_error = None
        raise error
    if owner._initialization_pending:
        owner._finish_initialization()
    retained_identity(owner)
    if owner._strict_exact:
        validate_ancestry(owner.path.parent)


def require_exact_guarantees(owner: DirectoryOwner) -> None:
    """Check native ownership before upgrading the retained exact journal."""
    validate(owner)
    validate_ancestry(owner.path.parent)
    owner._strict_exact = True
    validate(owner)


def close(owner: DirectoryOwner, *, remove_owned_companions: bool = False) -> None:
    """Reap only owned entries, then release the leaf pin before native removal."""
    if owner._closed:
        return
    owner._initialization_error = None
    parent, name, path = owner._parent_descriptor, owner._directory_name, owner.path
    if parent is None:
        owner._closed = True
        return
    if name is None or path is None:
        os.close(parent)
        owner._parent_descriptor = None
        owner._closed = True
        return
    if not owner._unlinked:
        try:
            retained_identity(owner)
        except FileNotFoundError:
            owner._unlinked = True
        else:
            descriptor = owner._directory_descriptor
            for entry in filesystem.list_directory(descriptor):
                if not remove_owned_companions or not owner._is_owned_journal_component(entry):
                    raise ExactPublicationError("Windows private spool retained an unowned file")
                metadata = filesystem.child_stat(descriptor, entry)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ExactPublicationError("Windows private spool retained an unsafe entry")
                owner._unlink_retained_component(descriptor, entry)
            os.close(descriptor)
            owner._directory_descriptor = None
            try:
                owner._remove_directory(parent, name, path)
            except BaseException:
                try:
                    metadata = filesystem.child_stat(parent, name, directory=True)
                except FileNotFoundError:
                    owner._unlinked = True
                else:
                    if (int(metadata.st_dev), int(metadata.st_ino)) != owner._identity:
                        raise ExactPublicationError("Windows private spool changed during cleanup")
                raise
            else:
                owner._unlinked = True
    owner._fsync_parent(parent)
    if owner._directory_descriptor is not None:
        os.close(owner._directory_descriptor)
        owner._directory_descriptor = None
    os.close(parent)
    owner._parent_descriptor = None
    owner._initialization_pending = False
    owner._closed = True
