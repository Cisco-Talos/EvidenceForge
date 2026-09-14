"""Windows-only private journal ownership for Security and Sysmon emitters.

The emitter retains its existing candidate, receipt, rendering, and SQLite schema
logic. These functions own only native filesystem allocation and validation.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from evidenceforge.generation.emitters.base import ExactPublicationError
from evidenceforge.utils import windows_filesystem as filesystem

if TYPE_CHECKING:
    from evidenceforge.generation.emitters.source_journal import SourceOwner


def _identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    return int(metadata.st_dev), int(metadata.st_ino)


def _private_identity(descriptor: int, *, directory: bool) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not correct_type or (not directory and metadata.st_nlink != 1):
        raise ExactPublicationError(
            "Windows private journal has an invalid file type or link count"
        )
    filesystem.require_private(descriptor)
    return int(metadata.st_dev), int(metadata.st_ino)


def validate_ancestry(path: Path) -> None:
    """Validate native ACLs on every existing private-spool ancestor."""
    current = Path(os.path.abspath(path))
    while True:
        descriptor = filesystem.open_directory(current)
        try:
            filesystem.require_private(descriptor, ancestry=True)
        except PermissionError as error:
            raise PermissionError(f"Windows spool ancestor {current}: {error}") from error
        finally:
            os.close(descriptor)
        if current == current.parent:
            return
        current = current.parent


def _spool_root() -> Path:
    configured = os.environ.get("EFORGE_SPOOL_DIR")
    return Path(
        os.path.abspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
    )


def require_capabilities() -> None:
    """Check native NTFS and ACL support before starting emitter threads."""
    ancestor = _spool_root()
    while not ancestor.exists():
        ancestor = ancestor.parent
    validate_ancestry(ancestor)


def preflight_private_spool_root(owner: SourceOwner, *, provider: str) -> None:
    """Keep active private spools outside public output and validate their ancestry."""
    root = _spool_root()
    output = Path(os.path.abspath(owner._base_dir))
    if root == output or root.is_relative_to(output):
        raise ExactPublicationError(f"{provider} private spool must be outside public output")
    ancestor = root
    while not ancestor.exists():
        ancestor = ancestor.parent
    validate_ancestry(ancestor)


def validate_spool_directory(owner: SourceOwner) -> None:
    """Require both retained and reopened directory identities and private native ACLs."""
    descriptor = owner._spool_directory_descriptor
    root = owner._spool_root_descriptor
    name = owner._spool_directory_name
    identity = owner._spool_directory_identity
    if descriptor is None or root is None or name is None or identity is None:
        raise ExactPublicationError("Windows private spool lost its identity")
    if _identity(root) != owner._spool_root_identity:
        raise ExactPublicationError("Windows private spool root identity changed")
    if _private_identity(descriptor, directory=True) != identity:
        raise ExactPublicationError("Windows private spool retained identity changed")
    reopened = filesystem.open_child(root, name, os.O_RDONLY, directory=True)
    try:
        if _private_identity(reopened, directory=True) != identity:
            raise ExactPublicationError("Windows private spool directory entry changed")
    finally:
        os.close(reopened)


def validate_spool_file(owner: SourceOwner) -> None:
    """Require one private regular SQLite file with its original identity."""
    validate_spool_directory(owner)
    parent = owner._spool_directory_descriptor
    name = owner._spool_filename
    if parent is None or name is None or owner._spool_file_identity is None:
        raise ExactPublicationError("Windows private journal lost its identity")
    descriptor = filesystem.open_child(parent, name, os.O_RDONLY)
    try:
        if _private_identity(descriptor, directory=False) != owner._spool_file_identity:
            raise ExactPublicationError("Windows private journal identity changed")
    finally:
        os.close(descriptor)


def adopt_private_spool_create_lost_return(owner: SourceOwner) -> None:
    """Adopt only the private native directory left by an uncertain create return."""
    root = owner._spool_root_descriptor
    name = owner._spool_directory_name
    if root is None or name is None:
        raise ExactPublicationError("Windows private spool lost its create owner")
    try:
        descriptor = filesystem.open_child(root, name, os.O_RDONLY, directory=True)
    except FileNotFoundError:
        return
    try:
        owner._spool_directory_identity = _private_identity(descriptor, directory=True)
    finally:
        os.close(descriptor)


def finish_private_spool_initialization(owner: SourceOwner) -> None:
    """Retain the directory handle before committing private-spool initialization."""
    root = owner._spool_root_descriptor
    name = owner._spool_directory_name
    if root is None or name is None:
        raise ExactPublicationError("Windows private spool lost its initialization owner")
    try:
        descriptor = filesystem.open_child(root, name, os.O_RDONLY, directory=True)
    except FileNotFoundError:
        try:
            filesystem.mkdir_child(root, name)
        except BaseException:
            adopt_private_spool_create_lost_return(owner)
            raise
        descriptor = filesystem.open_child(root, name, os.O_RDONLY, directory=True)
    try:
        identity = _private_identity(descriptor, directory=True)
        if owner._spool_directory_identity not in {None, identity}:
            raise ExactPublicationError("Windows private spool directory identity changed")
        if owner._spool_directory_descriptor is None:
            owner._spool_directory_descriptor = descriptor
            descriptor = None
        if _identity(owner._spool_directory_descriptor) != identity:
            raise ExactPublicationError("Windows private spool retained descriptor changed")
        owner._spool_directory_identity = identity
        owner._spool_initialization_pending = False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def get_spool_directory(owner: SourceOwner, *, provider: str) -> Path:
    """Allocate a private native journal directory without changing emitter semantics."""
    if owner._spool_dir is not None:
        if owner._spool_initialization_pending:
            finish_private_spool_initialization(owner)
        validate_spool_directory(owner)
        return owner._spool_dir
    preflight_private_spool_root(owner, provider=provider)
    root_path = _spool_root()
    root = filesystem.open_directory(root_path, create=bool(os.environ.get("EFORGE_SPOOL_DIR")))
    try:
        validate_ancestry(root_path)
    except BaseException:
        os.close(root)
        raise
    owner._spool_root_descriptor = root
    owner._spool_root_identity = _identity(root)
    for _attempt in range(128):
        name = f"evidenceforge-{provider.lower()}-spool-{secrets.token_hex(16)}"
        owner._spool_directory_name = name
        owner._spool_dir = root_path / name
        owner._owns_spool_dir = True
        owner._spool_initialization_pending = True
        try:
            filesystem.mkdir_child(root, name)
        except FileExistsError:
            owner._spool_directory_name = None
            owner._spool_dir = None
            owner._owns_spool_dir = False
            owner._spool_initialization_pending = False
            continue
        except BaseException:
            adopt_private_spool_create_lost_return(owner)
            raise
        break
    else:
        os.close(root)
        owner._spool_root_descriptor = None
        owner._spool_root_identity = None
        raise ExactPublicationError(f"Unable to allocate a unique {provider} private spool")
    finish_private_spool_initialization(owner)
    validate_spool_directory(owner)
    return owner._spool_dir


def adopt_private_journal_descriptor(owner: SourceOwner, descriptor: int) -> None:
    """Retain a newly created file's native ACL-validated identity."""
    owner._spool_file_identity = _private_identity(descriptor, directory=False)


def adopt_private_journal_create_lost_return(owner: SourceOwner) -> None:
    """Adopt only a private regular file after an uncertain exclusive create return."""
    parent = owner._spool_directory_descriptor
    name = owner._spool_filename
    if parent is None or name is None:
        raise ExactPublicationError("Windows private journal lost its create owner")
    try:
        descriptor = filesystem.open_child(parent, name, os.O_RDWR)
    except FileNotFoundError:
        return
    try:
        adopt_private_journal_descriptor(owner, descriptor)
    finally:
        os.close(descriptor)


def finish_private_journal_initialization(owner: SourceOwner) -> None:
    """Retain the existing SQLite schema and commit protocol inside native private storage."""
    parent = owner._spool_directory_descriptor
    name = owner._spool_filename
    path = owner._spool_path
    if parent is None or name is None or path is None:
        raise ExactPublicationError("Windows private journal lost its initialization owner")
    if owner._spool_file_identity is None:
        try:
            descriptor = filesystem.open_child(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        except FileExistsError as error:
            raise ExactPublicationError(
                "Windows private journal create ownership is ambiguous"
            ) from error
        except BaseException:
            adopt_private_journal_create_lost_return(owner)
            raise
        else:
            try:
                adopt_private_journal_descriptor(owner, descriptor)
            finally:
                os.close(descriptor)
    validate_spool_file(owner)
    if owner._spool_conn is None:
        owner._spool_conn = sqlite3.connect(
            f"{path.as_uri()}?mode=rw", uri=True, check_same_thread=False
        )
    owner._initialize_spool_schema_unlocked(owner._spool_conn)
    validate_spool_file(owner)
    owner._spool_file_initialization_pending = False


def get_spool_connection(owner: SourceOwner, *, provider: str) -> sqlite3.Connection:
    """Open native private storage while reusing the emitter's existing schema and state."""
    if owner._spool_conn is not None:
        if owner._spool_file_initialization_pending:
            finish_private_journal_initialization(owner)
        return owner._spool_conn
    directory = get_spool_directory(owner, provider=provider)
    parent = owner._spool_directory_descriptor
    if parent is None:
        raise ExactPublicationError("Windows private spool lost its directory descriptor")
    if owner._spool_filename is None:
        prefix = ".windows_event_spool_" if provider == "Windows" else ".sysmon_event_spool_"
        for _attempt in range(128):
            name = f"{prefix}{secrets.token_hex(16)}.sqlite3"
            owner._spool_filename = name
            owner._spool_path = directory / name
            owner._spool_file_initialization_pending = True
            try:
                descriptor = filesystem.open_child(parent, name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                owner._spool_filename = None
                owner._spool_path = None
                owner._spool_file_initialization_pending = False
                continue
            except BaseException:
                adopt_private_journal_create_lost_return(owner)
                raise
            else:
                try:
                    adopt_private_journal_descriptor(owner, descriptor)
                finally:
                    os.close(descriptor)
                break
        else:
            raise ExactPublicationError(f"Unable to allocate a unique {provider} private journal")
    finish_private_journal_initialization(owner)
    return owner._spool_conn


def cleanup_spool(owner: SourceOwner) -> None:
    """Close SQLite before native identity-checked terminal journal cleanup."""
    if (
        owner._exact_candidate_abort_close_rendering
        and not owner._exact_candidate_abort_close_rows_rendered
    ):
        raise ExactPublicationError(
            "Windows abort close cannot clear its journal before exact rows render"
        )
    if owner._spool_conn is not None:
        owner._spool_conn.close()
        owner._spool_conn = None
    parent = owner._spool_directory_descriptor
    name = owner._spool_filename
    if parent is not None:
        validate_spool_directory(owner)
    if parent is not None and name is not None:
        for candidate in (name, *(name + suffix for suffix in ("-journal", "-wal", "-shm"))):
            try:
                metadata = filesystem.child_stat(parent, candidate)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ExactPublicationError(
                    "Windows private journal cleanup found an invalid entry"
                )
            if (
                candidate == name
                and (int(metadata.st_dev), int(metadata.st_ino)) != owner._spool_file_identity
            ):
                raise ExactPublicationError("Windows private journal changed before cleanup")
            filesystem.remove_child(
                parent, candidate, expected_identity=(int(metadata.st_dev), int(metadata.st_ino))
            )
    if parent is not None:
        os.close(parent)
        owner._spool_directory_descriptor = None
    root = owner._spool_root_descriptor
    directory_name = owner._spool_directory_name
    if owner._owns_spool_dir and root is not None and directory_name is not None:
        try:
            metadata = filesystem.child_stat(root, directory_name, directory=True)
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            if (int(metadata.st_dev), int(metadata.st_ino)) != owner._spool_directory_identity:
                raise ExactPublicationError(
                    "Windows private spool changed before directory cleanup"
                )
            filesystem.remove_child(
                root,
                directory_name,
                directory=True,
                expected_identity=owner._spool_directory_identity,
            )
        os.close(root)
        owner._spool_root_descriptor = None
    owner._spool_path = None
    owner._spool_filename = None
    owner._spool_file_identity = None
    owner._spool_file_initialization_pending = False
    owner._spool_directory_identity = None
    owner._spool_root_identity = None
    owner._spool_directory_name = None
    owner._spool_dir = None
    owner._owns_spool_dir = False
    owner._spooled_count = 0
    owner._candidate_admitted_rows = 0
    owner._candidate_admitted_bytes = 0
    if owner._exact_candidate_abort_close_rendering:
        owner._exact_candidate_abort_close_render_complete = True
