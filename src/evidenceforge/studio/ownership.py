"""OS-account isolation for private Studio state and helper discovery."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.state_io import (
    StudioStateError,
    canonical_path,
    parent_handle,
    private_directory,
    safe_path,
)


class AccountIdentity(BaseModel):
    """Stable OS identity; display names and client headers are never identities."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["uid", "sid"]
    value: str = Field(min_length=1)


def current_account() -> AccountIdentity:
    """Read the actual account, refusing mixed POSIX elevation."""
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import current_user_sid

        return AccountIdentity(kind="sid", value=current_user_sid())
    if os.getuid() != os.geteuid():
        raise StudioStateError("Run Studio as your normal account, without changing user identity")
    return AccountIdentity(kind="uid", value=str(os.geteuid()))


def process_account(process: psutil.Process) -> AccountIdentity:
    """Read a live process's account without trusting a descriptor or username."""
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import process_user_sid

        return AccountIdentity(kind="sid", value=process_user_sid(process.pid))
    ids = process.uids()
    if len(set(ids)) != 1:
        raise StudioStateError("Studio helper has mixed user identities; it cannot be attached")
    return AccountIdentity(kind="uid", value=str(ids.effective))


def require_owned(metadata: os.stat_result) -> None:
    """Reject foreign POSIX objects even when the caller can read them."""
    if os.name != "nt" and metadata.st_uid != int(current_account().value):
        raise StudioStateError("Studio private state belongs to another OS account")


def secure_directory(
    path: Path,
    *,
    repair: bool = False,
    inspect_only: bool = False,
    repair_ancestors: frozenset[Path] = frozenset(),
) -> None:
    """Validate a private root; repair permissions only on a verified owned default."""
    safe_path(path)
    if os.name == "nt":
        if inspect_only and not path.exists():
            return
        private_directory(path)  # Native owner/SID and DACL verification, including ancestry.
        return
    uid = int(current_account().value)
    absolute = canonical_path(path)
    # Writable non-sticky ancestry would allow another account to substitute the root.
    for ancestor in absolute.parents:
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            continue
        if metadata.st_uid not in {0, uid} or (
            metadata.st_mode & 0o022
            and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
            and not (metadata.st_uid == uid and ancestor in repair_ancestors)
        ):
            raise StudioStateError("Studio private root has unsafe ownership or writable ancestry")
    # Check before creating descendants or modifying permissions.
    if absolute.exists():
        metadata = absolute.lstat()
        require_owned(metadata)
        if metadata.st_mode & 0o077 and not repair:
            raise StudioStateError(
                "Custom Studio storage must be private to your account (directory mode 700); "
                "choose a private directory or correct its permissions before reopening"
            )
    if inspect_only:
        return
    private_directory(absolute)
    parent = parent_handle(absolute)
    try:
        descriptor = os.open(
            absolute.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            metadata = os.fstat(descriptor)
            require_owned(metadata)
            if metadata.st_mode & 0o077:
                if not repair:
                    raise StudioStateError("Custom Studio storage is not private to your account")
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            # Refuse substitution between inspection and handle acquisition.
            observed = absolute.lstat()
            if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise StudioStateError("Studio private root changed during ownership verification")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def validate_private_paths(paths: StudioPaths) -> None:
    """Prepare only application-owned roots, before reading state or credentials."""
    roots = sorted(
        {paths.config, paths.data, paths.state, paths.cache, paths.logs},
        key=lambda path: len(path.parts),
    )
    repairs = frozenset(
        canonical_path(root)
        for root in roots
        if not any(
            root.absolute().is_relative_to(parent.absolute()) for parent in paths.custom_roots
        )
    )
    # Validate the whole set before tightening any directory or creating descendants.
    for root in (*paths.custom_roots, *roots):
        secure_directory(
            root,
            repair=canonical_path(root) in repairs,
            inspect_only=True,
            repair_ancestors=repairs,
        )
    # These authoritative entries may exist before stores or migration inspection run.
    for path in (
        paths.settings_file,
        paths.database_file,
        paths.data / "studio-state.json",
        paths.database_file.with_name("studio.sqlite-wal"),
        paths.database_file.with_name("studio.sqlite-shm"),
    ):
        safe_path(path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        require_owned(metadata)
    for root in (*paths.custom_roots, *roots):
        secure_directory(root, repair=canonical_path(root) in repairs)
