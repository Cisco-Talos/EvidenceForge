# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared removal policy for caller-owned workspace and temporary entries."""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from time import sleep

from evidenceforge._windows_paths import filesystem_path

logger = logging.getLogger(__name__)

_WINDOWS = os.name == "nt"
_DELETE_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)
_RETRYABLE_DELETE_ERRORS = frozenset({5, 32, 33, 145})


def _repair_readonly_entry(root: Path, error: OSError) -> bool:
    if getattr(error, "winerror", None) != 5 or error.filename is None:
        return False
    target = filesystem_path(Path(error.filename))
    if target != root and not target.is_relative_to(root):
        return False
    from evidenceforge._windows_cleanup_native import clear_readonly_for_removal

    return clear_readonly_for_removal(target)


def _remove(
    path: Path,
    operation: Callable[[Path], None],
    *,
    can_retry: Callable[[], bool] | None = None,
) -> None:
    """Retry removal only, after the caller has established ownership."""
    physical = filesystem_path(path)
    if not _WINDOWS:
        operation(physical)
        return
    for attempt in range(len(_DELETE_RETRY_DELAYS) + 1):
        try:
            operation(physical)
            return
        except FileNotFoundError:
            if not physical.exists():
                return
            raise
        except OSError as error:
            if (
                (can_retry is not None and not can_retry())
                or getattr(error, "winerror", None) not in _RETRYABLE_DELETE_ERRORS
                or attempt == len(_DELETE_RETRY_DELAYS)
            ):
                raise
            try:
                if _repair_readonly_entry(physical, error):
                    continue
            except OSError as repair_error:
                logger.debug(
                    "Windows removal attribute repair failed for %s: %s", path, repair_error
                )
            logger.debug("Retrying Windows owned-entry removal for %s: %s", path, error)
            sleep(_DELETE_RETRY_DELAYS[attempt])


def remove_owned_tree(path: Path, *, ignore_errors: bool = False) -> None:
    """Remove a caller-owned tree without hiding persistent deletion failures.

    Windows scanners and sync clients can temporarily prevent removal after our
    own streams close. Retry only their possible native delete errors, preserving
    the original exception after a bounded wait. A handle-checked read-only bit
    can be cleared on an owned entry; ACLs, other attributes and redirecting links
    are not changed. Callers establish ownership before passing a path. POSIX
    keeps its ordinary single removal.
    """
    entry_budget_exhausted = False

    def retry_entry(operation: Callable[..., None], name: str, error: BaseException) -> None:
        nonlocal entry_budget_exhausted
        if (
            not isinstance(error, OSError)
            or getattr(error, "winerror", None) not in _RETRYABLE_DELETE_ERRORS
            or operation not in (os.unlink, os.rmdir)
        ):
            raise error
        # Each entry gets a budget; a large read-only tree must not consume one
        # root retry per attribute repair. Only unlink/rmdir can be replayed here.
        try:
            _remove(Path(name), operation)
        except OSError:
            entry_budget_exhausted = True
            if not ignore_errors:
                raise

    def remove_once(physical: Path) -> None:
        if _WINDOWS:
            shutil.rmtree(physical, onexc=retry_entry)
        elif ignore_errors:
            shutil.rmtree(physical, ignore_errors=True)
        else:
            shutil.rmtree(physical)

    try:
        _remove(path, remove_once, can_retry=lambda: not entry_budget_exhausted)
    except OSError:
        if not ignore_errors:
            raise


def remove_owned_file(path: Path) -> None:
    """Unlink one owned file using the same bounded Windows removal policy."""
    _remove(path, Path.unlink)


def remove_empty_owned_directory(path: Path) -> None:
    """Remove an empty owned directory without recursive traversal."""
    _remove(path, Path.rmdir)


def remove_temporary_tree(path: Path) -> None:
    """Remove caller-owned scratch through the shared workspace removal policy."""
    remove_owned_tree(path)
