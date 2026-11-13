# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded retries for Windows removal of caller-owned temporary trees."""

from __future__ import annotations

import logging
import os
import shutil
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


def remove_temporary_tree(path: Path) -> None:
    """Remove an owned scratch tree without hiding persistent deletion failures.

    Windows scanners and sync clients can temporarily prevent removal after our
    own streams close. Retry only their possible native delete errors, preserving
    the original exception after a bounded wait. A handle-checked read-only bit
    can be cleared on an owned entry; ACLs, other attributes and redirecting links
    are not changed. Callers establish ownership before passing a path. POSIX
    keeps its ordinary single removal.
    """
    physical = filesystem_path(path)
    if not _WINDOWS:
        shutil.rmtree(physical)
        return
    for attempt in range(len(_DELETE_RETRY_DELAYS) + 1):
        try:
            shutil.rmtree(physical)
            return
        except FileNotFoundError:
            if not physical.exists():
                return
            raise
        except OSError as error:
            if getattr(error, "winerror", None) not in _RETRYABLE_DELETE_ERRORS or attempt == len(
                _DELETE_RETRY_DELAYS
            ):
                raise
            try:
                if _repair_readonly_entry(physical, error):
                    continue
            except OSError as repair_error:
                logger.debug(
                    "Windows scratch attribute repair failed for %s: %s", path, repair_error
                )
            logger.debug("Retrying Windows temporary-tree removal for %s: %s", path, error)
            sleep(_DELETE_RETRY_DELAYS[attempt])
