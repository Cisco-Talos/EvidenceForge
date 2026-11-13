# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Generated-file opens that tolerate bounded Windows sharing conflicts."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path
from time import sleep
from typing import IO, Any

from evidenceforge._windows_paths import filesystem_path

logger = logging.getLogger(__name__)

_WINDOWS = os.name == "nt"
_OPEN_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2)
_RETRYABLE_NATIVE_ERRORS = frozenset({5, 32, 33})


def _retryable(error: OSError) -> bool:
    native = getattr(error, "winerror", None)
    if native is not None:
        return native in _RETRYABLE_NATIVE_ERRORS
    # The Windows CRT maps both sharing conflicts and permission denial to
    # EACCES without retaining winerror. Never interpret it as permission to
    # change ACLs/attributes; a persistent failure remains the original error.
    return error.errno == errno.EACCES


def _metadata(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        return f"metadata unavailable ({type(error).__name__})"
    return (
        f"attributes=0x{getattr(metadata, 'st_file_attributes', 0):x}, "
        f"reparse_tag=0x{getattr(metadata, 'st_reparse_tag', 0):x}"
    )


def open_generated_file(
    path: Path,
    mode: str,
    *,
    encoding: str | None = None,
    newline: str | None = None,
) -> IO[Any]:
    """Open caller-owned output/spool data, retrying only acquisition on Windows.

    Callers retain path validation and publication ownership. Preserve Python's
    access/sharing modes and all ACLs/attributes. Once a stream is returned, no
    read, write, flush, close or publication operation is automatically replayed.
    POSIX performs its existing single open. Persistent Windows access failures
    include metadata diagnostics and propagate after at most 6.35 seconds of waits.
    """
    physical = filesystem_path(path)
    if not _WINDOWS:
        return open(physical, mode, encoding=encoding, newline=newline)
    for attempt in range(len(_OPEN_RETRY_DELAYS) + 1):
        try:
            return open(physical, mode, encoding=encoding, newline=newline)
        except OSError as error:
            if not _retryable(error):
                raise
            if attempt == len(_OPEN_RETRY_DELAYS):
                detail = _metadata(physical)
                note = (
                    f"Generated file stayed inaccessible after bounded Windows open retries "
                    f"({detail}). Another application may be using it, or access may be "
                    "restricted. The failed output has not been accepted as complete."
                )
                error.add_note(note)
                logger.error("Cannot open generated file %s: %s", path, note)
                raise
            logger.debug("Retrying Windows generated-file open for %s: %s", path, error)
            sleep(_OPEN_RETRY_DELAYS[attempt])
    raise AssertionError("Generated-file open retry loop did not terminate")
