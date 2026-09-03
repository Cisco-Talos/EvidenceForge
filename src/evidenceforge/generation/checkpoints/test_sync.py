"""Deterministic test-only synchronization after durable checkpoint publication."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

from .models import CheckpointCursor

_SYNC_DIRECTORY_ENV = "EFORGE_TEST_CHECKPOINT_SYNC_DIR"
_SYNC_HOUR_ENV = "EFORGE_TEST_CHECKPOINT_SYNC_HOUR"
_SYNC_TIMEOUT_ENV = "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT"


def checkpoint_test_synchronizer_from_environment() -> Callable[[CheckpointCursor], None] | None:
    """Build the explicit subprocess-test barrier requested through the environment."""

    raw_directory = os.environ.get(_SYNC_DIRECTORY_ENV)
    if raw_directory is None:
        return None
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise RuntimeError(f"{_SYNC_DIRECTORY_ENV} is reserved for pytest interruption tests")
    directory = Path(raw_directory).resolve()
    if not directory.is_dir():
        raise RuntimeError("checkpoint test synchronization directory must already exist")
    info = directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("checkpoint test synchronization path must be a real directory")
    raw_timeout = os.environ.get(_SYNC_TIMEOUT_ENV, "60")
    try:
        timeout = float(raw_timeout)
    except ValueError as error:
        raise RuntimeError("checkpoint test synchronization timeout is invalid") from error
    if not 0 < timeout <= 300:
        raise RuntimeError("checkpoint test synchronization timeout must be in (0, 300]")
    raw_hour = os.environ.get(_SYNC_HOUR_ENV)
    try:
        target_hour = None if raw_hour is None else int(raw_hour)
    except ValueError as error:
        raise RuntimeError("checkpoint test synchronization hour is invalid") from error
    if target_hour is not None and (target_hour <= 0 or str(target_hour) != raw_hour):
        raise RuntimeError("checkpoint test synchronization hour must be a canonical positive int")

    def synchronize(cursor: CheckpointCursor) -> None:
        if target_hour is not None and cursor.completed_simulated_hours != target_hour:
            return
        stem = f"{cursor.completed_simulated_hours:020d}"
        marker = directory / f"{stem}.ready"
        acknowledgement = directory / f"{stem}.continue"
        payload = json.dumps(
            {
                "completed_simulated_hours": cursor.completed_simulated_hours,
                "next_hour": cursor.next_hour,
                "phase": cursor.phase,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        deadline = time.monotonic() + timeout
        while not acknowledgement.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("checkpoint test synchronization acknowledgement timed out")
            time.sleep(0.01)

    return synchronize


__all__ = ["checkpoint_test_synchronizer_from_environment"]
