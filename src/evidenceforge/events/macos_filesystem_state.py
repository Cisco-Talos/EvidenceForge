# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact directory and inode-allocator changes owned by a filesystem action."""

from dataclasses import dataclass
from datetime import UTC, datetime

from evidenceforge.events.macos_execution_directory import MacosExecutionDirectory

MAX_FILESYSTEM_DIRECTORY_HISTORY = 128
MAX_FILESYSTEM_DIRECTORIES_PER_HOST = 256


@dataclass(frozen=True, slots=True)
class MacosFilesystemChange:
    """One directory's before/after facts and optional host inode reservation."""

    before: MacosExecutionDirectory
    after: MacosExecutionDirectory
    allocation: tuple[int, int, int] | None = None

    def __post_init__(self) -> None:
        for directory in (self.before, self.after):
            if type(directory) is not MacosExecutionDirectory:
                raise ValueError("Filesystem change requires exact directory observations")
            directory.__post_init__()
        old, new = self.before, self.after
        if (
            old.hostname != new.hostname
            or old.native_path != new.native_path
            or old.observed_at != new.observed_at
            or new.metadata.model_copy(
                update={
                    "modified": old.metadata.modified,
                    "changed": old.metadata.changed,
                    "size_bytes": old.metadata.size_bytes,
                }
            )
            != old.metadata
        ):
            raise ValueError("Filesystem change must preserve its directory object and ownership")
        observed = new.observed_at.astimezone(UTC)
        delta = observed - datetime(1970, 1, 1, tzinfo=UTC)
        epoch_seconds = delta.days * 86400 + delta.seconds
        # Compare through the exact native representation, including nanoseconds.
        for field in ("modified", "changed"):
            before = getattr(old.metadata, field)
            after = getattr(new.metadata, field)
            if not (
                (before.seconds, before.nanoseconds)
                <= (after.seconds, after.nanoseconds)
                <= (epoch_seconds, observed.microsecond * 1000)
            ):
                raise ValueError("Filesystem directory times must advance within their occurrence")
        if self.allocation is not None:
            if type(self.allocation) is not tuple or len(self.allocation) != 3:
                raise ValueError("Filesystem change requires an exact three-value allocation")
            base, before, after = self.allocation
            if any(type(value) is not int for value in self.allocation) or not (
                0 < base <= after < 2**63 and before == after - 1 and before >= base - 1
            ):
                raise ValueError("Filesystem change requires one exact monotonic inode allocation")
