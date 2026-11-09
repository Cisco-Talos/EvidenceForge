# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit working-directory facts at a Mac process launch or image replacement."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

from evidenceforge.events.macos_file import MacosDirectoryMetadata, detach_directory_metadata


@dataclass(frozen=True, slots=True)
class MacosExecutionDirectory:
    """An execution-time observation, not a process's permanently current directory.

    All facts come from a modeled producer. A later fork/exec must supply its own
    observation: the task may have changed directory since this snapshot. No
    generator-host filesystem, environment expansion, or inode allocation occurs.
    """

    hostname: str
    native_path: str
    observed_at: datetime
    metadata: MacosDirectoryMetadata

    def __post_init__(self) -> None:
        if (
            type(self.hostname) is not str
            or not self.hostname.strip()
            or "\0" in self.hostname
            or type(self.native_path) is not str
            or not self.native_path.startswith("/")
            or "\0" in self.native_path
            or ".." in PurePosixPath(self.native_path).parts
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or type(self.metadata) is not MacosDirectoryMetadata
        ):
            raise ValueError("Mac execution directory requires exact host, absolute path and stat")
        detach_directory_metadata(self.metadata)


def validate_macos_execution_directory(
    directory: MacosExecutionDirectory | None,
    *,
    hostname: str,
    observed_at: datetime,
    platform: str = "macos",
) -> None:
    """Require an explicitly supplied directory to belong to this exact occurrence."""
    if directory is None:
        return
    if type(directory) is not MacosExecutionDirectory:
        raise ValueError("Mac execution directory requires its exact immutable type")
    directory.__post_init__()
    if (
        platform != "macos"
        or directory.hostname != hostname
        or directory.observed_at != observed_at
    ):
        raise ValueError("Mac execution directory requires its macOS host and execution time")
