# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact controlling-terminal observations tied to POSIX session lifetimes."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from evidenceforge.events.job_control import PosixSessionIdentity
from evidenceforge.events.macos_file import MacosTerminalMetadata, detach_terminal_metadata


@dataclass(frozen=True, slots=True)
class MacosTerminalObservation:
    """A terminal association at one instant, independent of shell executable identity.

    The producer supplies the session, device placement and observed stat.
    A terminal-looking process name or an open stdin descriptor cannot establish
    this controlling-terminal association. Reusing a SID cannot reuse this fact.
    """

    session: PosixSessionIdentity
    native_path: str
    observed_at: datetime
    metadata: MacosTerminalMetadata

    def __post_init__(self) -> None:
        if (
            type(self.session) is not PosixSessionIdentity
            or type(self.native_path) is not str
            or not self.native_path.startswith("/dev/")
            or "\0" in self.native_path
            or ".." in PurePosixPath(self.native_path).parts
            or PurePosixPath(self.native_path).as_posix() != self.native_path
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.observed_at < self.session.started_at
        ):
            raise ValueError("Mac terminal requires exact session, device path and observation")
        self.session.__post_init__()
        object.__setattr__(self, "metadata", detach_terminal_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class MacosTerminalSession:
    """Canonical session-owned device allocation or explicitly known absence.

    Primitive canonical stat text makes the retained allocation immutable and
    checkpointable without retaining caller-owned models. A session's children
    observe this same allocation; exec does not allocate another device.
    """

    session: PosixSessionIdentity
    ordinal: int
    slot: int | None = None
    native_path: str | None = None
    metadata_json: str | None = None

    def __post_init__(self) -> None:
        if type(self.session) is not PosixSessionIdentity or type(self.ordinal) is not int:
            raise ValueError("Mac terminal allocation requires an exact session and ordinal")
        self.session.__post_init__()
        if self.ordinal == 0 and self.slot is self.native_path is self.metadata_json is None:
            return
        if (
            self.ordinal <= 0
            or type(self.slot) is not int
            or not 0 <= self.slot < 4096
            or self.native_path != f"/dev/ttys{self.slot:03d}"
            or type(self.metadata_json) is not str
        ):
            raise ValueError("Mac terminal allocation requires complete device identity")
        metadata = MacosTerminalMetadata.model_validate_json(self.metadata_json)
        if metadata.canonical_json() != self.metadata_json:
            raise ValueError("Mac terminal allocation requires canonical primitive stat")
        birth = self.session.started_at
        from datetime import UTC

        delta = birth - datetime(1970, 1, 1, tzinfo=UTC)
        if (
            metadata.born.seconds != delta.days * 86400 + delta.seconds
            or metadata.born.nanoseconds != delta.microseconds * 1000
            or metadata.file_object_id
            != f"{self.session.hostname}:{metadata.volume_id}:{metadata.inode}"
            or metadata.size_bytes != 0
            or metadata.allocated_blocks != 0
            or metadata.link_count != 1
            or metadata.flags != 0
            or metadata.generation != 0
        ):
            raise ValueError("Mac terminal stat contradicts its modeled session-owned device")

    def observe(self, at: datetime) -> Literal["absent"] | MacosTerminalObservation:
        """Project one exact instant without sampling or reallocating stat."""
        self.__post_init__()
        if type(at) is not datetime or at.utcoffset() is None or at < self.session.started_at:
            raise ValueError("Mac terminal observation cannot precede its session")
        if self.ordinal == 0:
            return "absent"
        return MacosTerminalObservation(
            self.session,
            self.native_path,
            at,
            MacosTerminalMetadata.model_validate_json(self.metadata_json),
        )
