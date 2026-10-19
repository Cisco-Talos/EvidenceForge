# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact controlling-terminal observations tied to POSIX session lifetimes."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

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
