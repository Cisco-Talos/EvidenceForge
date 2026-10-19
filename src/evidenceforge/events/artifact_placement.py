# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Retained publication/removal times for one immutable runtime placement version."""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.content_identity import LocalArtifactIdentity


@dataclass(frozen=True, slots=True)
class LocalArtifactPlacementObservation:
    """Canonical placement bounds, independent of loaded content retention.

    Older checkpoints may lack either bound. Out-of-order legacy publications
    may have contradictory bounds; they cannot establish historical presence.
    This describes one retained version, not a complete file-object path history.
    """

    artifact: LocalArtifactIdentity
    introduced_at: datetime | None
    withdrawn: bool
    withdrawn_at: datetime | None

    def __post_init__(self) -> None:
        if (
            type(self.artifact) is not LocalArtifactIdentity
            or type(self.withdrawn) is not bool
            or (not self.withdrawn and self.withdrawn_at is not None)
            or any(
                type(at) is not datetime or at.utcoffset() is None
                for at in (self.introduced_at, self.withdrawn_at)
                if at is not None
            )
        ):
            raise ValueError("Artifact placement requires an exact identity and known aware bounds")

    def present_at(self, timestamp: datetime) -> bool | None:
        """Return bounded presence, or unknown when retained facts do not establish it."""
        if type(timestamp) is not datetime or timestamp.utcoffset() is None:
            raise ValueError("Artifact placement observation requires an aware timestamp")
        if self.introduced_at is None or (self.withdrawn and self.withdrawn_at is None):
            return None
        if self.withdrawn_at is not None and self.withdrawn_at < self.introduced_at:
            return None
        return timestamp >= self.introduced_at and (
            self.withdrawn_at is None or timestamp < self.withdrawn_at
        )
