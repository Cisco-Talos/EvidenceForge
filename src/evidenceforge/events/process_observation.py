# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable event-time process relationships for source-specific projections."""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.parentage import ProcessParentReference


@dataclass(frozen=True, slots=True)
class ProcessParentObservation:
    """Freeze a child and its exact current parent's execution at one instant.

    A None parent denotes explicitly known no-parent state. Unknown parentage
    cannot produce this observation. The observation carries canonical facts,
    not native collection authority or a fabricated responsible-process identity.
    """

    process: ProcessIdentity
    parent: ProcessIdentity | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.process) is not ProcessIdentity
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.observed_at < self.process.execution_started_at
            or self.process.parentage is None
        ):
            raise ValueError("Parent observation requires exact timed process and known parentage")
        reference = self.process.parentage.current
        if reference is None:
            if self.parent is not None or self.process.parentage.original is not None:
                raise ValueError("Parent observation disagrees with explicit no-parent state")
            return
        if (
            type(self.parent) is not ProcessIdentity
            or self.parent.object_id == self.process.object_id
            or self.parent.execution_started_at > self.observed_at
            or reference
            != ProcessParentReference(
                self.parent.hostname, self.parent.object_id, self.parent.pid, self.parent.started_at
            )
        ):
            raise ValueError("Parent observation requires the exact same-host parent incarnation")
