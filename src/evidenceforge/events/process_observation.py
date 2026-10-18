# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable event-time process relationships for source-specific projections."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

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


@dataclass(frozen=True, slots=True)
class ProcessResponsibilityObservation:
    """Exact responsible execution, or self with an explicit absence/exit reason."""

    process: ProcessIdentity
    responsible: ProcessIdentity
    observed_at: datetime
    reason: Literal["active", "absent", "exited"]
    responsible_exit_at: datetime | None = None

    def __post_init__(self) -> None:
        from evidenceforge.events.responsibility import ResponsibleProcessReference

        if (
            type(self.process) is not ProcessIdentity
            or type(self.responsible) is not ProcessIdentity
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.process.execution_started_at > self.observed_at
            or self.responsible.execution_started_at > self.observed_at
            or self.process.responsibility is None
            or type(self.reason) is not str
            or self.reason not in {"active", "absent", "exited"}
        ):
            raise ValueError("Responsibility observation requires exact timed known facts")
        reference = self.process.responsibility.responsible
        if self.reason == "active":
            if self.responsible_exit_at is not None or reference != ResponsibleProcessReference(
                self.responsible.hostname,
                self.responsible.object_id,
                self.responsible.pid,
                self.responsible.started_at,
            ):
                raise ValueError("Responsibility observation requires its exact active lifetime")
        elif self.responsible != self.process:
            raise ValueError("Absent or exited responsibility must project the process itself")
        elif self.reason == "absent":
            if reference is not None or self.responsible_exit_at is not None:
                raise ValueError("Absent responsibility requires explicit absence")
        elif (
            reference is None
            or type(self.responsible_exit_at) is not datetime
            or self.responsible_exit_at.utcoffset() is None
            or not reference.started_at <= self.responsible_exit_at <= self.observed_at
        ):
            raise ValueError("Exited responsibility requires an ordered explicit exit time")


@dataclass(frozen=True, slots=True)
class ProcessRelationshipObservation:
    """Parent and responsibility snapshots captured for the same occurrence."""

    parent: ProcessParentObservation
    responsibility: ProcessResponsibilityObservation

    def __post_init__(self) -> None:
        if (
            type(self.parent) is not ProcessParentObservation
            or type(self.responsibility) is not ProcessResponsibilityObservation
            or self.parent.process != self.responsibility.process
            or self.parent.observed_at != self.responsibility.observed_at
        ):
            raise ValueError("Process relationships require the same exact subject and event time")
