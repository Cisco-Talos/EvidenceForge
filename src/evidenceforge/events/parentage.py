# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded exact parent lifetime references, independent of mutable PID lookup."""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from pydantic import Field


@dataclass(frozen=True, slots=True)
class ProcessParentReference:
    """One exact parent incarnation without recursively retaining its ancestry."""

    hostname: Annotated[str, Field(strict=True, min_length=1)]
    object_id: Annotated[str, Field(strict=True, min_length=1)]
    pid: Annotated[int, Field(strict=True, gt=0, lt=2**31)]
    started_at: Annotated[datetime, Field(strict=True)]

    def __post_init__(self) -> None:
        if (
            type(self.hostname) is not str
            or not self.hostname
            or type(self.object_id) is not str
            or not self.object_id
            or type(self.pid) is not int
            or not 0 < self.pid < 2**31
            or type(self.started_at) is not datetime
            or self.started_at.utcoffset() is None
        ):
            raise ValueError(
                "Process parent reference requires an exact host, lifetime, PID and time"
            )


@dataclass(frozen=True, slots=True)
class ProcessParentage:
    """Original and current parent facts; an explicit None denotes no parent.

    An absent ProcessParentage on a process means unknown legacy parentage.
    This record does not itself authorize a reparenting transition.
    """

    original: ProcessParentReference | None
    current: ProcessParentReference | None

    def __post_init__(self) -> None:
        for reference in (self.original, self.current):
            if reference is not None and type(reference) is not ProcessParentReference:
                raise ValueError("Process parentage requires exact immutable references")
        if (
            self.original is not None
            and self.current is not None
            and self.original.hostname != self.current.hostname
        ):
            raise ValueError("Process parentage cannot cross a host boundary")

    @property
    def original_pid(self) -> int:
        """Return the original native PPID, preserving the explicit no-parent value."""
        return self.original.pid if self.original is not None else 0

    @property
    def current_pid(self) -> int:
        """Return the current native PPID without consulting a PID allocator."""
        return self.current.pid if self.current is not None else 0


def validate_process_parentage(
    parentage: ProcessParentage | None,
    *,
    hostname: str,
    object_id: str,
    parent_pid: int,
    started_at: datetime,
) -> None:
    """Validate bounded references against their owning process lifetime."""
    if parentage is None:
        return
    if type(parentage) is not ProcessParentage or parentage.current_pid != parent_pid:
        raise ValueError("Process parentage must agree with its current parent PID")
    for parent in (parentage.original, parentage.current):
        if parent is not None and (parent.hostname != hostname or parent.object_id == object_id):
            raise ValueError("Process parentage must use another lifetime on the same host")
    if parentage.original is not None and parentage.original.started_at > started_at:
        raise ValueError("Original parent cannot start after its child")
