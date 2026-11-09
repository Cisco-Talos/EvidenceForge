# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit process responsibility, independent of parent and login identity."""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from pydantic import Field


@dataclass(frozen=True, slots=True)
class ResponsibleProcessReference:
    """Exact responsible lifetime without retaining a recursive process graph."""

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
            raise ValueError("Responsibility requires an exact host, lifetime, PID and aware time")


@dataclass(frozen=True, slots=True)
class ProcessResponsibility:
    """Known responsibility; None reference explicitly means no responsible process.

    An absent ProcessResponsibility on a process means unknown. This bounded
    profile establishes responsibility at launch and preserves it through fork
    and exec. It does not infer responsibility from parentage or GUI activity.
    """

    responsible: ResponsibleProcessReference | None

    def __post_init__(self) -> None:
        if (
            self.responsible is not None
            and type(self.responsible) is not ResponsibleProcessReference
        ):
            raise ValueError("Responsibility requires an exact immutable lifetime reference")


def validate_process_responsibility(
    responsibility: ProcessResponsibility | None,
    *,
    hostname: str,
    object_id: str,
    started_at: datetime,
) -> None:
    """Validate immutable relationship structure independently of live State admission."""
    if responsibility is None:
        return
    if type(responsibility) is not ProcessResponsibility:
        raise ValueError("Process responsibility requires its exact immutable type")
    reference = responsibility.responsible
    if reference is not None and (
        reference.hostname != hostname
        or reference.object_id == object_id
        or reference.started_at > started_at
    ):
        raise ValueError("Responsibility requires a prior distinct lifetime on the same host")
