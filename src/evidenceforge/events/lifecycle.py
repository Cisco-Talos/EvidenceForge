# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed lifecycle metadata for correlated action groups."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

LifecyclePhase = Literal["start", "dependent", "closure"]
SessionEndAuthority = Literal["explicit_storyline", "generated"]


@dataclass(frozen=True, slots=True)
class SessionEndPlan:
    """Canonical intent for one durable session end.

    Explicit storyline plans are authoritative deadlines. Generated plans may
    still be moved after later activity by the owning session bundle.
    """

    canonical_end: datetime
    authority: SessionEndAuthority
    storyline_event_id: str = ""

    @property
    def is_authoritative(self) -> bool:
        """Return whether dependents must be bounded by this end time."""

        return self.authority == "explicit_storyline"

    def __post_init__(self) -> None:
        """Require explicit plans to retain their storyline owner."""

        if self.authority == "explicit_storyline" and not self.storyline_event_id:
            raise ValueError("Explicit session end plans require a storyline_event_id")


@dataclass(frozen=True, slots=True)
class ActionLifecycleContext:
    """Source-independent lifecycle identity used by final window admission."""

    group_id: str
    canonical_start: datetime
    phase: LifecyclePhase
    parent_group_id: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete group metadata before dispatch."""

        if not self.group_id:
            raise ValueError("Action lifecycle group_id cannot be empty")
        if self.parent_group_id == self.group_id:
            raise ValueError("An action lifecycle group cannot parent itself")
