# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed lifecycle metadata for correlated action groups."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

LifecyclePhase = Literal["start", "dependent", "closure"]


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
