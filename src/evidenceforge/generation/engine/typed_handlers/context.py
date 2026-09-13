# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared execution context for typed storyline handlers."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.models.scenario import System, User


@dataclass(frozen=True)
class TypedEventContext:
    """Existing per-event state, shared without new RNG or lifecycle ownership."""

    actor: User
    system: System
    time: datetime
    activity: str
    explicit_types: set[str]
    future_specs: tuple[Any, ...]
    authored_time_shift: timedelta
    session_required_until: datetime | None
    rng: random.Random
    dispatcher: EventDispatcher | None
    malicious_event: dict[str, Any]
    _ground_truth_uid: Callable[[str, str, str], str]
