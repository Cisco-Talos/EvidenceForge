# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Timestamp rendering helpers for Windows Event XML formats."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from evidenceforge.utils.rng import _stable_seed


def format_windows_system_time(ts: datetime, event_data: dict[str, Any]) -> str:
    """Render Windows Event XML SystemTime with 100ns-style fractional precision."""
    seed = (
        f"windows_100ns_{event_data.get('Computer', '')}_{event_data.get('EventRecordID', '')}_"
        f"{event_data.get('EventID', '')}_{ts.isoformat()}"
    )
    final_digit = _stable_seed(seed) % 10
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"{final_digit}Z"
