# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for traffic rate configuration.

Loads traffic_rates.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/traffic_rates.yaml if present.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_RATES_PATH = get_activity_directory() / "traffic_rates.yaml"
_CACHED: dict[str, Any] | None = None

MAX_TRAFFIC_RATE_OVERRIDE = 50_000

VALID_TRAFFIC_TYPES = frozenset(
    {
        "user_activity",
        "web",
        "dns_interval",
        "ntp",
        "smb_interval",
        "kerberos",
        "ldap",
        "persona_connections",
    }
)


def load_traffic_rates() -> dict[str, Any]:
    """Load traffic rate defaults, merged with overlay. Cached after first call."""
    global _CACHED  # noqa: PLW0603
    if _CACHED is not None:
        return _CACHED

    _CACHED = load_with_overlay(
        _RATES_PATH,
        "activity/traffic_rates.yaml",
        deep_merge_dict,
    )
    return _CACHED


def get_rates_for_intensity(intensity: str) -> dict[str, list[int]]:
    """Get the rate table for a given intensity level.

    Args:
        intensity: One of "low", "medium", "high".

    Returns:
        Dict mapping traffic type keys to [lo, hi] ranges.
    """
    data = load_traffic_rates()
    return data[intensity]


def reset_cache() -> None:
    """Clear cached data (for testing)."""
    global _CACHED  # noqa: PLW0603
    _CACHED = None
