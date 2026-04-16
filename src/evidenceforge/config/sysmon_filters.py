# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for Sysmon event filtering configuration.

Loads sysmon_filters.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/sysmon_filters.yaml if present.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_FILTERS_PATH = get_activity_directory() / "sysmon_filters.yaml"
_CACHED: dict[str, Any] | None = None


def _merge_sysmon_filters(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely."""
    return deep_merge_dict(default, overlay)


def load_sysmon_filters() -> dict[str, Any]:
    """Load Sysmon filter config, merged with overlay. Cached after first call."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    _CACHED = load_with_overlay(
        _FILTERS_PATH,
        "activity/sysmon_filters.yaml",
        _merge_sysmon_filters,
    )
    return _CACHED
