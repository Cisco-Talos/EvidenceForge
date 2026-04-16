# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for Sysmon event filtering configuration.

Loads sysmon_filters.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/sysmon_filters.yaml if present.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

_FILTERS_PATH = get_activity_directory() / "sysmon_filters.yaml"
_CACHED: dict[str, Any] | None = None


def _merge_sysmon_filters(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely.

    Unlike deep_merge_dict, this replaces each top-level section wholesale
    when present in the overlay. A user who overrides `network_connect:`
    gets exactly their config, not a merge with the defaults. Sections
    not present in the overlay are preserved from the defaults.
    """
    result = dict(default)
    for key, value in overlay.items():
        result[key] = value
    return result


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
