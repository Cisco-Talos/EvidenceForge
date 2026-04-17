# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for CallTrace pattern configuration.

Loads calltrace_patterns.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/calltrace_patterns.yaml if present.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

_CALLTRACE_PATH = get_activity_directory() / "calltrace_patterns.yaml"
_CACHED: list[dict[str, Any]] | None = None


def _merge_calltrace(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely."""
    result = dict(default)
    for key, value in overlay.items():
        result[key] = value
    return result


def load_calltrace_patterns() -> list[dict[str, Any]]:
    """Load CallTrace pattern config, merged with overlay. Cached after first call."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    data = load_with_overlay(
        _CALLTRACE_PATH,
        "activity/calltrace_patterns.yaml",
        _merge_calltrace,
    )
    _CACHED = data.get("patterns", [])
    return _CACHED
