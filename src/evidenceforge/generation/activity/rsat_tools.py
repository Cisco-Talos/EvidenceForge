# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for RSAT tool configuration.

Loads rsat_tools.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/rsat_tools.yaml if present.
"""

from __future__ import annotations

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_RSAT_PATH = get_activity_directory() / "rsat_tools.yaml"
_CACHED: list[dict[str, Any]] | None = None


def _merge_rsat(default: dict, overlay: dict) -> dict:
    result = dict(default)
    if "tools" in overlay:
        result["tools"] = merge_keyed_list(
            default.get("tools", []),
            overlay["tools"],
            key="id",
        )
    return result


def load_rsat_tools() -> list[dict[str, Any]]:
    """Load RSAT tool definitions, merged with overlay. Cached after first call."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    data = load_with_overlay(
        _RSAT_PATH,
        "activity/rsat_tools.yaml",
        _merge_rsat,
    )
    _CACHED = data.get("tools", [])
    return _CACHED


def pick_rsat_tool(rng: random.Random) -> dict[str, Any]:
    """Pick a random RSAT tool weighted by the ``weight`` field."""
    tools = load_rsat_tools()
    weights = [t.get("weight", 1) for t in tools]
    return rng.choices(tools, weights=weights, k=1)[0]
