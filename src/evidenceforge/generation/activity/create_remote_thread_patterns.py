# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Sysmon Event 8 CreateRemoteThread baseline pattern loader."""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_PATTERNS_PATH = get_activity_directory() / "create_remote_thread_patterns.yaml"
_CACHED_DATA: list[dict[str, Any]] | None = None


def _merge_create_remote_thread_patterns(default: dict, overlay: dict) -> dict:
    """Merge CreateRemoteThread pattern overlay with package defaults."""
    result = dict(default)
    if "baseline_pairs" in overlay:
        result["baseline_pairs"] = extend_list(
            default.get("baseline_pairs", []),
            overlay["baseline_pairs"],
        )
    return result


def load_create_remote_thread_patterns() -> list[dict[str, Any]]:
    """Load benign CreateRemoteThread baseline patterns, merged with overlay if present."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    data = load_with_overlay(
        _PATTERNS_PATH,
        "activity/create_remote_thread_patterns.yaml",
        _merge_create_remote_thread_patterns,
    )
    _CACHED_DATA = data.get("baseline_pairs", [])
    return _CACHED_DATA


def pick_create_remote_thread_pattern(
    patterns: list[dict[str, Any]],
    rng: random.Random,
) -> dict[str, Any]:
    """Pick a weighted CreateRemoteThread pattern."""
    weighted = [
        (pattern, int(pattern.get("weight", 1)))
        for pattern in patterns
        if int(pattern.get("weight", 1)) > 0
    ]
    if not weighted:
        return {}
    total = sum(weight for _pattern, weight in weighted)
    choice = rng.randint(1, total)
    running = 0
    for pattern, weight in weighted:
        running += weight
        if choice <= running:
            return pattern
    return weighted[-1][0]
