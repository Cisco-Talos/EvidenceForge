# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Sysmon Event 10 ProcessAccess pattern loader."""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_PATTERNS_PATH = get_activity_directory() / "process_access_patterns.yaml"
_CACHED_DATA: list[dict[str, Any]] | None = None


def _merge_process_access_patterns(default: dict, overlay: dict) -> dict:
    """Merge ProcessAccess pattern overlay with package defaults."""
    result = dict(default)
    if "baseline_pairs" in overlay:
        result["baseline_pairs"] = extend_list(
            default.get("baseline_pairs", []),
            overlay["baseline_pairs"],
        )
    return result


def load_process_access_patterns() -> list[dict[str, Any]]:
    """Load baseline ProcessAccess patterns from YAML, merged with overlay if present."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    data = load_with_overlay(
        _PATTERNS_PATH,
        "activity/process_access_patterns.yaml",
        _merge_process_access_patterns,
    )
    _CACHED_DATA = data.get("baseline_pairs", [])
    return _CACHED_DATA


def pick_granted_access(pattern: dict[str, Any], rng: random.Random) -> str:
    """Pick a weighted GrantedAccess mask for a ProcessAccess pattern."""
    masks = pattern.get("access_masks", [])
    weighted_masks = [
        (entry.get("mask"), int(entry.get("weight", 0)))
        for entry in masks
        if isinstance(entry, dict) and entry.get("mask") and int(entry.get("weight", 0)) > 0
    ]
    if not weighted_masks:
        return "0x1010"

    total = sum(weight for _mask, weight in weighted_masks)
    choice = rng.randint(1, total)
    running = 0
    for mask, weight in weighted_masks:
        running += weight
        if choice <= running:
            return str(mask)
    return str(weighted_masks[-1][0])
