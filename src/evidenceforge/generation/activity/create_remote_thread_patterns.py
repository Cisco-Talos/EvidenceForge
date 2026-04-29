# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Sysmon Event 8 CreateRemoteThread baseline pattern loader."""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_PATTERNS_PATH = get_activity_directory() / "create_remote_thread_patterns.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_create_remote_thread_patterns(default: dict, overlay: dict) -> dict:
    """Merge CreateRemoteThread pattern overlay with package defaults."""
    result = dict(default)
    if "baseline_pairs" in overlay:
        result["baseline_pairs"] = extend_list(
            default.get("baseline_pairs", []),
            overlay["baseline_pairs"],
        )
    if "start_locations" in overlay:
        start_locations = dict(default.get("start_locations", {}))
        for exe_name, locations in (overlay.get("start_locations") or {}).items():
            start_locations[exe_name] = extend_list(start_locations.get(exe_name, []), locations)
        result["start_locations"] = start_locations
    if "target_overrides" in overlay:
        target_overrides = dict(default.get("target_overrides", {}))
        for exe_name, override in (overlay.get("target_overrides") or {}).items():
            existing = dict(target_overrides.get(exe_name, {}))
            if "start_locations" in override:
                existing["start_locations"] = extend_list(
                    existing.get("start_locations", []),
                    override["start_locations"],
                )
            target_overrides[exe_name] = existing
        result["target_overrides"] = target_overrides
    return result


def load_create_remote_thread_config() -> dict[str, Any]:
    """Load CreateRemoteThread baseline and start-location config with overlays."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _PATTERNS_PATH,
        "activity/create_remote_thread_patterns.yaml",
        _merge_create_remote_thread_patterns,
    )
    return _CACHED_DATA


def load_create_remote_thread_patterns() -> list[dict[str, Any]]:
    """Load benign CreateRemoteThread baseline patterns, merged with overlay if present."""
    return load_create_remote_thread_config().get("baseline_pairs", [])


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


def _pick_weighted_location(
    locations: list[dict[str, Any]],
    rng: random.Random,
) -> dict[str, Any]:
    weighted = [
        (location, int(location.get("weight", 1)))
        for location in locations
        if int(location.get("weight", 1)) > 0
    ]
    if not weighted:
        return {}
    total = sum(weight for _location, weight in weighted)
    choice = rng.randint(1, total)
    running = 0
    for location, weight in weighted:
        running += weight
        if choice <= running:
            return location
    return weighted[-1][0]


def pick_remote_thread_start(
    source_image: str,
    target_image: str,
    rng: random.Random,
) -> tuple[str, str]:
    """Pick a process-aware remote-thread start module/function."""
    config = load_create_remote_thread_config()
    source_exe = source_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    target_exe = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    locations = list(
        (config.get("start_locations") or {}).get(
            source_exe,
            (config.get("start_locations") or {}).get("default", []),
        )
    )
    target_override = (config.get("target_overrides") or {}).get(target_exe, {})
    locations.extend(target_override.get("start_locations") or [])
    picked = _pick_weighted_location(locations, rng)
    return picked.get("module", ""), picked.get("function", "")
