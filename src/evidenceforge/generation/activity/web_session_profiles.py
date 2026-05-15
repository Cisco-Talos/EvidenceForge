# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Inbound web server visitor profile loader and selection helpers."""

from __future__ import annotations

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "web_session_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_web_session_profiles() -> dict[str, Any]:
    """Load inbound web visitor profiles from YAML, merged with overlay. Cached."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/web_session_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_web_session_profiles_cache() -> None:
    """Clear cached web visitor profile data. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _positive_weight(value: Any, fallback: float = 1.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


def _visitor_candidates(
    data: dict[str, Any], *, is_external: bool
) -> list[tuple[str, dict[str, Any]]]:
    classes = data.get("visitor_classes", {})
    if not isinstance(classes, dict):
        return []
    allowed_key = "external" if is_external else "internal"
    candidates: list[tuple[str, dict[str, Any]]] = []
    for name, profile in classes.items():
        if not isinstance(profile, dict):
            continue
        if profile.get(allowed_key, True) is False:
            continue
        candidates.append((str(name), profile))
    return candidates


def pick_web_visitor_profile(
    rng: random.Random, *, is_external: bool
) -> tuple[str, dict[str, Any]]:
    """Pick a visitor profile appropriate for an internal or external client."""
    data = load_web_session_profiles()
    candidates = _visitor_candidates(data, is_external=is_external)
    if not candidates:
        return (
            "human_browser",
            {
                "kind": "session",
                "browsing_intensity": "normal",
                "user_agent_pool": "browser_any",
            },
        )
    weights = [_positive_weight(profile.get("weight")) for _, profile in candidates]
    return rng.choices(candidates, weights=weights, k=1)[0]


def pick_web_user_agent(
    rng: random.Random,
    profile: dict[str, Any],
    *,
    source_os: str | None = None,
) -> str:
    """Pick a User-Agent from the profile's configured pool."""
    data = load_web_session_profiles()
    pools = data.get("user_agent_pools", {})
    if not isinstance(pools, dict):
        pools = {}

    pool_name = None
    by_os = profile.get("user_agent_pool_by_os")
    if isinstance(by_os, dict) and source_os:
        pool_name = by_os.get(source_os)
    if not isinstance(pool_name, str):
        pool_name = profile.get("user_agent_pool")
    pool = pools.get(pool_name) if isinstance(pool_name, str) else None
    if not isinstance(pool, list) or not pool:
        pool = pools.get("browser_any", [])
    if not isinstance(pool, list) or not pool:
        return "Mozilla/5.0"
    return str(rng.choice(pool))


def pick_profile_request(rng: random.Random, profile: dict[str, Any]) -> dict[str, Any]:
    """Pick a configured request entry from a non-session visitor profile."""
    requests = profile.get("requests", [])
    if not isinstance(requests, list) or not requests:
        return {"path": "/", "method": "GET", "status": 200, "type": "text/html"}
    choices = [entry for entry in requests if isinstance(entry, dict)]
    if not choices:
        return {"path": "/", "method": "GET", "status": 200, "type": "text/html"}
    weights = [_positive_weight(entry.get("weight")) for entry in choices]
    return dict(rng.choices(choices, weights=weights, k=1)[0])


def request_count_bounds(profile: dict[str, Any]) -> tuple[int, int]:
    """Return safe per-visitor request count bounds for non-session profiles."""
    raw_bounds = profile.get("request_count", [1, 1])
    if not isinstance(raw_bounds, (list, tuple)) or len(raw_bounds) != 2:
        return 1, 1
    try:
        lo = int(raw_bounds[0])
        hi = int(raw_bounds[1])
    except (TypeError, ValueError):
        return 1, 1
    lo = max(1, min(lo, 50))
    hi = max(1, min(hi, 50))
    if hi < lo:
        return 1, 1
    return lo, hi
