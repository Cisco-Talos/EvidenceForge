# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Timing realism profile loader and helpers."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "timing_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_MAX_RELATIONSHIP_MS = 86_400_000
_MAX_COLLISION_NEAR_ZERO_UNTIL = 10_000
_MAX_COLLISION_GAP_US = 1_000_000
_MAX_COLLISION_GAP_MS = 60_000


@dataclass(frozen=True, slots=True)
class TimingWindow:
    """A sampled timing window for a named causal relationship."""

    min_ms: int
    max_ms: int
    position: Literal["before", "after"]
    relationship_class: str = ""


def load_timing_profiles() -> dict[str, Any]:
    """Load timing profiles, merged with project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/timing_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_timing_profiles_cache() -> None:
    """Clear cached timing profiles. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _safe_int(value: Any, fallback: int, *, minimum: int, maximum: int) -> int:
    """Convert input to int and clamp to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def get_timing_window(
    key: str,
    *,
    default_min_ms: int,
    default_max_ms: int,
    default_position: Literal["before", "after"],
    default_class: str = "",
) -> TimingWindow:
    """Return a named timing relationship with safe code defaults."""
    entry = load_timing_profiles().get("relationships", {}).get(key, {})
    if not isinstance(entry, dict):
        entry = {}
    min_ms = _safe_int(
        entry.get("min_ms", default_min_ms),
        default_min_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    max_ms = _safe_int(
        entry.get("max_ms", default_max_ms),
        default_max_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    if max_ms < min_ms:
        min_ms, max_ms = default_min_ms, default_max_ms
    position = entry.get("position", default_position)
    if position not in {"before", "after"}:
        position = default_position
    return TimingWindow(
        min_ms=min_ms,
        max_ms=max_ms,
        position=position,
        relationship_class=str(entry.get("class", default_class)),
    )


def sample_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a deterministic timedelta for a named timing relationship."""
    window = get_timing_window(
        key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    if window.max_ms <= window.min_ms:
        return timedelta(milliseconds=window.min_ms)
    seed = "timing_delta:" + key + ":" + ":".join(str(part) for part in seed_parts)
    rng = random.Random(_stable_seed(seed))
    return timedelta(milliseconds=rng.randint(window.min_ms, window.max_ms))


def sample_packet_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a deterministic packet-observation delta with sub-millisecond jitter."""
    base_delta = sample_timing_delta(key, seed_parts=seed_parts)
    seed = "packet_timing_delta:" + key + ":" + ":".join(str(part) for part in seed_parts)
    rng = random.Random(_stable_seed(seed))
    return base_delta + timedelta(microseconds=rng.randint(37, 997))


def windows_collision_spacing_config() -> dict[str, int]:
    """Return Windows/Sysmon same-timestamp collision spacing settings."""
    spacing = load_timing_profiles().get("windows_event_time", {}).get("collision_spacing", {})
    if not isinstance(spacing, dict):
        spacing = {}
    config = {
        "near_zero_until": _safe_int(
            spacing.get("near_zero_until", 25),
            25,
            minimum=0,
            maximum=_MAX_COLLISION_NEAR_ZERO_UNTIL,
        ),
        "near_gap_min_us": _safe_int(
            spacing.get("near_gap_min_us", 50),
            50,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "near_gap_max_us": _safe_int(
            spacing.get("near_gap_max_us", 500),
            500,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "large_gap_min_ms": _safe_int(
            spacing.get("large_gap_min_ms", 1000),
            1000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
        "large_gap_max_ms": _safe_int(
            spacing.get("large_gap_max_ms", 4000),
            4000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
    }
    if config["near_gap_max_us"] < config["near_gap_min_us"]:
        config["near_gap_min_us"], config["near_gap_max_us"] = 50, 500
    if config["large_gap_max_ms"] < config["large_gap_min_ms"]:
        config["large_gap_min_ms"], config["large_gap_max_ms"] = 1000, 4000
    return config
