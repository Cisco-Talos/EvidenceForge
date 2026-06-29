# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for behavior-shaped beacon profiles."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "beacon_profiles.yaml"
_OVERLAY_SUBPATH = "activity/beacon_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_beacon_profiles(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay beacon profiles into defaults by profile name."""
    return deep_merge_dict(default, overlay)


def load_beacon_profiles() -> dict[str, Any]:
    """Load beacon profiles, merged with any project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            _OVERLAY_SUBPATH,
            _merge_beacon_profiles,
        )
    return _CACHED_DATA


def reset_beacon_profiles_cache() -> None:
    """Clear cached beacon profile data. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def get_profile(name: str) -> dict[str, Any] | None:
    """Return one beacon profile by name, or None when unknown."""
    profile = load_beacon_profiles().get("profiles", {}).get(name)
    return profile if isinstance(profile, dict) else None


def list_profile_names() -> list[str]:
    """List available beacon profile names."""
    profiles = load_beacon_profiles().get("profiles", {})
    return sorted(profiles) if isinstance(profiles, dict) else []
