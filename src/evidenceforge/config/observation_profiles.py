# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Observation profile config loader."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "observation_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_observation_profiles() -> dict[str, Any]:
    """Load source-observation profiles, merged with project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/observation_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_observation_profiles_cache() -> None:
    """Clear cached observation profile config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def observation_profile_names() -> set[str]:
    """Return configured observation profile names."""
    profiles = load_observation_profiles().get("profiles", {})
    if not isinstance(profiles, dict):
        return set()
    return set(profiles)


def get_observation_profile(name: str) -> dict[str, Any]:
    """Return a named observation profile config."""
    profiles = load_observation_profiles().get("profiles", {})
    if not isinstance(profiles, dict):
        return {}
    profile = profiles.get(name, {})
    return profile if isinstance(profile, dict) else {}
