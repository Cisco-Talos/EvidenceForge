# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Observation profile config loader."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.compatibility import warn_legacy_config
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.schemas import ObservationProfilesConfig

_CONFIG_PATH = get_activity_directory() / "observation_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _normalize_observation_overlay(data: dict[str, Any]) -> dict[str, Any]:
    """Version one legacy partial overlay before merging it with package defaults."""

    if "schema_version" in data:
        return deepcopy(data)
    normalized = deepcopy(data)
    profiles = normalized.get("profiles")
    if isinstance(profiles, dict):
        for profile_name in profiles:
            warn_legacy_config(
                f"observation_profiles.profiles[{profile_name}] unversioned named profile",
                "observation_profiles schema_version: 2 with the same named profile fields",
                stacklevel=4,
            )
        normalized["schema_version"] = 2
    return normalized


def _merge_observation_profiles(
    default: dict[str, Any],
    overlay: dict[str, Any],
) -> dict[str, Any]:
    """Normalize one partial observation overlay before its deep merge."""

    return deep_merge_dict(default, _normalize_observation_overlay(overlay))


def load_observation_profiles() -> dict[str, Any]:
    """Load source-observation profiles, merged with project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        merged = load_with_overlay(
            _CONFIG_PATH,
            "activity/observation_profiles.yaml",
            _merge_observation_profiles,
        )
        _CACHED_DATA = ObservationProfilesConfig.model_validate(merged).model_dump(
            mode="python",
            exclude_unset=True,
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
    return {name for name, profile in profiles.items() if isinstance(profile, dict)}


def observation_profile_exists(name: str) -> bool:
    """Return True when a named observation profile is configured as a mapping."""
    profiles = load_observation_profiles().get("profiles", {})
    if not isinstance(profiles, dict):
        return False
    return isinstance(profiles.get(name), dict)


def get_observation_profile(name: str) -> dict[str, Any]:
    """Return a named observation profile config."""
    profiles = load_observation_profiles().get("profiles", {})
    if not isinstance(profiles, dict):
        return {}
    profile = profiles.get(name, {})
    return profile if isinstance(profile, dict) else {}
