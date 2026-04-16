# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for EDR object diversity pools.

Loads edr_pools.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/edr_pools.yaml if present.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

_EDR_POOLS_PATH = get_activity_directory() / "edr_pools.yaml"
_CACHED: dict[str, Any] | None = None


def _merge_edr_pools(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely.

    A user who overrides `file_paths_windows:` gets exactly their list,
    not a merge with the defaults. Sections not present in the overlay
    are preserved from the defaults.
    """
    result = dict(default)
    for key, value in overlay.items():
        result[key] = value
    return result


def load_edr_pools() -> dict[str, Any]:
    """Load EDR pool config, merged with overlay. Cached after first call."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    _CACHED = load_with_overlay(
        _EDR_POOLS_PATH,
        "activity/edr_pools.yaml",
        _merge_edr_pools,
    )
    return _CACHED


def get_file_paths(os_category: str) -> list[str]:
    """Return file path pool for the given OS category."""
    pools = load_edr_pools()
    key = "file_paths_windows" if os_category == "windows" else "file_paths_linux"
    return pools.get(key, [])


def get_registry_keys_hkcu() -> list[tuple[str, str]]:
    """Return HKCU registry key pool as (key, Details) tuples."""
    pools = load_edr_pools()
    return [(k, v) for k, v in pools.get("registry_keys_hkcu", [])]


def get_registry_keys_hklm() -> list[tuple[str, str]]:
    """Return HKLM registry key pool as (key, Details) tuples."""
    pools = load_edr_pools()
    return [(k, v) for k, v in pools.get("registry_keys_hklm", [])]


def get_dll_pool() -> list[str]:
    """Return DLL path pool for module load events."""
    pools = load_edr_pools()
    return pools.get("dll_pool", [])
