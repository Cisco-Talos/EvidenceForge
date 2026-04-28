# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for EDR object diversity pools.

Loads edr_pools.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/edr_pools.yaml if present.
"""

from __future__ import annotations

import logging
import random
import re
from typing import Any

import yaml

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

_EDR_POOLS_PATH = get_activity_directory() / "edr_pools.yaml"
_CACHED: dict[str, Any] | None = None
logger = logging.getLogger(__name__)


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

    with open(_EDR_POOLS_PATH) as f:
        defaults = yaml.safe_load(f)

    merged = load_with_overlay(
        _EDR_POOLS_PATH,
        "activity/edr_pools.yaml",
        _merge_edr_pools,
    )
    _CACHED = _sanitize_edr_pools(defaults, merged)
    return _CACHED


def _is_valid_string_list(value: Any) -> bool:
    return (
        isinstance(value, list) and len(value) > 0 and all(isinstance(item, str) for item in value)
    )


def _is_valid_registry_pool(value: Any) -> bool:
    if not isinstance(value, list) or len(value) == 0:
        return False
    for item in value:
        if not isinstance(item, list | tuple) or len(item) != 3:
            return False
        if not all(isinstance(field, str) and field for field in item):
            return False
    return True


def _sanitize_edr_pools(defaults: dict[str, Any], merged: dict[str, Any]) -> dict[str, Any]:
    """Validate merged EDR pools and fall back to defaults for malformed sections."""
    validators: dict[str, Any] = {
        "file_paths_windows": _is_valid_string_list,
        "file_paths_linux": _is_valid_string_list,
        "dll_pool": _is_valid_string_list,
        "registry_keys_hkcu": _is_valid_registry_pool,
        "registry_keys_hklm": _is_valid_registry_pool,
    }
    sanitized = dict(defaults)
    for key, validator in validators.items():
        candidate = merged.get(key)
        if validator(candidate):
            sanitized[key] = candidate
        else:
            logger.warning(
                "Invalid EDR pool section %s in overlay-merged config; falling back to package defaults",
                key,
            )
    return sanitized


def get_file_paths(os_category: str) -> list[str]:
    """Return file path pool for the given OS category."""
    pools = load_edr_pools()
    key = "file_paths_windows" if os_category == "windows" else "file_paths_linux"
    return pools.get(key, [])


def get_registry_keys_hkcu() -> list[tuple[str, str, str]]:
    """Return HKCU registry key pool as (key, value_name, details) tuples."""
    pools = load_edr_pools()
    return [(k, vn, d) for k, vn, d in pools.get("registry_keys_hkcu", [])]


def get_registry_keys_hklm() -> list[tuple[str, str, str]]:
    """Return HKLM registry key pool as (key, value_name, details) tuples."""
    pools = load_edr_pools()
    return [(k, vn, d) for k, vn, d in pools.get("registry_keys_hklm", [])]


def get_dll_pool() -> list[str]:
    """Return DLL path pool for module load events."""
    pools = load_edr_pools()
    return pools.get("dll_pool", [])


def materialize_edr_template(template: str, rng: random.Random, user: str = "SYSTEM") -> str:
    """Materialize common EDR pool template placeholders deterministically from an RNG."""
    replacements = {
        "user": user,
        "rand": f"{rng.randint(10000, 99999)}",
        "hex": f"{rng.getrandbits(32):08X}",
        "guid": (
            f"{rng.getrandbits(32):08X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(48):012X}"
        ),
        "mru": str(rng.randint(0, 24)),
        "doc": str(rng.randint(1, 80)),
        "package": rng.choice(
            [
                "Package_for_RollupFix",
                "Package_for_ServicingStack",
                "Package_for_KB5034122",
                "Package_for_DotNetRollup",
                "Microsoft-Windows-Client-Features",
            ]
        ),
        "version": rng.choice(["1.0", "2.1", "4.8", "16.0", "24.2", "125.0", "2024.3"]),
    }

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        return str(replacements[token]) if token in replacements else match.group(0)

    materialized = re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, template)
    return materialized.replace("{{", "{").replace("}}", "}")
