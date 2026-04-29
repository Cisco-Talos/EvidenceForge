# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Windows authentication realism configuration loader."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "windows_auth_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_windows_auth_realism() -> dict[str, Any]:
    """Load Windows authentication realism config, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/windows_auth_realism.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_windows_auth_realism_cache() -> None:
    """Clear cached Windows auth realism config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def workstation_lock_config() -> dict[str, Any]:
    """Return workstation lock/unlock realism settings."""
    config = load_windows_auth_realism().get("workstation_lock", {})
    return config if isinstance(config, dict) else {}


def min_unlock_gap_seconds() -> int:
    """Return the minimum realistic gap between a 4800 lock and 4801 unlock."""
    value = workstation_lock_config().get("min_unlock_gap_seconds", 127)
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return 127
    return max(1, seconds)


def failed_logon_config() -> dict[str, Any]:
    """Return failed-logon source-native field profiles."""
    config = load_windows_auth_realism().get("failed_logon", {})
    return config if isinstance(config, dict) else {}


def special_privileges_config() -> dict[str, Any]:
    """Return Windows 4672 privilege profile config."""
    config = load_windows_auth_realism().get("special_privileges", {})
    return config if isinstance(config, dict) else {}
