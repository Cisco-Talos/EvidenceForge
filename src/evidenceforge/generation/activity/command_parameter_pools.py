# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Config-backed command parameter pools for surfaced URL and host placeholders."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "command_parameter_pools.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_command_parameter_pools(
    default: dict[str, Any],
    overlay: dict[str, Any],
) -> dict[str, Any]:
    """Merge command parameter overlay pools with package defaults."""
    return deep_merge_dict(default, overlay)


def load_command_parameter_pools() -> dict[str, Any]:
    """Load command parameter pools, merged with local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/command_parameter_pools.yaml",
        _merge_command_parameter_pools,
    )
    return _CACHED_DATA


def reset_command_parameter_pools_cache() -> None:
    """Clear cached command parameter pools. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def command_parameter_pools() -> dict[str, dict[str, list[str]]]:
    """Return sanitized command parameter pools keyed by section name."""
    data = load_command_parameter_pools()
    result: dict[str, dict[str, list[str]]] = {}
    for section in ("general", "query", "linux_query"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            result[section] = {}
            continue
        result[section] = {
            str(key): [str(value) for value in values if str(value)]
            for key, values in section_data.items()
            if isinstance(values, list)
        }
    return result
