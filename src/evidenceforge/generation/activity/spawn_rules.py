# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Spawn rules for realistic process tree parent selection.

Defines valid parent-child relationships for Windows and Linux processes.
The generator uses these rules to automatically find or create valid
parent processes, building realistic process trees instead of parenting
everything from explorer.exe.
"""

from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_RULES_PATH = get_activity_directory() / "spawn_rules.yaml"
_CACHED_RULES: dict[str, Any] | None = None
_CACHED_REVERSE_WIN: dict[str, list[str]] | None = None
_CACHED_REVERSE_LINUX: dict[str, list[str]] | None = None


def load_spawn_rules() -> dict[str, Any]:
    """Load spawn rules from YAML. Cached after first call."""
    global _CACHED_RULES
    if _CACHED_RULES is not None:
        return _CACHED_RULES

    with open(_RULES_PATH) as f:
        _CACHED_RULES = yaml.safe_load(f)
    return _CACHED_RULES


def build_reverse_index(os_rules: dict[str, Any]) -> dict[str, list[str]]:
    """Build child → list of possible parent exe names.

    Args:
        os_rules: The "windows" or "linux" section of the spawn rules.

    Returns:
        Dict mapping child exe name (lowercase) to list of parent exe names
        that can spawn it.
    """
    reverse: dict[str, list[str]] = {}
    for parent_name, config in os_rules.items():
        children = config.get("children", [])
        for child in children:
            child_lower = child.lower()
            if child_lower not in reverse:
                reverse[child_lower] = []
            reverse[child_lower].append(parent_name.lower())
    return reverse


def get_reverse_index_windows() -> dict[str, list[str]]:
    """Get or build the Windows reverse index. Cached."""
    global _CACHED_REVERSE_WIN
    if _CACHED_REVERSE_WIN is not None:
        return _CACHED_REVERSE_WIN
    rules = load_spawn_rules()
    _CACHED_REVERSE_WIN = build_reverse_index(rules["windows"])
    return _CACHED_REVERSE_WIN


def get_reverse_index_linux() -> dict[str, list[str]]:
    """Get or build the Linux reverse index. Cached."""
    global _CACHED_REVERSE_LINUX
    if _CACHED_REVERSE_LINUX is not None:
        return _CACHED_REVERSE_LINUX
    rules = load_spawn_rules()
    _CACHED_REVERSE_LINUX = build_reverse_index(rules["linux"])
    return _CACHED_REVERSE_LINUX


def get_parent_config(os_type: str, parent_exe: str) -> dict[str, Any]:
    """Get the spawn rule config for a specific parent process.

    Returns dict with command_templates, lifetime, spawn_delay, etc.
    Returns empty dict if parent not in rules.
    """
    rules = load_spawn_rules()
    os_key = "windows" if os_type == "windows" else "linux"
    os_rules = rules.get(os_key, {})
    # Case-insensitive lookup
    for name, config in os_rules.items():
        if name.lower() == parent_exe.lower():
            return config
    return {}
