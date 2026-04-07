# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Child/utility process definitions for multi-level process tree generation.

Loads app_child_processes.yaml and provides lookup of child processes
that should be spawned by main applications (browser renderers, GPU
processes, utility subprocesses, etc.).

Follows the same cached-loader pattern as dns_registry.py, spawn_rules.py, etc.
"""

from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_CHILD_PATH = get_activity_directory() / "app_child_processes.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_app_child_processes() -> dict[str, Any]:
    """Load child process definitions from YAML. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    with open(_CHILD_PATH) as f:
        _CACHED_DATA = yaml.safe_load(f)
    return _CACHED_DATA


def get_child_processes(os_type: str, parent_exe: str) -> list[dict[str, str]]:
    """Get child process definitions for a given parent executable.

    Args:
        os_type: "windows" or "linux"
        parent_exe: Parent executable basename (e.g., "chrome.exe")

    Returns:
        List of dicts with "image" and "command_line" keys, or empty list.
    """
    data = load_app_child_processes()
    os_data = data.get(os_type, {})
    return os_data.get(parent_exe.lower(), [])
