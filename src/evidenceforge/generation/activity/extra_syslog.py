# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Extra syslog message loader with role/distro filtering.

Loads extra_syslog_messages.yaml and provides filtered message pools
for baseline syslog diversity generation.

Follows the same cached-loader pattern as dns_registry.py, spawn_rules.py, etc.
"""

from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_MESSAGES_PATH = get_activity_directory() / "extra_syslog_messages.yaml"
_CACHED_DATA: list[dict[str, Any]] | None = None


def load_extra_syslog_messages() -> list[dict[str, Any]]:
    """Load extra syslog message definitions from YAML. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    with open(_MESSAGES_PATH) as f:
        data = yaml.safe_load(f)
    _CACHED_DATA = data.get("programs", [])
    return _CACHED_DATA


def filter_syslog_messages(
    programs: list[dict[str, Any]],
    is_rhel_like: bool,
    host_roles: list[str] | None,
) -> list[tuple[str, list[str]]]:
    """Filter syslog programs by distro and host roles.

    Args:
        programs: Raw program entries from YAML.
        is_rhel_like: True for CentOS/RHEL/Rocky/Alma hosts.
        host_roles: List of roles assigned to the host, or None.

    Returns:
        List of (app_name, messages) tuples matching the host context.
    """
    result = []
    for entry in programs:
        # Distro filter
        distro = entry.get("distro")
        if distro == "ubuntu" and is_rhel_like:
            continue

        # Role filter — if roles specified, host must have at least one
        required_roles = entry.get("roles")
        if required_roles:
            if not host_roles or not any(r in host_roles for r in required_roles):
                continue

        result.append((entry["app"], entry["messages"]))
    return result
