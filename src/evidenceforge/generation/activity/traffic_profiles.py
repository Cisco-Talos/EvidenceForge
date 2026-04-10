# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Role/persona-aware traffic profile loader.

Loads traffic_profiles.yaml and provides filtered connection profiles
for role-based system traffic and persona-based user traffic.

Traffic profiles define both outbound (host-initiated) and inbound
(connections received from other roles/external) patterns. The `role`
field names the other end of the connection in both directions.

Follows the same cached-loader pattern as dns_registry.py, spawn_rules.py, etc.
"""

from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_PROFILES_PATH = get_activity_directory() / "traffic_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_traffic_profiles() -> dict[str, Any]:
    """Load traffic profiles from YAML. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    with open(_PROFILES_PATH) as f:
        _CACHED_DATA = yaml.safe_load(f)
    return _CACHED_DATA


def get_role_connections(roles: list[str], os_category: str) -> list[dict[str, Any]]:
    """Get merged outbound connection entries for one or more host roles.

    Looks up each role in order and merges all matching profiles. Falls back
    to "_default" if no role matches.

    Args:
        roles: List of role names (e.g., ["web_server"] or ["domain_controller"]).
        os_category: Source host OS ("windows" or "linux").

    Returns:
        List of connection dicts with role, port, service, weight, etc.
    """
    data = load_traffic_profiles()
    role_data = data.get("role_traffic", {})
    connections: list[dict[str, Any]] = []
    matched = False
    for role in roles:
        profile = role_data.get(role)
        if profile:
            matched = True
            connections.extend(profile.get("outbound", []))
    if not matched:
        default = role_data.get("_default", {})
        connections = default.get("outbound", [])
    return [c for c in connections if _os_matches(c, os_category)]


def get_role_inbound_connections(roles: list[str], os_category: str) -> list[dict[str, Any]]:
    """Get merged inbound connection entries for one or more host roles.

    Inbound entries describe connections the host receives from other roles
    or external sources. The `role` field names the source of the connection.

    Args:
        roles: List of role names (e.g., ["web_server", "server"]).
        os_category: Host OS ("windows" or "linux").

    Returns:
        List of connection dicts with role, port, service, weight, etc.
    """
    data = load_traffic_profiles()
    role_data = data.get("role_traffic", {})
    connections: list[dict[str, Any]] = []
    for role in roles:
        profile = role_data.get(role)
        if profile:
            connections.extend(profile.get("inbound", []))
    return [c for c in connections if _os_matches(c, os_category)]


def get_persona_connections(persona: str, os_category: str) -> list[dict[str, Any]]:
    """Get outbound connection entries for a user persona, filtered by OS.

    Args:
        persona: User persona name (e.g., "developer", "executive").
                 Falls back to "_default" if persona not found.
        os_category: Host OS where the user has an active session.

    Returns:
        List of connection dicts with role, port, service, weight, etc.
    """
    data = load_traffic_profiles()
    persona_data = data.get("persona_traffic", {})
    profile = persona_data.get(persona) or persona_data.get("_default", {})
    connections = profile.get("outbound", [])
    return [c for c in connections if _os_matches(c, os_category)]


def _os_matches(entry: dict[str, Any], os_category: str) -> bool:
    """Check if a connection entry is compatible with the given OS."""
    entry_os = entry.get("os")
    if entry_os is None:
        return True
    return entry_os == os_category
