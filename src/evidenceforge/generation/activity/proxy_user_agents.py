# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Proxy User-Agent selection backed by activity YAML config."""

import random
from typing import TYPE_CHECKING, Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.activity.helpers import _get_os_category

if TYPE_CHECKING:
    from evidenceforge.models.scenario import System

_CONFIG_PATH = get_activity_directory() / "proxy_user_agents.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_proxy_user_agents(default: dict, overlay: dict) -> dict:
    """Merge proxy User-Agent overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_proxy_user_agents() -> dict[str, Any]:
    """Load proxy User-Agent pools from YAML, merged with overlay. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/proxy_user_agents.yaml",
        _merge_proxy_user_agents,
    )
    return _CACHED_DATA


def reset_proxy_user_agents_cache() -> None:
    """Clear cached proxy User-Agent config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _pool(data: dict[str, Any], *path: str) -> list[str]:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return []
        value = value.get(key, {})
    return value if isinstance(value, list) else []


def _is_server_source(source_system: "System", data: dict[str, Any]) -> bool:
    roles = set(source_system.roles or [])
    server_roles = set(_pool(data, "server", "roles"))
    return source_system.type == "server" or bool(roles & server_roles)


def _pick_package_manager_agent(
    rng: random.Random,
    source_system: "System",
    hostname: str | None,
    data: dict[str, Any],
) -> str | None:
    host = (hostname or "").lower()
    if not host:
        return None

    os_name = source_system.os.lower()
    role_keys = (
        ("server", "workstation")
        if _is_server_source(source_system, data)
        else (
            "workstation",
            "server",
        )
    )
    managers_by_scope: list[dict[str, Any]] = []
    for role_key in role_keys:
        role_managers = data.get(role_key, {}).get("package_managers", {})
        if isinstance(role_managers, dict):
            managers_by_scope.append(role_managers)
    if not managers_by_scope:
        return None

    for managers in managers_by_scope:
        for manager in managers.values():
            if not isinstance(manager, dict):
                continue
            os_keywords = manager.get("os_keywords", [])
            hosts = manager.get("hosts", [])
            user_agents = manager.get("user_agents", [])
            if not isinstance(os_keywords, list) or not isinstance(hosts, list):
                continue
            if not isinstance(user_agents, list) or not user_agents:
                continue
            if any(str(keyword).lower() in os_name for keyword in os_keywords) and host in {
                str(package_host).lower() for package_host in hosts
            }:
                return rng.choice(user_agents)
    return None


def _pick_domain_override_agent(
    rng: random.Random,
    source_system: "System",
    hostname: str | None,
    data: dict[str, Any],
) -> str | None:
    """Pick a domain-specific agent for update, telemetry, and cert infrastructure."""
    host = (hostname or "").lower()
    if not host:
        return None

    overrides = data.get("domain_overrides", {})
    if not isinstance(overrides, dict):
        return None

    os_name = source_system.os.lower()
    for override in overrides.values():
        if not isinstance(override, dict):
            continue
        os_keywords = override.get("os_keywords", [])
        hosts = override.get("hosts", [])
        user_agents = override.get("user_agents", [])
        if not isinstance(os_keywords, list) or not isinstance(hosts, list):
            continue
        if not isinstance(user_agents, list) or not user_agents:
            continue
        host_matches = any(
            host == str(candidate).lower() or host.endswith(f".{str(candidate).lower()}")
            for candidate in hosts
        )
        if host_matches and any(str(keyword).lower() in os_name for keyword in os_keywords):
            return rng.choice(user_agents)
    return None


def pick_proxy_domain_user_agent(
    rng: random.Random,
    source_system: "System | None",
    *,
    hostname: str | None = None,
) -> str | None:
    """Pick a domain-specific proxy User-Agent override, if one applies."""
    if source_system is None:
        return None
    data = load_proxy_user_agents()
    return _pick_domain_override_agent(rng, source_system, hostname, data)


def pick_proxy_user_agent(
    rng: random.Random,
    source_system: "System | None",
    *,
    hostname: str | None = None,
    domain_tags: list[str] | None = None,
) -> str:
    """Pick a proxy User-Agent appropriate for source host role and destination."""
    _ = domain_tags  # Reserved for future tag-driven UA profiles in the YAML schema.
    data = load_proxy_user_agents()

    if source_system is None:
        windows_pool = _pool(data, "workstation", "windows")
        return rng.choice(windows_pool)

    domain_agent = _pick_domain_override_agent(rng, source_system, hostname, data)
    if domain_agent:
        return domain_agent

    package_agent = _pick_package_manager_agent(rng, source_system, hostname, data)
    if package_agent:
        return package_agent

    if _is_server_source(source_system, data):
        server_pool = _pool(data, "server", "generic")
        return rng.choice(server_pool)

    if _get_os_category(source_system.os) == "linux":
        linux_pool = _pool(data, "workstation", "linux")
        return rng.choice(linux_pool)

    windows_pool = _pool(data, "workstation", "windows")
    return rng.choice(windows_pool)
