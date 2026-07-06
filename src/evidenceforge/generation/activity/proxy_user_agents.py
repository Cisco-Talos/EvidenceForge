# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Proxy User-Agent selection backed by activity YAML config."""

import random
from typing import TYPE_CHECKING, Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.utils.rng import _stable_seed

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


def _package_manager_keys_matching_os(data: dict[str, Any], os_name: str) -> set[str]:
    """Return package-manager config keys compatible with the source OS."""
    compatible: set[str] = set()
    os_lower = os_name.lower()
    for role_key in ("workstation", "server"):
        managers = data.get(role_key, {}).get("package_managers", {})
        if not isinstance(managers, dict):
            continue
        for manager_key, manager in managers.items():
            if not isinstance(manager, dict):
                continue
            keywords = manager.get("os_keywords", [])
            if not isinstance(keywords, list):
                continue
            if any(str(keyword).lower() in os_lower for keyword in keywords):
                compatible.add(str(manager_key))
    return compatible


def _package_manager_key_for_user_agent(data: dict[str, Any], user_agent: str) -> str | None:
    """Return the package-manager config key that owns a User-Agent string."""
    normalized = " ".join(user_agent.strip().lower().split())
    if not normalized:
        return None
    for role_key in ("workstation", "server"):
        managers = data.get(role_key, {}).get("package_managers", {})
        if not isinstance(managers, dict):
            continue
        for manager_key, manager in managers.items():
            if not isinstance(manager, dict):
                continue
            agents = manager.get("user_agents", [])
            if not isinstance(agents, list):
                continue
            if normalized in {" ".join(str(agent).strip().lower().split()) for agent in agents}:
                return str(manager_key)
    return None


def _generic_agent_pool_for_source(source_system: "System", data: dict[str, Any]) -> list[str]:
    """Return a generic fallback UA pool for the source host."""
    if _is_server_source(source_system, data):
        server_pool = _pool(data, "server", "generic")
        if server_pool:
            return server_pool
    if _get_os_category(source_system.os) == "linux":
        return _pool(data, "workstation", "linux")
    return _pool(data, "workstation", "windows")


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
    for override_name, override in overrides.items():
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
            if str(override.get("stickiness", "request")).lower() == "source_host":
                source_key = ":".join(
                    str(part)
                    for part in (
                        getattr(source_system, "hostname", ""),
                        getattr(source_system, "ip", ""),
                        getattr(source_system, "os", ""),
                    )
                )
                stable_rng = random.Random(
                    _stable_seed(f"proxy_domain_ua:{override_name}:{source_key}:{host}")
                )
                return stable_rng.choice(user_agents)
            return rng.choice(user_agents)
    return None


def _ua_looks_windows(user_agent: str) -> bool:
    ua = user_agent.lower()
    return any(token in ua for token in ("windows nt", "win64", "wow64", "trident/", "edg/"))


def _ua_looks_linux(user_agent: str) -> bool:
    ua = user_agent.lower()
    return "x11; linux" in ua or "ubuntu;" in ua or "linux x86_64" in ua


def normalize_proxy_user_agent_for_os(
    rng: random.Random,
    source_system: "System | None",
    user_agent: str,
    *,
    hostname: str | None = None,
    domain_tags: list[str] | None = None,
) -> str:
    """Replace User-Agents that contradict the source host OS or distro family."""
    if source_system is None or not user_agent:
        return user_agent
    data = load_proxy_user_agents()
    package_key = _package_manager_key_for_user_agent(data, user_agent)
    if package_key is not None:
        compatible_package_keys = _package_manager_keys_matching_os(data, source_system.os)
        if compatible_package_keys and package_key not in compatible_package_keys:
            replacement = _pick_package_manager_agent(rng, source_system, hostname, data)
            if replacement:
                return replacement
            generic_pool = _generic_agent_pool_for_source(source_system, data)
            return rng.choice(generic_pool) if generic_pool else user_agent

    os_category = _get_os_category(source_system.os)
    if os_category == "linux" and _ua_looks_windows(user_agent):
        linux_pool = _pool(data, "workstation", "linux")
        return (
            rng.choice(linux_pool)
            if linux_pool
            else pick_proxy_user_agent(
                rng,
                source_system,
                hostname=hostname,
                domain_tags=domain_tags,
            )
        )
    if os_category == "windows" and _ua_looks_linux(user_agent):
        windows_pool = _pool(data, "workstation", "windows")
        return (
            rng.choice(windows_pool)
            if windows_pool
            else pick_proxy_user_agent(
                rng,
                source_system,
                hostname=hostname,
                domain_tags=domain_tags,
            )
        )
    return user_agent


def _browser_family_for_process(process_image: str) -> str:
    """Return the browser family implied by a process image, if any."""
    exe = process_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if exe in {"chrome.exe", "chrome", "google-chrome", "chromium", "chromium-browser"}:
        return "chrome"
    if exe in {"msedge.exe", "microsoft-edge", "edge"}:
        return "edge"
    if exe in {"firefox.exe", "firefox"}:
        return "firefox"
    if exe in {"opera.exe", "opera"}:
        return "opera"
    return ""


def _user_agent_matches_browser_family(user_agent: str, family: str) -> bool:
    """Return whether a User-Agent belongs to the requested browser family."""
    ua = user_agent.lower()
    if family == "chrome":
        return "chrome/" in ua and "edg/" not in ua and "opr/" not in ua
    if family == "edge":
        return "edg/" in ua or "edge/" in ua
    if family == "firefox":
        return "firefox/" in ua
    if family == "opera":
        return "opr/" in ua or "opera/" in ua
    return False


def browser_user_agent_for_process(
    rng: random.Random,
    source_system: "System | None",
    process_image: str,
    *,
    hostname: str | None = None,
    domain_tags: list[str] | None = None,
) -> str:
    """Pick a User-Agent that agrees with a known browser process image."""
    family = _browser_family_for_process(process_image)
    if not family:
        return ""

    data = load_proxy_user_agents()
    os_category = _get_os_category(source_system.os) if source_system is not None else "windows"
    pool_key = "linux" if os_category == "linux" else "windows"
    candidates = [
        user_agent
        for user_agent in _pool(data, "workstation", pool_key)
        if _user_agent_matches_browser_family(user_agent, family)
    ]
    if not candidates:
        return ""
    return normalize_proxy_user_agent_for_os(
        rng,
        source_system,
        rng.choice(candidates),
        hostname=hostname,
        domain_tags=domain_tags,
    )


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
