# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable per-run effective configuration and legacy-cache isolation."""

from __future__ import annotations

import copy
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

_CURRENT_EFFECTIVE_CONFIG: ContextVar[Any | None] = ContextVar(
    "evidenceforge_effective_config",
    default=None,
)
_CONFIG_EXECUTION_LOCK = threading.RLock()

_CATALOG_OVERLAY_TARGETS: dict[str, str] = {
    "destination_catalog": "activity/dns_registry.yaml",
    "traffic_catalog": "activity/traffic_profiles.yaml",
    "storage_catalog": "activity/storage_catalog.yaml",
}
_BUILTIN_DNS_TAGS = {
    "background",
    "cdn",
    "dev",
    "email",
    "git",
    "internal",
    "linux",
    "onedrive",
    "outlook",
    "saas",
    "social",
    "storage",
    "teams",
    "web",
    "windows",
}


def current_effective_config() -> Any | None:
    """Return the active immutable compilation snapshot, if any."""

    return _CURRENT_EFFECTIVE_CONFIG.get()


def uses_ambient_overlay_compat() -> bool:
    """Return whether a direct-Scenario caller retains legacy CWD overlay discovery."""

    effective = current_effective_config()
    return bool(effective is not None and effective.ambient_overlay_compat)


def project_overlay_document(relative_path: str) -> dict[str, Any] | None:
    """Return one snapshotted project overlay instead of rereading the filesystem."""

    effective = current_effective_config()
    if effective is None:
        return None
    value = effective.project_overlays.get(relative_path)
    return copy.deepcopy(value) if isinstance(value, dict) else None


def packaged_default_document(path: Any) -> tuple[bool, Any]:
    """Return an inlined packaged YAML document for a compiled run when available."""

    effective = current_effective_config()
    if effective is None or effective.ambient_overlay_compat:
        return False, None
    from pathlib import Path

    from evidenceforge.config import get_config_directory

    resolved_path = Path(path).resolve()
    config_root = get_config_directory().resolve()
    if not resolved_path.is_relative_to(config_root):
        return False, None
    relative_path = str(resolved_path.relative_to(config_root))
    if relative_path not in effective.packaged_defaults:
        return False, None
    return True, copy.deepcopy(effective.packaged_defaults[relative_path])


def pack_overlay_document(relative_path: str) -> dict[str, Any] | None:
    """Translate stable public pack catalogs into internal configuration families."""

    effective = current_effective_config()
    if effective is None:
        return None
    catalog_name = next(
        (name for name, target in _CATALOG_OVERLAY_TARGETS.items() if target == relative_path),
        None,
    )
    if catalog_name is None:
        return None
    entries = effective.catalogs.get(catalog_name, {})
    if catalog_name == "destination_catalog":
        domains: list[dict[str, Any]] = []
        valid_tags: dict[str, str] = {}
        for name, entry in entries.items():
            data = entry["data"]
            for tag in data["tags"]:
                if tag not in _BUILTIN_DNS_TAGS:
                    valid_tags[tag] = f"Pack-defined destination tag from {name}"
            for endpoint in data["endpoints"]:
                domains.append(
                    {
                        "domain": endpoint["domain"],
                        "ips": endpoint["ips"],
                        "tags": data["tags"],
                    }
                )
        return {"valid_tags": valid_tags, "domains": domains} if domains else None
    if catalog_name == "traffic_catalog":
        persona_traffic: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for entry in entries.values():
            data = entry["data"]
            for persona in data["audience"]:
                persona_traffic.setdefault(persona, {"outbound": []})["outbound"].extend(
                    data["outbound"]
                )
        return {"persona_traffic": persona_traffic} if persona_traffic else None
    if catalog_name == "storage_catalog":
        profiles = {name: entry["data"] for name, entry in entries.items()}
        return {"profiles": profiles} if profiles else None
    return None


def _cache_globals() -> list[tuple[object, str, Any]]:
    """Find legacy config caches that must not cross provider boundaries."""

    caches: list[tuple[object, str, Any]] = []
    for module_name, module in tuple(sys.modules.items()):
        if module is None or not module_name.startswith("evidenceforge"):
            continue
        for name, value in tuple(vars(module).items()):
            if name.startswith("_CACHED"):
                caches.append((module, name, value))
    return caches


def _cached_callables() -> list[Any]:
    """Find functools caches used by derived configuration loaders."""

    callables: list[Any] = []
    for module_name, module in tuple(sys.modules.items()):
        if module is None or not module_name.startswith("evidenceforge"):
            continue
        for value in tuple(vars(module).values()):
            if callable(value) and callable(getattr(value, "cache_clear", None)):
                callables.append(value)
    return callables


def _clear_runtime_caches() -> None:
    """Clear loaded raw and derived caches before reading a provider snapshot."""

    for module, name, _value in _cache_globals():
        setattr(module, name, None)
    for value in _cached_callables():
        value.cache_clear()


def _refresh_legacy_registry_globals() -> None:
    """Refresh imported-by-value DNS globals from the active provider snapshot."""

    network = sys.modules.get("evidenceforge.generation.activity.network")
    if network is None:
        return
    from evidenceforge.generation.activity.dns_registry import (
        get_cdn_ranges,
        get_domains_by_tag,
        get_forward_dns,
        get_ipv6_map,
        get_reverse_dns,
    )

    reverse_dns = get_reverse_dns()
    forward_dns = {domain: ips[0] for domain, ips in get_forward_dns().items() if ips}
    external_ips: dict[str, list[str]] = {}
    for activity_type, tag in network._TAG_TO_ACTIVITY.items():
        ips = [ip for entry in get_domains_by_tag(tag) for ip in entry["ips"]]
        external_ips[activity_type] = list(dict.fromkeys(ips))
    cdn_ranges = [tuple(value) for value in get_cdn_ranges()]
    ipv6_map = get_ipv6_map()

    network.REVERSE_DNS.clear()
    network.REVERSE_DNS.update(reverse_dns)
    network.FORWARD_DNS.clear()
    network.FORWARD_DNS.update(forward_dns)
    network.EXTERNAL_IPS.clear()
    network.EXTERNAL_IPS.update(external_ips)
    network._CDN_RANGES[:] = cdn_ranges
    network._IPV6_MAP.clear()
    network._IPV6_MAP.update(ipv6_map)


@contextmanager
def effective_config_scope(effective_config: Any) -> Iterator[None]:
    """Activate one provider with serialized legacy-cache compatibility.

    The lock makes old module-global caches safe while they are progressively
    migrated. Concurrent callers cannot leak configuration: each run receives a
    clean cache namespace and the previous process cache state is restored.
    """

    with _CONFIG_EXECUTION_LOCK:
        saved = _cache_globals()
        _clear_runtime_caches()
        token = _CURRENT_EFFECTIVE_CONFIG.set(effective_config)
        try:
            _refresh_legacy_registry_globals()
            yield
        finally:
            _CURRENT_EFFECTIVE_CONFIG.reset(token)
            _clear_runtime_caches()
            _refresh_legacy_registry_globals()
            for module, name, value in saved:
                setattr(module, name, value)
