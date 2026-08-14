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

_PACK_OVERLAY_PATHS = {
    "activity/application_catalog.yaml",
    "activity/dns_registry.yaml",
    "activity/storage_catalog.yaml",
    "activity/traffic_profiles.yaml",
}
_PUBLIC_SERVICE_RUNTIME: dict[str, tuple[str, str, int]] = {
    "http": ("tcp", "http", 80),
    "https": ("tcp", "ssl", 443),
    "ssh": ("tcp", "ssh", 22),
    "smb": ("tcp", "smb", 445),
    "smtp": ("tcp", "smtp", 25),
    "mssql": ("tcp", "mssql", 1433),
    "mysql": ("tcp", "mysql", 3306),
    "postgresql": ("tcp", "postgresql", 5432),
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


def _qualified_reference(owner: str, reference: str) -> str:
    """Qualify one local public reference with its exporting pack namespace."""

    return reference if ":" in reference else f"{owner.split(':', 1)[0]}:{reference}"


def _ordered_unique(values: list[str]) -> list[str]:
    """Deduplicate strings without changing authored precedence."""

    return list(dict.fromkeys(values))


def _builtin_dns_tags(effective: Any) -> set[str]:
    """Return packaged DNS tags from the immutable per-run snapshot."""

    registry = effective.packaged_defaults.get("activity/dns_registry.yaml", {})
    valid_tags = registry.get("valid_tags", {})
    if isinstance(valid_tags, dict):
        return {str(tag) for tag, description in valid_tags.items() if isinstance(description, str)}
    return {
        str(tag)
        for domain in registry.get("domains", [])
        if isinstance(domain, dict)
        for tag in domain.get("tags", [])
    }


def _document_parameter_pools(terms: list[str], os_category: str) -> dict[str, list[str]]:
    """Build process-scoped document placeholders without cross-pack global state."""

    if not terms:
        return {}
    separator = "\\" if os_category == "windows" else "/"
    documents = (
        r"C:\Users\{username}\Documents"
        if os_category == "windows"
        else "/home/{username}/Documents"
    )
    return {
        "document_term": terms,
        "document_name": [
            filename for term in terms for filename in (f"{term}.docx", f"{term}.xlsx")
        ],
        "doc_path": [f"{documents}{separator}{term}.docx" for term in terms],
        "document_path": [f"{documents}{separator}{term}.docx" for term in terms],
        "spreadsheet_path": [f"{documents}{separator}{term}.xlsx" for term in terms],
        "pdf_path": [f"{documents}{separator}{term}.pdf" for term in terms],
    }


def _application_graph(effective: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Adapt process/application catalogs into runtime apps and exact connection metadata."""

    processes = effective.catalogs.get("process_catalog", {})
    applications = effective.catalogs.get("application_catalog", {})
    packaged = effective.packaged_defaults.get("activity/application_catalog.yaml", {})
    builtin_apps = {
        str(entry.get("id")): entry
        for entry in packaged.get("applications", [])
        if isinstance(entry, dict) and entry.get("id")
    }
    overlays: dict[str, dict[str, Any]] = {}
    application_runtime: dict[str, dict[str, Any]] = {}

    def merge_runtime_app(
        app_id: str,
        *,
        personas: list[str],
        platform_pools: dict[str, dict[str, list[str]]],
        full_entry: dict[str, Any] | None = None,
    ) -> None:
        existing = overlays.get(app_id)
        incoming = copy.deepcopy(full_entry) if full_entry is not None else {"id": app_id}
        incoming["personas"] = personas
        incoming_platforms = incoming.setdefault("platforms", {})
        for os_category, pools in platform_pools.items():
            if not pools:
                continue
            incoming_platforms.setdefault(os_category, {})["command_parameter_pools"] = pools
        if existing is None:
            overlays[app_id] = incoming
            return
        existing["personas"] = _ordered_unique(
            [*existing.get("personas", []), *incoming.get("personas", [])]
        )
        for os_category, platform in incoming.get("platforms", {}).items():
            if os_category not in existing.get("platforms", {}):
                existing.setdefault("platforms", {})[os_category] = copy.deepcopy(platform)
                continue
            existing_pool = existing["platforms"][os_category].setdefault(
                "command_parameter_pools", {}
            )
            for key, values in platform.get("command_parameter_pools", {}).items():
                existing_pool[key] = _ordered_unique([*existing_pool.get(key, []), *values])

    for application_name, application_entry in applications.items():
        application_data = application_entry["data"]
        personas = [
            _qualified_reference(application_name, value)
            for value in application_data.get("personas", [])
        ]
        runtime_ids: list[str] = []
        for raw_process_reference in application_data.get("processes", []):
            process_reference = _qualified_reference(application_name, raw_process_reference)
            process_entry = processes.get(process_reference)
            if process_entry is None:
                continue
            process_data = process_entry["data"]
            terms = list(process_data.get("document_terms", []))
            for builtin_id in process_data.get("builtins", []):
                builtin = builtin_apps.get(builtin_id)
                if builtin is None:
                    continue
                # Clone packaged processes under the qualified profile identity.
                # Otherwise two profiles that reuse (for example) Chrome would
                # union their document-term pools on one global built-in entry.
                runtime_id = f"{process_reference}::{builtin_id}"
                builtin_entry = copy.deepcopy(builtin)
                builtin_entry["id"] = runtime_id
                pools = {
                    os_category: _document_parameter_pools(terms, os_category)
                    for os_category in builtin.get("platforms", {})
                }
                merge_runtime_app(
                    runtime_id,
                    personas=personas,
                    platform_pools=pools,
                    full_entry=builtin_entry,
                )
                runtime_ids.append(runtime_id)
            for custom in process_data.get("custom", []):
                custom_entry = copy.deepcopy(custom)
                custom_id = str(custom_entry["id"])
                process_owner = process_reference.split(":", 1)[0]
                runtime_id = custom_id if ":" in custom_id else f"{process_owner}:{custom_id}"
                custom_entry["id"] = runtime_id
                pools = {
                    os_category: _document_parameter_pools(terms, os_category)
                    for os_category in custom_entry.get("platforms", {})
                }
                merge_runtime_app(
                    runtime_id,
                    personas=personas,
                    platform_pools=pools,
                    full_entry=custom_entry,
                )
                runtime_ids.append(runtime_id)
        application_runtime[application_name] = {
            "application_ids": _ordered_unique(runtime_ids),
            "connections": copy.deepcopy(application_data.get("connections", {})),
        }
    return list(overlays.values()), application_runtime


def _destination_overlay(effective: Any) -> dict[str, Any] | None:
    """Adapt destinations to DNS entries with collision-proof exact selection tags."""

    domains: list[dict[str, Any]] = []
    valid_tags: dict[str, str] = {}
    exact_destination_domains: dict[str, list[str]] = {}
    builtin_tags = _builtin_dns_tags(effective)
    entries = effective.catalogs.get("destination_catalog", {})
    for name, entry in entries.items():
        namespace = name.split(":", 1)[0]
        data = entry["data"]
        exact_destination_domains[name] = [
            str(endpoint["domain"]) for endpoint in data.get("endpoints", [])
        ]
        tags: list[str] = [name]
        valid_tags[name] = f"Exact destination export {name}"
        for raw_tag in data.get("tags", []):
            tag = raw_tag if raw_tag in builtin_tags or ":" in raw_tag else f"{namespace}:{raw_tag}"
            tags.append(tag)
            if tag not in builtin_tags:
                valid_tags[tag] = f"Pack-defined destination tag from {name}"
        for endpoint in data.get("endpoints", []):
            domains.append(
                {
                    "domain": endpoint["domain"],
                    "ips": endpoint["ips"],
                    "tags": _ordered_unique(tags),
                }
            )
    if not domains:
        return None
    return {
        "valid_tags": valid_tags,
        "domains": domains,
        "_pack_exact_destination_domains": exact_destination_domains,
    }


def _connection_from_application(
    *,
    application_name: str,
    binding: dict[str, Any],
    application_runtime: dict[str, dict[str, Any]],
    destinations: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Compile an exact application connection to the legacy network request shape."""

    runtime = application_runtime.get(application_name)
    if runtime is None:
        return None
    connection = runtime["connections"].get(binding["connection"])
    if connection is None:
        return None
    destination_name = _qualified_reference(application_name, connection["destination"])
    destination = destinations.get(destination_name)
    if destination is None:
        return None
    service_spec = destination["data"].get("services", {}).get(connection["service"])
    if service_spec is None:
        return None
    protocol = str(service_spec["protocol"])
    proto, service, default_port = _PUBLIC_SERVICE_RUNTIME[protocol]
    return {
        "role": "_external",
        "port": int(service_spec.get("port") or default_port),
        "proto": proto,
        "service": service,
        "weight": int(binding.get("weight", 1)),
        "emit_dns": True,
        "dns_tags": [destination_name],
        "pack_application": application_name,
        "application_ids": runtime["application_ids"],
    }


def _traffic_overlay(effective: Any) -> dict[str, Any] | None:
    """Compile traffic exports as independently scheduled, provenance-preserving groups."""

    _application_overlays, application_runtime = _application_graph(effective)
    applications = effective.catalogs.get("application_catalog", {})
    destinations = effective.catalogs.get("destination_catalog", {})
    builtin_tags = _builtin_dns_tags(effective)
    groups_by_persona: dict[str, dict[str, dict[str, Any]]] = {}
    for traffic_name, traffic_entry in effective.catalogs.get("traffic_catalog", {}).items():
        namespace = traffic_name.split(":", 1)[0]
        data = traffic_entry["data"]
        connections: list[dict[str, Any]] = []
        for outbound in data.get("outbound", []):
            compiled = copy.deepcopy(outbound)
            compiled["dns_tags"] = [
                tag if tag in builtin_tags or ":" in tag else f"{namespace}:{tag}"
                for tag in compiled.get("dns_tags", [])
            ]
            connections.append(compiled)
        for binding in data.get("applications", []):
            application_name = _qualified_reference(traffic_name, binding["application"])
            if application_name not in applications:
                continue
            compiled = _connection_from_application(
                application_name=application_name,
                binding=binding,
                application_runtime=application_runtime,
                destinations=destinations,
            )
            if compiled is not None:
                connections.append(compiled)
        group = {
            "id": traffic_name,
            "cadence": copy.deepcopy(data.get("cadence")),
            "outbound": connections,
        }
        for raw_persona in data.get("audience", []):
            persona = _qualified_reference(traffic_name, raw_persona)
            groups_by_persona.setdefault(persona, {})[traffic_name] = group
    return {"pack_persona_traffic": groups_by_persona} if groups_by_persona else None


def pack_overlay_document(relative_path: str) -> dict[str, Any] | None:
    """Translate the complete public pack graph into internal configuration families."""

    effective = current_effective_config()
    if effective is None or relative_path not in _PACK_OVERLAY_PATHS:
        return None
    if relative_path == "activity/application_catalog.yaml":
        applications, _runtime = _application_graph(effective)
        return {"applications": applications} if applications else None
    if relative_path == "activity/dns_registry.yaml":
        return _destination_overlay(effective)
    if relative_path == "activity/traffic_profiles.yaml":
        return _traffic_overlay(effective)
    if relative_path == "activity/storage_catalog.yaml":
        profiles = {
            name: entry["data"]
            for name, entry in effective.catalogs.get("storage_catalog", {}).items()
        }
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
def effective_config_scope(
    effective_config: Any,
    *,
    refresh_legacy_globals: bool = True,
) -> Iterator[None]:
    """Activate one provider with serialized legacy-cache compatibility.

    The lock makes old module-global caches safe while they are progressively
    migrated. Concurrent callers cannot leak configuration: each run receives a
    clean cache namespace and the previous process cache state is restored.

    Args:
        effective_config: Immutable configuration snapshot to activate.
        refresh_legacy_globals: Refresh imported-by-value DNS registries at the
            scope boundary. Validation preflight disables this because malformed
            user configuration must be reported before any derived registry loads.
    """

    with _CONFIG_EXECUTION_LOCK:
        saved = _cache_globals()
        _clear_runtime_caches()
        token = _CURRENT_EFFECTIVE_CONFIG.set(effective_config)
        try:
            if refresh_legacy_globals:
                _refresh_legacy_registry_globals()
            yield
        finally:
            _CURRENT_EFFECTIVE_CONFIG.reset(token)
            _clear_runtime_caches()
            if refresh_legacy_globals:
                _refresh_legacy_registry_globals()
            for module, name, value in saved:
                setattr(module, name, value)
