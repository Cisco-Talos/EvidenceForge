# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable per-run effective configuration and legacy-cache isolation."""

from __future__ import annotations

import copy
import functools
import importlib
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from importlib.machinery import ModuleSpec
from types import FunctionType, ModuleType
from typing import Any

_CURRENT_EFFECTIVE_CONFIG: ContextVar[Any | None] = ContextVar(
    "evidenceforge_effective_config",
    default=None,
)
_CURRENT_PREPARED_TIMING_PROFILES: ContextVar[Any | None] = ContextVar(
    "evidenceforge_prepared_timing_profiles",
    default=None,
)
_CONFIG_EXECUTION_LOCK = threading.RLock()
_BASE_EXCEPTION_DICT_DESCRIPTOR = BaseException.__dict__["__dict__"]


class _ConfigScopeLease:
    """Serialize provider cache namespaces while allowing callback-safe preparation."""

    __slots__ = ("_cleanup_pin_groups", "_condition", "_depth", "_owner_thread_id")

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._owner_thread_id: int | None = None
        self._depth = 0
        self._cleanup_pin_groups: list[list[Any]] = []

    def acquire(self) -> None:
        """Acquire one reentrant lease level."""

        thread_id = threading.get_ident()
        with self._condition:
            while self._owner_thread_id not in {None, thread_id}:
                self._condition.wait()
            self._owner_thread_id = thread_id
            self._depth += 1

    def release(self, cleanup_pins: list[Any] | None = None) -> list[list[Any]]:
        """Release one level and return deferred pins after ownership reaches zero."""

        thread_id = threading.get_ident()
        released_pin_groups: list[list[Any]] = []
        with self._condition:
            if self._owner_thread_id != thread_id or self._depth < 1:
                raise RuntimeError("provider scope lease released by a non-owner")
            if cleanup_pins is not None:
                list.append(self._cleanup_pin_groups, cleanup_pins)
            self._depth -= 1
            if self._depth == 0:
                self._owner_thread_id = None
                self._condition.notify_all()
                released_pin_groups = self._cleanup_pin_groups
                self._cleanup_pin_groups = []
        return released_pin_groups

    @contextmanager
    def hold(self) -> Iterator[None]:
        """Hold one reentrant lease level for a cache-namespace operation."""

        self.acquire()
        try:
            yield
        finally:
            self.release()

    @contextmanager
    def suspend_current(self) -> Iterator[None]:
        """Temporarily release every current-thread level around callbacks.

        Nested scope preparation otherwise inherits its outer scope's lease.
        Suspending lets warning callbacks join public loader/provider threads;
        the exact outer depth is reacquired before preparation returns.
        """

        thread_id = threading.get_ident()
        suspended_depth = 0
        with self._condition:
            if self._owner_thread_id == thread_id:
                suspended_depth = self._depth
                self._depth = 0
                self._owner_thread_id = None
                self._condition.notify_all()
        try:
            yield
        finally:
            body_failure = sys.exception()
            retained_failure = body_failure
            if suspended_depth:
                with self._condition:
                    while self._owner_thread_id is not None:
                        try:
                            self._condition.wait()
                        except BaseException as reacquire_failure:
                            retained_failure = _retain_provider_failure(
                                retained_failure,
                                reacquire_failure,
                                description="provider lease reacquisition",
                            )
                    self._owner_thread_id = thread_id
                    self._depth = suspended_depth
            if body_failure is None and retained_failure is not None:
                raise retained_failure

    def owned_by_current_thread(self) -> bool:
        """Return whether the calling thread currently owns the lease."""

        with self._condition:
            return self._owner_thread_id == threading.get_ident()


_CONFIG_SCOPE_LEASE = _ConfigScopeLease()

_TRUSTED_DERIVED_CACHE_SLOTS: tuple[tuple[str, str], ...] = (
    (
        "evidenceforge.generation.resource_forecast",
        "load_resource_forecast_calibration",
    ),
    ("evidenceforge.generation.storage_world", "_load_catalog_config"),
    ("evidenceforge.evaluation.thresholds", "load_thresholds"),
)
_TIMING_PROFILE_MODULE_NAME = "evidenceforge.generation.activity.timing_profiles"
_TIMING_PROFILE_CACHE_SLOT = "_CACHED_TIMING_PROFILES"
_LEGACY_NETWORK_MODULE_NAME = "evidenceforge.generation.activity.network"


@dataclass(frozen=True, slots=True)
class _RuntimeModuleAnchor:
    """One exact canonical module object and its callback-free namespace."""

    name: str
    module: ModuleType
    namespace: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _TimingProfileRuntimeCacheAnchor:
    """Provider-owned immutable identities for the timing cache protocol."""

    owner: _RuntimeModuleAnchor
    controller: Any
    controller_type: type[Any]
    snapshot_operation: Callable[[Any], Any]
    clear_operation: Callable[[Any], None]
    restore_operation: Callable[[Any, Any], None]


@dataclass(frozen=True, slots=True)
class _DerivedRuntimeCacheAnchor:
    """One exact canonical owner slot and its audited LRU wrapper identity."""

    owner: _RuntimeModuleAnchor
    slot: str
    wrapper: Any


def _exact_registered_runtime_module(
    module_name: str,
    namespace: dict[str, Any],
) -> _RuntimeModuleAnchor:
    """Resolve one registering module without invoking registry or module callbacks."""

    if type(module_name) is not str or type(namespace) is not dict:
        raise RuntimeError("runtime cache registration has invalid provenance")
    modules = ModuleType.__getattribute__(sys, "modules")
    if type(modules) is not dict:
        raise RuntimeError("runtime module registry must be a builtin mapping")
    module = dict.get(modules, module_name)
    if type(module) is not ModuleType:
        raise RuntimeError("runtime cache registration owner must be an exact module")
    actual_namespace = ModuleType.__getattribute__(module, "__dict__")
    if type(actual_namespace) is not dict or actual_namespace is not namespace:
        raise RuntimeError("runtime cache registration namespace was replaced")
    registered_name = dict.get(namespace, "__name__")
    if type(registered_name) is not str or not str.__eq__(registered_name, module_name):
        raise RuntimeError("runtime cache registration module name is invalid")
    spec = dict.get(namespace, "__spec__")
    if spec is not None:
        if type(spec) is not ModuleSpec:
            raise RuntimeError("runtime cache registration module spec is invalid")
        spec_name = object.__getattribute__(spec, "name")
        if type(spec_name) is not str or not str.__eq__(spec_name, module_name):
            raise RuntimeError("runtime cache registration module spec is invalid")
    return _RuntimeModuleAnchor(
        name=module_name,
        module=module,
        namespace=namespace,
    )


def _make_timing_profile_runtime_cache_registry() -> tuple[
    Callable[..., None],
    Callable[[], _TimingProfileRuntimeCacheAnchor | None],
]:
    """Build a one-time registration closure immune to peer-module rebinding."""

    registration_lock = threading.Lock()
    registered: _TimingProfileRuntimeCacheAnchor | None = None

    def register(
        module_name: str,
        namespace: dict[str, Any],
        controller: Any,
        controller_type: type[Any],
        snapshot_operation: Callable[[Any], Any],
        clear_operation: Callable[[Any], None],
        restore_operation: Callable[[Any, Any], None],
    ) -> None:
        nonlocal registered
        if type(module_name) is not str or not str.__eq__(module_name, _TIMING_PROFILE_MODULE_NAME):
            raise RuntimeError("timing cache registration owner is invalid")
        if type(controller_type) is not type or type(controller) is not controller_type:
            raise RuntimeError("timing cache registration type is invalid")
        if any(
            type(operation) is not FunctionType
            for operation in (snapshot_operation, clear_operation, restore_operation)
        ):
            raise RuntimeError("timing cache registration operations must be exact functions")
        owner = _exact_registered_runtime_module(module_name, namespace)
        candidate = _TimingProfileRuntimeCacheAnchor(
            owner=owner,
            controller=controller,
            controller_type=controller_type,
            snapshot_operation=snapshot_operation,
            clear_operation=clear_operation,
            restore_operation=restore_operation,
        )
        with registration_lock:
            if registered is not None:
                raise RuntimeError("timing cache registration cannot be rebound")
            registered = candidate

    def get_registered() -> _TimingProfileRuntimeCacheAnchor | None:
        with registration_lock:
            return registered

    return register, get_registered


def _make_derived_runtime_cache_registry() -> tuple[
    Callable[[str, str, dict[str, Any], Any], None],
    Callable[[], tuple[_DerivedRuntimeCacheAnchor, ...]],
]:
    """Build immutable per-owner identities for the three audited LRU caches."""

    registration_lock = threading.Lock()
    registered: dict[tuple[str, str], _DerivedRuntimeCacheAnchor] = {}

    def register(
        module_name: str,
        slot: str,
        namespace: dict[str, Any],
        wrapper: Any,
    ) -> None:
        if type(module_name) is not str or type(slot) is not str:
            raise RuntimeError("derived cache registration provenance is invalid")
        key = (module_name, slot)
        if key not in _TRUSTED_DERIVED_CACHE_SLOTS:
            raise RuntimeError("derived cache registration owner is not trusted")
        if type(wrapper) is not functools._lru_cache_wrapper:
            raise RuntimeError("derived cache registration wrapper is invalid")
        owner = _exact_registered_runtime_module(module_name, namespace)
        candidate = _DerivedRuntimeCacheAnchor(
            owner=owner,
            slot=slot,
            wrapper=wrapper,
        )
        with registration_lock:
            if key in registered:
                raise RuntimeError("derived cache registration cannot be rebound")
            dict.__setitem__(registered, key, candidate)

    def get_registered() -> tuple[_DerivedRuntimeCacheAnchor, ...]:
        with registration_lock:
            return tuple(
                registered[key] for key in _TRUSTED_DERIVED_CACHE_SLOTS if key in registered
            )

    return register, get_registered


def _make_legacy_network_module_registry() -> tuple[
    Callable[[str, dict[str, Any]], None],
    Callable[[], _RuntimeModuleAnchor | None],
]:
    """Build the one-time canonical legacy-network module trust anchor."""

    registration_lock = threading.Lock()
    registered: _RuntimeModuleAnchor | None = None

    def register(module_name: str, namespace: dict[str, Any]) -> None:
        nonlocal registered
        if type(module_name) is not str or not str.__eq__(module_name, _LEGACY_NETWORK_MODULE_NAME):
            raise RuntimeError("legacy network registration owner is invalid")
        candidate = _exact_registered_runtime_module(module_name, namespace)
        with registration_lock:
            if registered is not None:
                raise RuntimeError("legacy network registration cannot be rebound")
            registered = candidate

    def get_registered() -> _RuntimeModuleAnchor | None:
        with registration_lock:
            return registered

    return register, get_registered


(
    _register_timing_profile_runtime_cache,
    _get_timing_profile_runtime_cache_anchor,
) = _make_timing_profile_runtime_cache_registry()
(
    _register_trusted_derived_cache,
    _get_trusted_derived_cache_anchors,
) = _make_derived_runtime_cache_registry()
(
    _register_legacy_network_module,
    _get_legacy_network_module_anchor,
) = _make_legacy_network_module_registry()

_PACK_OVERLAY_PATHS = {
    "activity/application_catalog.yaml",
    "activity/dns_registry.yaml",
    "activity/storage_catalog.yaml",
    "activity/traffic_profiles.yaml",
}
_TIMING_PROFILE_PATH = "activity/timing_profiles.yaml"
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


@dataclass(frozen=True, slots=True)
class _CoordinatedRuntimeCacheValue:
    """One state snapshot owned by a lock-aware module cache coordinator."""

    controller: Any
    snapshot: Any
    clear_operation: Callable[[Any], None]
    restore_operation: Callable[[Any, Any], None]


@dataclass(frozen=True, slots=True)
class _LegacyRegistryGlobalsSnapshot:
    """Exact mutable objects and contents exported by the legacy network module."""

    owner: _RuntimeModuleAnchor
    reverse_dns: dict[str, str]
    reverse_dns_items: dict[str, str]
    forward_dns: dict[str, str]
    forward_dns_items: dict[str, str]
    external_ips: dict[str, list[str]]
    external_ips_items: dict[str, list[str]]
    cdn_ranges: list[tuple[Any, ...]]
    cdn_range_items: list[tuple[Any, ...]]
    ipv6_map: dict[str, str]
    ipv6_map_items: dict[str, str]


@dataclass(frozen=True, slots=True)
class _PreparedLegacyRegistryGlobals:
    """Detached DNS values computed before provider serialization."""

    reverse_dns: dict[str, str]
    forward_dns: dict[str, str]
    external_ips: dict[str, list[str]]
    cdn_ranges: list[tuple[Any, ...]]
    ipv6_map: dict[str, str]


@dataclass(frozen=True, slots=True)
class _PreparedEffectiveTimingProfiles:
    """One lock-free timing preparation plus its exact validation provenance."""

    owner: _RuntimeModuleAnchor
    value: Any
    prepare_operation: Callable[[], Any]
    validator_operation: Callable[[Any], bool]


def current_effective_config() -> Any | None:
    """Return the active immutable compilation snapshot, if any."""

    return _CURRENT_EFFECTIVE_CONFIG.get()


def current_prepared_timing_profiles() -> Any | None:
    """Return the scope-entry timing snapshot prepared outside provider locks."""

    return _CURRENT_PREPARED_TIMING_PROFILES.get()


def uses_ambient_overlay_compat() -> bool:
    """Return whether a direct-Scenario caller retains legacy CWD overlay discovery."""

    effective = current_effective_config()
    return bool(effective is not None and effective.ambient_overlay_compat)


def _copy_timing_profile_document(value: Any) -> dict[str, Any]:
    """Bound and detach timing data without invoking recursive copy callbacks."""

    from evidenceforge.generation.activity.timing_profiles import (
        TimingProfileError,
        _detached_timing_profile_copy,
    )

    copied = _detached_timing_profile_copy(value)
    if type(copied) is not dict:
        raise TimingProfileError("timing profile root must be a mapping")
    return copied


def project_overlay_document(relative_path: str) -> dict[str, Any] | None:
    """Return one snapshotted project overlay instead of rereading the filesystem."""

    effective = current_effective_config()
    if effective is None:
        return None
    value = effective.project_overlays.get(relative_path)
    if value is not None and relative_path == _TIMING_PROFILE_PATH:
        return _copy_timing_profile_document(value)
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
    value = effective.packaged_defaults[relative_path]
    if relative_path == _TIMING_PROFILE_PATH:
        return True, _copy_timing_profile_document(value)
    return True, copy.deepcopy(value)


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
                for platform in builtin_entry.get("platforms", {}).values():
                    if not isinstance(platform, dict):
                        continue
                    deployment = platform.get("deployment")
                    if (
                        isinstance(deployment, dict)
                        and deployment.get("kind") == "catalog"
                        and not deployment.get("product_id")
                    ):
                        # The qualified runtime ID is a profile identity, not a new
                        # software product. Preserve the packaged application's
                        # release namespace so two pack profiles that reuse Chrome
                        # resolve to one path-independent content identity.
                        deployment["product_id"] = builtin_id
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
        return (
            {
                "schema_version": 2,
                "default_deployment": {"kind": "legacy_static"},
                "applications": applications,
            }
            if applications
            else None
        )
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


def _is_evidenceforge_module_name(module_name: str) -> bool:
    """Match the exact package namespace without virtual string dispatch."""

    return str.__eq__(module_name, "evidenceforge") or str.startswith(
        module_name,
        "evidenceforge.",
    )


def _snapshot_runtime_modules() -> tuple[list[_RuntimeModuleAnchor], BaseException | None]:
    """Capture canonical EvidenceForge modules without invoking registry callbacks."""

    retained_failure: BaseException | None = None
    modules = ModuleType.__getattribute__(sys, "modules")
    if type(modules) is not dict:
        return [], RuntimeError("runtime module registry must be a builtin mapping")
    try:
        registry_items = tuple(dict.items(dict.copy(modules)))
    except BaseException as discovery_failure:
        return [], discovery_failure

    candidates: list[tuple[str, Any]] = []
    for module_name, module in registry_items:
        if type(module_name) is not str:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("runtime module registry keys must be builtin strings"),
                description="runtime-module discovery",
            )
            continue
        if _is_evidenceforge_module_name(module_name):
            candidates.append((module_name, module))
    candidates.sort(key=lambda item: item[0])

    discovered: list[_RuntimeModuleAnchor] = []
    seen_module_ids: set[int] = set()
    for module_name, module in candidates:
        if type(module) is not ModuleType:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("EvidenceForge runtime modules must use exact module objects"),
                description="runtime-module discovery",
            )
            continue
        namespace = ModuleType.__getattribute__(module, "__dict__")
        if type(namespace) is not dict:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("EvidenceForge runtime module namespace must be a builtin mapping"),
                description="runtime-module discovery",
            )
            continue
        canonical_name = dict.get(namespace, "__name__")
        if (
            type(canonical_name) is not str
            or not str.__eq__(canonical_name, module_name)
            or id(module) in seen_module_ids
        ):
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("EvidenceForge runtime module alias has invalid provenance"),
                description="runtime-module discovery",
            )
            continue
        spec = dict.get(namespace, "__spec__")
        if spec is not None:
            if type(spec) is not ModuleSpec:
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("EvidenceForge runtime module spec is invalid"),
                    description="runtime-module discovery",
                )
                continue
            spec_name = object.__getattribute__(spec, "name")
            if type(spec_name) is not str or not str.__eq__(spec_name, module_name):
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("EvidenceForge runtime module spec is invalid"),
                    description="runtime-module discovery",
                )
                continue
        seen_module_ids.add(id(module))
        discovered.append(
            _RuntimeModuleAnchor(
                name=module_name,
                module=module,
                namespace=namespace,
            )
        )
    return discovered, retained_failure


def _snapshot_runtime_module_items(
    owner: _RuntimeModuleAnchor,
) -> tuple[list[tuple[str, Any]], BaseException | None]:
    """Capture one exact module namespace in deterministic callback-free order."""

    try:
        raw_items = tuple(dict.items(dict.copy(owner.namespace)))
    except BaseException as discovery_failure:
        return [], discovery_failure
    retained_failure: BaseException | None = None
    items: list[tuple[str, Any]] = []
    for name, value in raw_items:
        if type(name) is not str:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("runtime module namespace keys must be builtin strings"),
                description="runtime-cache discovery",
            )
            continue
        items.append((name, value))
    items.sort(key=lambda item: item[0])
    return items, retained_failure


def _discover_cache_globals(
    *,
    snapshot_coordinators: bool,
    _get_timing_anchor: Callable[[], _TimingProfileRuntimeCacheAnchor | None] = (
        _get_timing_profile_runtime_cache_anchor
    ),
) -> tuple[list[tuple[dict[str, Any], str, Any]], BaseException | None]:
    """Discover every safe raw cache incrementally and retain the first failure."""

    modules, retained_failure = _snapshot_runtime_modules()
    caches: list[tuple[dict[str, Any], str, Any]] = []
    timing_anchor = _get_timing_anchor()
    modules_by_name = {owner.name: owner for owner in modules}
    anchored_target_added = False
    if timing_anchor is not None:
        current_owner = modules_by_name.get(_TIMING_PROFILE_MODULE_NAME)
        owner_matches = not (
            current_owner is None
            or current_owner.module is not timing_anchor.owner.module
            or current_owner.namespace is not timing_anchor.owner.namespace
        )
        slot_matches = owner_matches and (
            dict.get(timing_anchor.owner.namespace, _TIMING_PROFILE_CACHE_SLOT)
            is timing_anchor.controller
        )
        if not owner_matches or not slot_matches:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError(
                    "anchored timing profile runtime module is missing or replaced"
                    if not owner_matches
                    else "timing profile runtime cache coordinator was replaced"
                ),
                description="runtime-cache discovery",
            )
            snapshot: Any = None
            if snapshot_coordinators:
                try:
                    snapshot = timing_anchor.snapshot_operation(timing_anchor.controller)
                except BaseException as discovery_failure:
                    retained_failure = _retain_provider_failure(
                        retained_failure,
                        discovery_failure,
                        description="runtime-cache coordinator snapshot",
                    )
            caches.append(
                (
                    timing_anchor.owner.namespace,
                    _TIMING_PROFILE_CACHE_SLOT,
                    _CoordinatedRuntimeCacheValue(
                        controller=timing_anchor.controller,
                        snapshot=snapshot,
                        clear_operation=timing_anchor.clear_operation,
                        restore_operation=timing_anchor.restore_operation,
                    ),
                )
            )
            anchored_target_added = True
    for owner in modules:
        items, item_failure = _snapshot_runtime_module_items(owner)
        if item_failure is not None:
            retained_failure = _retain_provider_failure(
                retained_failure,
                item_failure,
                description="runtime-cache discovery",
            )
        for name, value in items:
            if not str.startswith(name, "_CACHED"):
                continue
            coordinated_location = str.__eq__(
                owner.name, _TIMING_PROFILE_MODULE_NAME
            ) and str.__eq__(name, _TIMING_PROFILE_CACHE_SLOT)
            if not coordinated_location:
                caches.append((owner.namespace, name, value))
                continue
            if (
                timing_anchor is None
                or owner.module is not timing_anchor.owner.module
                or owner.namespace is not timing_anchor.owner.namespace
                or value is not timing_anchor.controller
                or type(value) is not timing_anchor.controller_type
            ):
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("timing profile runtime cache coordinator was replaced"),
                    description="runtime-cache discovery",
                )
                if timing_anchor is not None and not anchored_target_added:
                    snapshot = None
                    if snapshot_coordinators:
                        try:
                            snapshot = timing_anchor.snapshot_operation(timing_anchor.controller)
                        except BaseException as discovery_failure:
                            retained_failure = _retain_provider_failure(
                                retained_failure,
                                discovery_failure,
                                description="runtime-cache coordinator snapshot",
                            )
                    caches.append(
                        (
                            timing_anchor.owner.namespace,
                            _TIMING_PROFILE_CACHE_SLOT,
                            _CoordinatedRuntimeCacheValue(
                                controller=timing_anchor.controller,
                                snapshot=snapshot,
                                clear_operation=timing_anchor.clear_operation,
                                restore_operation=timing_anchor.restore_operation,
                            ),
                        )
                    )
                    anchored_target_added = True
                # Pin and callback-free clear the untrusted replacement during cleanup.
                caches.append((owner.namespace, name, value))
                continue
            snapshot: Any = None
            if snapshot_coordinators:
                try:
                    snapshot = timing_anchor.snapshot_operation(value)
                except BaseException as discovery_failure:
                    retained_failure = _retain_provider_failure(
                        retained_failure,
                        discovery_failure,
                        description="runtime-cache coordinator snapshot",
                    )
            caches.append(
                (
                    owner.namespace,
                    name,
                    _CoordinatedRuntimeCacheValue(
                        controller=value,
                        snapshot=snapshot,
                        clear_operation=timing_anchor.clear_operation,
                        restore_operation=timing_anchor.restore_operation,
                    ),
                )
            )
    return caches, retained_failure


def _cache_globals() -> list[tuple[dict[str, Any], str, Any]]:
    """Snapshot every legacy cache or fail before clearing any target."""

    caches, discovery_failure = _discover_cache_globals(snapshot_coordinators=True)
    if discovery_failure is not None:
        raise discovery_failure
    return caches


def _cache_globals_for_clear() -> tuple[
    list[tuple[dict[str, Any], str, Any]],
    BaseException | None,
]:
    """Return every safe current cache plus the first exhaustive rescan failure."""

    return _discover_cache_globals(snapshot_coordinators=False)


def _discover_cached_callables(
    *,
    _get_derived_anchors: Callable[[], tuple[_DerivedRuntimeCacheAnchor, ...]] = (
        _get_trusted_derived_cache_anchors
    ),
) -> tuple[list[Any], BaseException | None]:
    """Discover anchored LRUs incrementally and reject every unknown owned wrapper."""

    modules, retained_failure = _snapshot_runtime_modules()
    modules_by_name = {owner.name: owner for owner in modules}
    anchors = _get_derived_anchors()
    anchors_by_key = {(anchor.owner.name, anchor.slot): anchor for anchor in anchors}
    trusted_by_id: dict[int, Any] = {}

    for module_name, slot in _TRUSTED_DERIVED_CACHE_SLOTS:
        owner = modules_by_name.get(module_name)
        anchor = anchors_by_key.get((module_name, slot))
        if owner is None:
            if anchor is not None:
                trusted_by_id[id(anchor.wrapper)] = anchor.wrapper
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("trusted derived cache canonical owner is missing"),
                    description="derived-cache discovery",
                )
            continue
        if anchor is None:
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("trusted derived cache owner was not registered"),
                description="derived-cache discovery",
            )
            continue
        trusted_by_id[id(anchor.wrapper)] = anchor.wrapper
        current = dict.get(owner.namespace, slot)
        if (
            owner.module is not anchor.owner.module
            or owner.namespace is not anchor.owner.namespace
            or current is not anchor.wrapper
            or type(current) is not functools._lru_cache_wrapper
        ):
            retained_failure = _retain_provider_failure(
                retained_failure,
                RuntimeError("trusted derived cache owner was replaced"),
                description="derived-cache discovery",
            )

    scanned_wrapper_ids = set(trusted_by_id)
    for owner in modules:
        items, item_failure = _snapshot_runtime_module_items(owner)
        if item_failure is not None:
            retained_failure = _retain_provider_failure(
                retained_failure,
                item_failure,
                description="derived-cache discovery",
            )
        for _name, value in items:
            if type(value) is not functools._lru_cache_wrapper:
                continue
            value_id = id(value)
            if value_id in scanned_wrapper_ids:
                continue
            scanned_wrapper_ids.add(value_id)
            wrapper_namespace = object.__getattribute__(value, "__dict__")
            if type(wrapper_namespace) is not dict:
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("derived cache wrapper metadata is invalid"),
                    description="derived-cache discovery",
                )
                continue
            owner_module = dict.get(wrapper_namespace, "__module__")
            if type(owner_module) is not str:
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("derived cache wrapper metadata is invalid"),
                    description="derived-cache discovery",
                )
                continue
            if _is_evidenceforge_module_name(owner_module):
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    RuntimeError("untrusted derived cache wrapper discovered"),
                    description="derived-cache discovery",
                )
    return list(trusted_by_id.values()), retained_failure


def _cached_callables() -> list[Any]:
    """Return anchored LRUs or fail before clearing any derived cache."""

    cached_callables, discovery_failure = _discover_cached_callables()
    if discovery_failure is not None:
        raise discovery_failure
    return cached_callables


def _cached_callables_for_clear() -> tuple[list[Any], BaseException | None]:
    """Return every anchored LRU plus the first exhaustive rescan failure."""

    return _discover_cached_callables()


def _note_cleanup_failure(
    primary: BaseException,
    action: str,
    _exception_dict_descriptor: Any = _BASE_EXCEPTION_DICT_DESCRIPTOR,
) -> None:
    """Annotate a primary through exact builtin storage without virtual callbacks."""

    if type(action) is not str:
        return
    try:
        exception_namespace = type(_exception_dict_descriptor).__get__(
            _exception_dict_descriptor,
            primary,
            BaseException,
        )
    except BaseException:
        return
    if type(exception_namespace) is not dict:
        return
    note = f"additional {action} failure was suppressed during provider cleanup"
    if not dict.__contains__(exception_namespace, "__notes__"):
        dict.__setitem__(exception_namespace, "__notes__", [note])
        return
    notes = dict.get(exception_namespace, "__notes__")
    if type(notes) is not list:
        return
    for existing_note in list.__iter__(notes):
        if type(existing_note) is not str:
            return
    list.append(notes, note)


def _retain_provider_failure(
    primary_exception: BaseException | None,
    new_failure: BaseException,
    *,
    description: str,
) -> BaseException:
    """Retain the exact first failure and annotate each later failure."""

    if primary_exception is None:
        return new_failure
    _note_cleanup_failure(primary_exception, description)
    return primary_exception


def _clear_runtime_cache_values(
    values: list[tuple[dict[str, Any], str, Any]],
    cached_callables: list[Any],
    *,
    primary_exception: BaseException | None = None,
) -> BaseException | None:
    """Attempt every cache clear and retain the exact first failure."""

    retained_failure = primary_exception
    for namespace, name, value in values:
        try:
            if type(value) is _CoordinatedRuntimeCacheValue:
                value.clear_operation(value.controller)
            else:
                dict.__setitem__(namespace, name, None)
        except BaseException as clear_failure:
            retained_failure = _retain_provider_failure(
                retained_failure,
                clear_failure,
                description="runtime-cache clearing",
            )
    for value in cached_callables:
        try:
            if type(value) is functools._lru_cache_wrapper:
                functools._lru_cache_wrapper.cache_clear(value)
            else:
                value.cache_clear()
        except BaseException as clear_failure:
            retained_failure = _retain_provider_failure(
                retained_failure,
                clear_failure,
                description="derived-cache clearing",
            )
    return retained_failure


def _clear_runtime_caches() -> None:
    """Clear loaded raw and derived caches before reading a provider snapshot."""

    with _CONFIG_SCOPE_LEASE.hold(), _CONFIG_EXECUTION_LOCK:
        saved = _cache_globals()
        cached_callables = _cached_callables()
        clear_failure = _clear_runtime_cache_values(saved, cached_callables)
        if clear_failure is not None:
            rollback_values, rollback_discovery_failure = _cache_globals_for_clear()
            retained_failure = clear_failure
            if rollback_discovery_failure is not None:
                retained_failure = _retain_provider_failure(
                    retained_failure,
                    rollback_discovery_failure,
                    description="runtime-cache rollback discovery",
                )
            saved_keys = {(id(namespace), name) for namespace, name, _value in saved}
            late_values = [
                value for value in rollback_values if (id(value[0]), value[1]) not in saved_keys
            ]
            retained_failure = _clear_runtime_cache_values(
                late_values,
                [],
                primary_exception=retained_failure,
            )
            retained_failure = _restore_runtime_caches(
                saved,
                primary_exception=retained_failure,
            )
            raise retained_failure


def _restore_runtime_caches(
    saved: list[tuple[dict[str, Any], str, Any]],
    *,
    primary_exception: BaseException | None = None,
) -> BaseException | None:
    """Best-effort restore every snapshot while preserving primary-exception priority."""

    retained_failure = primary_exception
    for namespace, name, value in saved:
        try:
            if type(value) is _CoordinatedRuntimeCacheValue:
                if dict.get(namespace, name) is not value.controller:
                    retained_failure = _retain_provider_failure(
                        retained_failure,
                        RuntimeError("runtime cache coordinator was replaced during scope"),
                        description="runtime-cache restoration",
                    )
                dict.__setitem__(namespace, name, value.controller)
                value.restore_operation(value.controller, value.snapshot)
            else:
                dict.__setitem__(namespace, name, value)
        except BaseException as restore_failure:
            retained_failure = _retain_provider_failure(
                retained_failure,
                restore_failure,
                description="runtime-cache restoration",
            )
    return retained_failure


def _run_provider_cleanup_action(
    action: Callable[[], None],
    primary_exception: BaseException | None,
    *,
    description: str,
) -> BaseException | None:
    """Run one cleanup action, retaining the first BaseException exactly."""

    try:
        action()
    except BaseException as cleanup_failure:
        return _retain_provider_failure(
            primary_exception,
            cleanup_failure,
            description=description,
        )
    return primary_exception


def _require_runtime_module_anchor(owner: _RuntimeModuleAnchor) -> None:
    """Require that one anchored module still owns its canonical registry slot."""

    modules = ModuleType.__getattribute__(sys, "modules")
    if type(modules) is not dict:
        raise RuntimeError("runtime module registry must be a builtin mapping")
    if dict.get(modules, owner.name) is not owner.module:
        raise RuntimeError("anchored runtime module was replaced")
    namespace = ModuleType.__getattribute__(owner.module, "__dict__")
    if type(namespace) is not dict or namespace is not owner.namespace:
        raise RuntimeError("anchored runtime module namespace was replaced")


def _prepare_legacy_registry_module(
    _get_network_anchor: Callable[[], _RuntimeModuleAnchor | None] = (
        _get_legacy_network_module_anchor
    ),
) -> _RuntimeModuleAnchor:
    """Complete first import and logging callbacks before provider serialization."""

    imported = importlib.import_module(_LEGACY_NETWORK_MODULE_NAME)
    owner = _get_network_anchor()
    if owner is None or imported is not owner.module:
        raise RuntimeError("legacy network module is not registered")
    _require_runtime_module_anchor(owner)
    return owner


def _prepare_legacy_registry_values(
    effective_config: Any,
    owner: _RuntimeModuleAnchor,
) -> _PreparedLegacyRegistryGlobals:
    """Build detached inner DNS values while logging and merge callbacks are lock-free."""

    required_fields = (
        "ambient_overlay_compat",
        "packaged_defaults",
        "project_overlays",
    )
    if not all(hasattr(effective_config, name) for name in required_fields):
        snapshot = _snapshot_legacy_registry_globals(owner)
        return _PreparedLegacyRegistryGlobals(
            reverse_dns=dict.copy(snapshot.reverse_dns),
            forward_dns=dict.copy(snapshot.forward_dns),
            external_ips={key: list(value) for key, value in dict.items(snapshot.external_ips)},
            cdn_ranges=list.copy(snapshot.cdn_ranges),
            ipv6_map=dict.copy(snapshot.ipv6_map),
        )

    modules = ModuleType.__getattribute__(sys, "modules")
    if type(modules) is not dict:
        raise RuntimeError("runtime module registry must be a builtin mapping")
    dns_module = dict.get(modules, "evidenceforge.generation.activity.dns_registry")
    if type(dns_module) is not ModuleType:
        raise RuntimeError("legacy DNS registry module is not an exact module")
    dns_namespace = ModuleType.__getattribute__(dns_module, "__dict__")
    if type(dns_namespace) is not dict:
        raise RuntimeError("legacy DNS registry namespace must be a builtin mapping")
    load_with_overlay_operation = dict.get(dns_namespace, "load_with_overlay")
    merge_operation = dict.get(dns_namespace, "_merge_dns_registry")
    registry_path = dict.get(dns_namespace, "_REGISTRY_PATH")
    if (
        type(load_with_overlay_operation) is not FunctionType
        or type(merge_operation) is not FunctionType
    ):
        raise RuntimeError("legacy DNS registry loader binding was replaced")

    token = _CURRENT_EFFECTIVE_CONFIG.set(effective_config)
    try:
        data = load_with_overlay_operation(
            registry_path,
            "activity/dns_registry.yaml",
            merge_operation,
        )
    finally:
        _CURRENT_EFFECTIVE_CONFIG.reset(token)
    if type(data) is not dict:
        raise RuntimeError("legacy DNS registry must be a mapping")

    reverse_dns: dict[str, str] = {}
    forward_dns: dict[str, str] = {}
    domains_by_tag: dict[str, list[dict[str, Any]]] = {}
    for entry in data.get("domains", []):
        domain = entry["domain"]
        ips = entry["ips"]
        if ips:
            forward_dns[domain] = ips[0]
        for ip in ips:
            reverse_dns.setdefault(ip, domain)
        for tag in entry.get("tags", []):
            domains_by_tag.setdefault(tag, []).append(entry)

    tag_to_activity = dict.get(owner.namespace, "_TAG_TO_ACTIVITY")
    if type(tag_to_activity) is not dict:
        raise RuntimeError("legacy network activity tags were replaced")
    external_ips: dict[str, list[str]] = {}
    for activity_type, tag in dict.items(tag_to_activity):
        ips = [ip for entry in domains_by_tag.get(tag, []) for ip in entry["ips"]]
        external_ips[activity_type] = list(dict.fromkeys(ips))
    return _PreparedLegacyRegistryGlobals(
        reverse_dns=reverse_dns,
        forward_dns=forward_dns,
        external_ips=external_ips,
        cdn_ranges=[tuple(value) for value in data.get("cdn_ranges", [])],
        ipv6_map=dict(data.get("ipv6_map", {})),
    )


def _snapshot_legacy_registry_globals(
    owner: _RuntimeModuleAnchor,
) -> _LegacyRegistryGlobalsSnapshot:
    """Snapshot all mutable legacy DNS exports from one exact prepared module."""

    _require_runtime_module_anchor(owner)
    namespace = owner.namespace
    reverse_dns = dict.get(namespace, "REVERSE_DNS")
    forward_dns = dict.get(namespace, "FORWARD_DNS")
    external_ips = dict.get(namespace, "EXTERNAL_IPS")
    cdn_ranges = dict.get(namespace, "_CDN_RANGES")
    ipv6_map = dict.get(namespace, "_IPV6_MAP")
    if (
        type(reverse_dns) is not dict
        or type(forward_dns) is not dict
        or type(external_ips) is not dict
        or type(cdn_ranges) is not list
        or type(ipv6_map) is not dict
    ):
        raise RuntimeError("legacy network registry globals must use builtin containers")
    return _LegacyRegistryGlobalsSnapshot(
        owner=owner,
        reverse_dns=reverse_dns,
        reverse_dns_items=dict.copy(reverse_dns),
        forward_dns=forward_dns,
        forward_dns_items=dict.copy(forward_dns),
        external_ips=external_ips,
        external_ips_items=dict.copy(external_ips),
        cdn_ranges=cdn_ranges,
        cdn_range_items=list.copy(cdn_ranges),
        ipv6_map=ipv6_map,
        ipv6_map_items=dict.copy(ipv6_map),
    )


def _restore_legacy_registry_dict(
    snapshot: _LegacyRegistryGlobalsSnapshot,
    name: str,
    target: dict[Any, Any],
    items: dict[Any, Any],
    cleanup_pins: list[Any],
) -> None:
    """Rebind and restore one mapping while retaining displaced values."""

    cleanup_pins.append(dict.get(snapshot.owner.namespace, name))
    cleanup_pins.append(dict.copy(target))
    dict.__setitem__(snapshot.owner.namespace, name, target)
    dict.clear(target)
    dict.update(target, items)


def _restore_legacy_registry_list(
    snapshot: _LegacyRegistryGlobalsSnapshot,
    name: str,
    target: list[Any],
    items: list[Any],
    cleanup_pins: list[Any],
) -> None:
    """Rebind and restore one list while retaining displaced values."""

    cleanup_pins.append(dict.get(snapshot.owner.namespace, name))
    cleanup_pins.append(list.copy(target))
    dict.__setitem__(snapshot.owner.namespace, name, target)
    list.clear(target)
    list.extend(target, items)


def _restore_legacy_registry_globals(
    snapshot: _LegacyRegistryGlobalsSnapshot | None,
    cleanup_pins: list[Any],
    *,
    primary_exception: BaseException | None = None,
) -> BaseException | None:
    """Best-effort restore every legacy DNS binding, identity, and exact contents."""

    if snapshot is None:
        return primary_exception
    retained_failure = primary_exception
    actions: tuple[Callable[[], None], ...] = (
        lambda: _restore_legacy_registry_dict(
            snapshot,
            "REVERSE_DNS",
            snapshot.reverse_dns,
            snapshot.reverse_dns_items,
            cleanup_pins,
        ),
        lambda: _restore_legacy_registry_dict(
            snapshot,
            "FORWARD_DNS",
            snapshot.forward_dns,
            snapshot.forward_dns_items,
            cleanup_pins,
        ),
        lambda: _restore_legacy_registry_dict(
            snapshot,
            "EXTERNAL_IPS",
            snapshot.external_ips,
            snapshot.external_ips_items,
            cleanup_pins,
        ),
        lambda: _restore_legacy_registry_list(
            snapshot,
            "_CDN_RANGES",
            snapshot.cdn_ranges,
            snapshot.cdn_range_items,
            cleanup_pins,
        ),
        lambda: _restore_legacy_registry_dict(
            snapshot,
            "_IPV6_MAP",
            snapshot.ipv6_map,
            snapshot.ipv6_map_items,
            cleanup_pins,
        ),
    )
    for action in actions:
        retained_failure = _run_provider_cleanup_action(
            action,
            retained_failure,
            description="legacy registry restoration",
        )
    return retained_failure


def _merge_runtime_cache_values(
    current: list[tuple[dict[str, Any], str, Any]],
    entry: list[tuple[dict[str, Any], str, Any]],
) -> list[tuple[dict[str, Any], str, Any]]:
    """Keep current targets first and retain entry targets missing from the rescan."""

    merged = list(current)
    seen = {(id(namespace), name) for namespace, name, _value in current}
    merged.extend(value for value in entry if (id(value[0]), value[1]) not in seen)
    return merged


def _merge_cached_callables(current: list[Any], entry: list[Any]) -> list[Any]:
    """Deduplicate current and entry callable cache targets by exact identity."""

    merged = list(current)
    seen = {id(value) for value in current}
    merged.extend(value for value in entry if id(value) not in seen)
    return merged


def _refresh_legacy_registry_globals(
    owner: _RuntimeModuleAnchor,
    prepared: _PreparedLegacyRegistryGlobals,
) -> None:
    """Refresh imported-by-value DNS globals from the active provider snapshot."""

    _require_runtime_module_anchor(owner)
    snapshot = _snapshot_legacy_registry_globals(owner)
    dict.clear(snapshot.reverse_dns)
    dict.update(snapshot.reverse_dns, prepared.reverse_dns)
    dict.clear(snapshot.forward_dns)
    dict.update(snapshot.forward_dns, prepared.forward_dns)
    dict.clear(snapshot.external_ips)
    dict.update(snapshot.external_ips, prepared.external_ips)
    list.__setitem__(snapshot.cdn_ranges, slice(None), prepared.cdn_ranges)
    dict.clear(snapshot.ipv6_map)
    dict.update(snapshot.ipv6_map, prepared.ipv6_map)


def _prepare_effective_timing_profiles(
    effective_config: Any,
    _get_anchor: Callable[[], _TimingProfileRuntimeCacheAnchor | None] = (
        _get_timing_profile_runtime_cache_anchor
    ),
    _effective_context: ContextVar[Any | None] = _CURRENT_EFFECTIVE_CONFIG,
    _import_module: Callable[[str], ModuleType] = importlib.import_module,
    _require_owner: Callable[[_RuntimeModuleAnchor], None] = _require_runtime_module_anchor,
) -> _PreparedEffectiveTimingProfiles | None:
    """Prepare and prewarn one real EffectiveConfig outside provider serialization."""

    required_fields = (
        "ambient_overlay_compat",
        "packaged_defaults",
        "project_overlays",
    )
    if not all(hasattr(effective_config, name) for name in required_fields):
        return None
    imported = _import_module(_TIMING_PROFILE_MODULE_NAME)
    anchor = _get_anchor()
    if anchor is None or imported is not anchor.owner.module:
        raise RuntimeError("timing profile runtime module is not registered")
    _require_owner(anchor.owner)
    prepare_operation = dict.get(
        anchor.owner.namespace,
        "_prepare_timing_profiles_for_active_provider",
    )
    validator_operation = dict.get(
        anchor.owner.namespace,
        "_prepared_timing_profiles_are_current",
    )
    if type(prepare_operation) is not FunctionType or type(validator_operation) is not FunctionType:
        raise RuntimeError("timing profile preparation operations were replaced")

    token = _effective_context.set(effective_config)
    try:
        prepared = prepare_operation()
    finally:
        _effective_context.reset(token)
    _require_owner(anchor.owner)
    if (
        dict.get(anchor.owner.namespace, "_prepare_timing_profiles_for_active_provider")
        is not prepare_operation
        or dict.get(anchor.owner.namespace, "_prepared_timing_profiles_are_current")
        is not validator_operation
    ):
        raise RuntimeError("timing profile preparation operations were replaced")
    return _PreparedEffectiveTimingProfiles(
        owner=anchor.owner,
        value=prepared,
        prepare_operation=prepare_operation,
        validator_operation=validator_operation,
    )


def _prepared_effective_timing_profiles_are_current(
    prepared: _PreparedEffectiveTimingProfiles | None,
    _prepared_type: type[_PreparedEffectiveTimingProfiles] = _PreparedEffectiveTimingProfiles,
    _require_owner: Callable[[_RuntimeModuleAnchor], None] = _require_runtime_module_anchor,
    _object_getattribute: Callable[[Any, str], Any] = object.__getattribute__,
) -> bool:
    """Return whether one scope-entry preparation survived concurrent rollback."""

    if prepared is None:
        return True
    if type(prepared) is not _prepared_type:
        raise TypeError("effective timing preparation has invalid type")
    owner = _object_getattribute(prepared, "owner")
    prepare_operation = _object_getattribute(prepared, "prepare_operation")
    validator_operation = _object_getattribute(prepared, "validator_operation")
    value = _object_getattribute(prepared, "value")
    _require_owner(owner)
    if (
        dict.get(owner.namespace, "_prepare_timing_profiles_for_active_provider")
        is not prepare_operation
        or dict.get(owner.namespace, "_prepared_timing_profiles_are_current")
        is not validator_operation
    ):
        raise RuntimeError("timing profile preparation operations were replaced")
    return validator_operation(value)


@contextmanager
def effective_config_scope(
    effective_config: Any,
    *,
    refresh_legacy_globals: bool = True,
) -> Iterator[None]:
    """Activate one provider with serialized legacy-cache compatibility.

    The reentrant scope lease makes old module-global caches safe while they are
    progressively migrated. Concurrent callers cannot leak configuration: each
    run receives a clean cache namespace and the previous process state is restored.

    Args:
        effective_config: Immutable configuration snapshot to activate.
        refresh_legacy_globals: Refresh imported-by-value DNS registries at the
            scope boundary. Validation preflight disables this because malformed
            user configuration must be reported before any derived registry loads.
    """

    prepare_timing_profiles = _prepare_effective_timing_profiles
    validate_timing_preparation = _prepared_effective_timing_profiles_are_current
    prepared_network: _RuntimeModuleAnchor | None = None
    prepared_legacy_registry: _PreparedLegacyRegistryGlobals | None = None
    prepared_timing_profiles: _PreparedEffectiveTimingProfiles | None = None
    while True:
        with _CONFIG_SCOPE_LEASE.suspend_current():
            if refresh_legacy_globals and prepared_network is None:
                prepared_network = _prepare_legacy_registry_module()
                prepared_legacy_registry = _prepare_legacy_registry_values(
                    effective_config,
                    prepared_network,
                )
            prepared_timing_profiles = prepare_timing_profiles(effective_config)
        _CONFIG_SCOPE_LEASE.acquire()
        try:
            preparation_is_current = validate_timing_preparation(prepared_timing_profiles)
        except BaseException:
            _CONFIG_SCOPE_LEASE.release()
            raise
        if preparation_is_current:
            break
        _CONFIG_SCOPE_LEASE.release()

    # The contextmanager frame pins this scope's displaced values. Release transfers
    # them to the lease across nested scopes and returns them only after depth zero.
    legacy_registry_cleanup_pins: list[Any] = []
    try:
        legacy_registry_snapshot: _LegacyRegistryGlobalsSnapshot | None = None
        with _CONFIG_EXECUTION_LOCK:
            if refresh_legacy_globals:
                if prepared_network is None:  # pragma: no cover - guarded by preparation
                    raise RuntimeError("legacy network module was not prepared")
                legacy_registry_snapshot = _snapshot_legacy_registry_globals(prepared_network)
            saved = _cache_globals()
            cached_callables = _cached_callables()
            clear_failure = _clear_runtime_cache_values(saved, cached_callables)
            if clear_failure is not None:
                rollback_values, rollback_discovery_failure = _cache_globals_for_clear()
                retained_failure = clear_failure
                if rollback_discovery_failure is not None:
                    retained_failure = _retain_provider_failure(
                        retained_failure,
                        rollback_discovery_failure,
                        description="runtime-cache rollback discovery",
                    )
                saved_keys = {(id(namespace), name) for namespace, name, _value in saved}
                late_values = [
                    value for value in rollback_values if (id(value[0]), value[1]) not in saved_keys
                ]
                retained_failure = _clear_runtime_cache_values(
                    late_values,
                    [],
                    primary_exception=retained_failure,
                )
                retained_failure = _restore_runtime_caches(
                    saved,
                    primary_exception=retained_failure,
                )
                retained_failure = _restore_legacy_registry_globals(
                    legacy_registry_snapshot,
                    legacy_registry_cleanup_pins,
                    primary_exception=retained_failure,
                )
                raise retained_failure

        token: Any | None = None
        timing_token: Any | None = None
        try:
            with _CONFIG_EXECUTION_LOCK:
                token = _CURRENT_EFFECTIVE_CONFIG.set(effective_config)
                timing_token = _CURRENT_PREPARED_TIMING_PROFILES.set(
                    None if prepared_timing_profiles is None else prepared_timing_profiles.value
                )
                if refresh_legacy_globals:
                    if (
                        prepared_network is None or prepared_legacy_registry is None
                    ):  # pragma: no cover - guarded by preparation
                        raise RuntimeError("legacy network module was not prepared")
                    _refresh_legacy_registry_globals(
                        prepared_network,
                        prepared_legacy_registry,
                    )
            yield
        finally:
            body_exception = sys.exception()
            cleanup_exception = body_exception
            with _CONFIG_EXECUTION_LOCK:
                if timing_token is not None:
                    cleanup_exception = _run_provider_cleanup_action(
                        lambda: _CURRENT_PREPARED_TIMING_PROFILES.reset(timing_token),
                        cleanup_exception,
                        description="prepared timing context reset",
                    )
                if token is not None:
                    cleanup_exception = _run_provider_cleanup_action(
                        lambda: _CURRENT_EFFECTIVE_CONFIG.reset(token),
                        cleanup_exception,
                        description="effective config context reset",
                    )
                cleanup_values = saved
                cleanup_callables = cached_callables
                try:
                    discovered_values, discovery_failure = _cache_globals_for_clear()
                    cleanup_values = _merge_runtime_cache_values(
                        discovered_values,
                        saved,
                    )
                    if discovery_failure is not None:
                        cleanup_exception = _retain_provider_failure(
                            cleanup_exception,
                            discovery_failure,
                            description="runtime-cache rescan",
                        )
                except BaseException as discovery_failure:
                    cleanup_exception = _retain_provider_failure(
                        cleanup_exception,
                        discovery_failure,
                        description="runtime-cache rescan",
                    )
                try:
                    discovered_callables, discovery_failure = _cached_callables_for_clear()
                    cleanup_callables = _merge_cached_callables(
                        discovered_callables,
                        cached_callables,
                    )
                    if discovery_failure is not None:
                        cleanup_exception = _retain_provider_failure(
                            cleanup_exception,
                            discovery_failure,
                            description="derived-cache rescan",
                        )
                except BaseException as discovery_failure:
                    cleanup_exception = _retain_provider_failure(
                        cleanup_exception,
                        discovery_failure,
                        description="derived-cache rescan",
                    )
                cleanup_exception = _clear_runtime_cache_values(
                    cleanup_values,
                    cleanup_callables,
                    primary_exception=cleanup_exception,
                )
                cleanup_exception = _restore_runtime_caches(
                    saved,
                    primary_exception=cleanup_exception,
                )
                cleanup_exception = _restore_legacy_registry_globals(
                    legacy_registry_snapshot,
                    legacy_registry_cleanup_pins,
                    primary_exception=cleanup_exception,
                )
            if body_exception is None and cleanup_exception is not None:
                raise cleanup_exception
    finally:
        scope_failure = sys.exception()
        try:
            _CONFIG_SCOPE_LEASE.release(legacy_registry_cleanup_pins)
        except BaseException:
            if scope_failure is None:
                raise
            _note_cleanup_failure(scope_failure, "provider lease release")
