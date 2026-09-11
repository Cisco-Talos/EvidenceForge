# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Per-role baseline system process generation for Windows hosts.

Loads system_processes.yaml and provides functions to pick diverse
scheduled tasks and system service processes by host role.
"""

import random
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.schemas import ScheduledTaskEntry, SystemServiceEntry
from evidenceforge.events.content_identity import (
    CompiledServiceDeploymentIdentity,
    CompiledTaskDeploymentIdentity,
    Platform,
    canonical_native_path,
)
from evidenceforge.utils.rng import _stable_seed

_PROCESSES_PATH = get_activity_directory() / "system_processes.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_system_processes(default: dict, overlay: dict) -> dict:
    """Merge system processes overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_system_processes() -> dict[str, Any]:
    """Load system process configurations from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _PROCESSES_PATH,
        "activity/system_processes.yaml",
        _merge_system_processes,
    )
    return _CACHED_DATA


_CACHED_BINARY_EXES: set[str] | None = None
_CACHED_BINARY_PATHS: dict[str, str] | None = None
_CACHED_SINGLETON_SERVICE_PATHS: dict[str, set[str]] | None = None
_CACHED_NATIVE_BINARY_DESCRIPTORS: (
    dict[Platform, tuple["NativeSystemBinaryDescriptor", ...]] | None
) = None
_CACHED_SCHEDULED_TASK_DESCRIPTORS: tuple[ScheduledTaskEntry, ...] | None = None
_CACHED_SYSTEM_SERVICE_DESCRIPTORS: dict[str, tuple[SystemServiceEntry, ...]] | None = None
_CACHED_SCHEDULED_TASK_BY_ID: dict[str, ScheduledTaskEntry] | None = None
_CACHED_SYSTEM_SERVICE_BY_ID: dict[str, SystemServiceEntry] | None = None
_CACHED_SCHEDULED_TASK_ORDINAL_BY_ID: dict[str, int] | None = None
_CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID: dict[str, tuple[str, int]] | None = None


@dataclass(frozen=True, slots=True)
class NativeSystemBinaryDescriptor:
    """Typed catalog descriptor for one path-independent native binary identity."""

    platform: Platform
    exe: str
    path: str
    product_id: str
    variant: str
    release_policy: str = "host_build"
    distro: str = ""
    system_types: tuple[str, ...] = ()
    roles_any: tuple[str, ...] = ()
    services_any: tuple[str, ...] = ()
    description: str = ""
    product: str = ""
    company: str = ""
    original_filename: str = ""

    def __post_init__(self) -> None:
        """Normalize exact native placement and reject incomplete identity metadata."""

        for field_name in ("exe", "path", "product_id", "variant", "release_policy"):
            value = str(getattr(self, field_name)).strip()
            if not value:
                raise ValueError(f"native system binary {field_name} must not be empty")
            object.__setattr__(self, field_name, value)
        metadata = tuple(
            str(getattr(self, field_name)).strip()
            for field_name in ("description", "product", "company", "original_filename")
        )
        if any(metadata) and not all(metadata):
            raise ValueError("native system binary VERSIONINFO metadata must be complete")
        for field_name, value in zip(
            ("description", "product", "company", "original_filename"),
            metadata,
            strict=True,
        ):
            object.__setattr__(self, field_name, value)
        if self.original_filename:
            if "/" in self.original_filename or "\\" in self.original_filename:
                raise ValueError("native system binary original_filename must not be a path")
            expected_exe = self.exe.casefold() if self.platform == "windows" else self.exe
            original = (
                self.original_filename.casefold()
                if self.platform == "windows"
                else self.original_filename
            )
            if expected_exe != original:
                raise ValueError(
                    "native system binary exe and original_filename must identify the same artifact"
                )
        if self.release_policy not in {"host_build", "unspecified"}:
            raise ValueError(
                "native system binary release_policy must be host_build or unspecified"
            )
        if self.has_pe_version_info and self.release_policy != "host_build":
            raise ValueError("native system binary VERSIONINFO requires host_build policy")
        distro = self.distro.strip().casefold()
        if distro not in {"", "all", "debian", "rhel"}:
            raise ValueError("native system binary distro must be all, debian, or rhel")
        if distro and self.platform != "linux":
            raise ValueError("native system binary distro placement is valid only for Linux")
        object.__setattr__(self, "distro", distro)
        for field_name in ("system_types", "roles_any", "services_any"):
            raw_values = tuple(getattr(self, field_name))
            normalized_values = tuple(
                sorted(
                    {str(value).strip().casefold() for value in raw_values if str(value).strip()}
                )
            )
            if len(normalized_values) != len(raw_values):
                raise ValueError(
                    f"native system binary {field_name} must contain unique non-empty values"
                )
            object.__setattr__(self, field_name, normalized_values)
        if not set(self.system_types).issubset({"workstation", "server", "domain_controller"}):
            raise ValueError(
                "native system binary system_types must be workstation, server, or "
                "domain_controller"
            )
        if (self.system_types or self.roles_any or self.services_any) and self.platform != "linux":
            raise ValueError("native system binary placement selectors are valid only for Linux")
        object.__setattr__(self, "product_id", self.product_id.casefold())
        object.__setattr__(self, "variant", self.variant.casefold())
        canonical_native_path(self.path, self.platform)

    @property
    def has_pe_version_info(self) -> bool:
        """Return whether exact authored Windows VERSIONINFO is available."""

        return bool(self.original_filename)

    @property
    def has_explicit_placement(self) -> bool:
        """Return whether this descriptor proves host-specific installation."""

        return bool(self.system_types or self.roles_any or self.services_any)


@dataclass(frozen=True, slots=True)
class CompiledScheduledTaskMaterialization:
    """One exact compiled task descriptor after host-specific rendering."""

    deployment_identity: CompiledTaskDeploymentIdentity
    image_path: str
    command_line: str
    parent_key: str

    @property
    def task_id(self) -> str:
        """Return the exact compiler-owned task ID."""

        return self.deployment_identity.task_id


@dataclass(frozen=True, slots=True)
class CompiledSystemServiceMaterialization:
    """One exact compiled service descriptor after host-specific rendering."""

    deployment_identity: CompiledServiceDeploymentIdentity
    image_path: str
    command_line: str
    parent_key: str

    @property
    def service_id(self) -> str:
        """Return the exact compiler-owned service ID."""

        return self.deployment_identity.service_id


def get_native_system_binary_descriptors(
    platform: Platform,
) -> tuple[NativeSystemBinaryDescriptor, ...]:
    """Return exact native binary descriptors for one platform.

    Every repository binary has an explicit host-build release policy. Exact
    authored VERSIONINFO remains optional and is never inferred from a path.
    """

    global _CACHED_NATIVE_BINARY_DESCRIPTORS
    if _CACHED_NATIVE_BINARY_DESCRIPTORS is None:
        _CACHED_NATIVE_BINARY_DESCRIPTORS = {}
    cached = _CACHED_NATIVE_BINARY_DESCRIPTORS.get(platform)
    if cached is not None:
        return cached
    entries = load_system_processes().get("system_binaries", {}).get(platform, ())
    descriptors: list[NativeSystemBinaryDescriptor] = []
    seen_paths: set[str] = set()
    for entry in entries:
        release = entry.get("native_release") if isinstance(entry, dict) else None
        release = release if isinstance(release, dict) else {}
        release_policy = str(entry.get("release_policy") or "")
        fallback_product = {
            "windows": "microsoft-windows",
            "linux": "linux-host",
            "macos": "macos-host",
        }[platform]
        if release_policy == "unspecified":
            normalized_exe = "".join(
                character if character.isalnum() or character in ".-_" else "-"
                for character in str(entry.get("exe") or "").casefold()
            )
            fallback_product = f"legacy-native.{platform}.{normalized_exe}"
        descriptor = NativeSystemBinaryDescriptor(
            platform=platform,
            exe=str(entry.get("exe") or ""),
            path=str(entry.get("path") or ""),
            product_id=str(release.get("product_id") or fallback_product),
            variant=str(
                release.get("variant")
                or ("legacy-native" if release_policy == "unspecified" else "core-os")
            ),
            release_policy=release_policy,
            distro=str(entry.get("distro") or ""),
            system_types=tuple(entry.get("system_types") or ()),
            roles_any=tuple(entry.get("roles_any") or ()),
            services_any=tuple(entry.get("services_any") or ()),
            description=str(release.get("description") or ""),
            product=str(release.get("product") or ""),
            company=str(release.get("company") or ""),
            original_filename=str(release.get("original_filename") or ""),
        )
        native_path = canonical_native_path(descriptor.path, platform)
        if native_path in seen_paths:
            raise ValueError(
                f"duplicate native system binary descriptor path for {platform}: {descriptor.path!r}"
            )
        seen_paths.add(native_path)
        descriptors.append(descriptor)
    result = tuple(sorted(descriptors, key=lambda item: canonical_native_path(item.path, platform)))
    _CACHED_NATIVE_BINARY_DESCRIPTORS[platform] = result
    return result


def get_system_binary_exes() -> set[str]:
    """Return the set of all system binary exe names (both OSes).

    Reads from the ``system_binaries`` section of system_processes.yaml
    (including overlay). This replaces the hardcoded ``_SYSTEM_BINARIES``
    frozenset that was previously in application_catalog.py.
    """
    global _CACHED_BINARY_EXES
    if _CACHED_BINARY_EXES is not None:
        return _CACHED_BINARY_EXES

    data = load_system_processes()
    exes: set[str] = set()
    for os_binaries in data.get("system_binaries", {}).values():
        if isinstance(os_binaries, list):
            for entry in os_binaries:
                exe = entry.get("exe", "")
                if exe:
                    exes.add(exe)
    _CACHED_BINARY_EXES = exes
    return exes


def get_system_binary_path(
    exe_name: str,
    username: str | None = None,
    host: Any | None = None,
) -> str | None:
    """Look up the full image path for a system binary by exe name.

    Case-insensitive lookup. Resolves ``{username}`` placeholders if
    username is provided, consistent with catalog path resolution.

    Returns None if not found.
    """
    global _CACHED_BINARY_PATHS
    if _CACHED_BINARY_PATHS is None:
        data = load_system_processes()
        paths: dict[str, str] = {}
        for os_binaries in data.get("system_binaries", {}).values():
            if isinstance(os_binaries, list):
                for entry in os_binaries:
                    exe = entry.get("exe", "")
                    path = entry.get("path", "")
                    if exe and path:
                        paths[exe.lower()] = path
        _CACHED_BINARY_PATHS = paths

    path = _CACHED_BINARY_PATHS.get(exe_name.lower())
    if path and "{username}" in path:
        if username:
            path = path.replace("{username}", username)
        else:
            # No username context — return None to let caller fall back
            return None
    if path:
        path = _resolve_host_placeholders(path, host)
    return path


def get_windows_singleton_service_paths() -> dict[str, set[str]]:
    """Return Windows service-process paths that should be singleton per host.

    The keys and path values are normalized to lowercase backslash paths. Entries
    are driven by ``system_services`` records with ``singleton: true`` so
    endpoint-agent lifecycle policy stays with the service catalog.
    """
    global _CACHED_SINGLETON_SERVICE_PATHS
    if _CACHED_SINGLETON_SERVICE_PATHS is not None:
        return _CACHED_SINGLETON_SERVICE_PATHS

    data = load_system_processes()
    singleton_paths: dict[str, set[str]] = {}
    for entries in data.get("system_services", {}).values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("singleton"):
                continue
            image = str(entry.get("image") or "").replace("/", "\\").lower()
            if not image:
                continue
            exe_name = image.rsplit("\\", 1)[-1]
            singleton_paths.setdefault(exe_name, set()).add(image)

    _CACHED_SINGLETON_SERVICE_PATHS = singleton_paths
    return singleton_paths


def _resolve_template(template: str, rng: random.Random, entry_params: dict | None) -> str:
    """Resolve {placeholder} tokens in a command template."""
    result = template
    if not entry_params:
        return result
    for key, values in entry_params.items():
        token = "{" + key + "}"
        while token in result:
            result = result.replace(token, rng.choice(values), 1)
    return result


def _windows_servicing_stack_version(host: Any | None) -> str:
    """Return a plausible servicing-stack component version for a Windows host."""
    os_name = str(getattr(host, "os", "") or "").lower() if host is not None else ""
    system_type = str(getattr(host, "system_type", getattr(host, "type", "")) or "").lower()
    if "windows 11" in os_name:
        return "10.0.22621.3155"
    if "server" in os_name or system_type in {"server", "domain_controller"}:
        if "2019" in os_name:
            return "10.0.17763.5329"
        return "10.0.20348.2322"
    return "10.0.19041.3636"


def _host_local_search_sid(host: Any | None) -> str:
    """Return a stable host-local user SID for Windows Search pipe arguments."""
    hostname = str(getattr(host, "hostname", "") or "unknown").lower()
    ip = str(getattr(host, "ip", "") or "")
    seed = _stable_seed(f"windows_search_sid:{hostname}:{ip}")
    rng = random.Random(seed)
    authority = "-".join(str(rng.randint(100_000_000, 999_999_999)) for _ in range(3))
    rid = 1000 + (seed % 7000)
    return f"S-1-5-21-{authority}-{rid}"


def _resolve_host_placeholders(value: str, host: Any | None = None) -> str:
    """Resolve host-owned placeholders in system-process paths and commands."""
    resolved = value.replace(
        "{servicing_stack_version}",
        _windows_servicing_stack_version(host),
    )
    return resolved.replace("{host_local_search_sid}", _host_local_search_sid(host))


def _normalize_system_type(value: str | None) -> str:
    """Normalize scenario system types for config filtering."""
    return str(value or "").lower().replace("-", "_")


def _host_type_for_filter(host: Any | None) -> str:
    """Return the host type used for scheduled-task filtering."""
    return _normalize_system_type(
        getattr(host, "system_type", getattr(host, "type", "")) if host is not None else ""
    )


def _scheduled_task_allowed(entry: dict[str, Any], host: Any | None) -> bool:
    """Return whether a scheduled task is valid for the target host type."""
    allowed_types = entry.get("system_types")
    if not allowed_types:
        return True

    host_type = _host_type_for_filter(host)
    if not host_type:
        return True

    normalized_allowed = {_normalize_system_type(value) for value in allowed_types}
    return "all" in normalized_allowed or host_type in normalized_allowed


def scheduled_task_key(entry: dict[str, Any]) -> str:
    """Return a stable key for scheduled-task policy state."""
    if entry.get("id"):
        return str(entry["id"])
    templates = entry.get("command_templates") or []
    first_template = str(templates[0]) if templates else ""
    return f"{entry.get('image', '')}:{first_template}"


def _scheduled_task_descriptors() -> tuple[ScheduledTaskEntry, ...]:
    """Validate and cache repository/overlay task descriptors once."""

    global _CACHED_SCHEDULED_TASK_DESCRIPTORS
    global _CACHED_SCHEDULED_TASK_BY_ID
    global _CACHED_SCHEDULED_TASK_ORDINAL_BY_ID
    if _CACHED_SCHEDULED_TASK_DESCRIPTORS is None:
        descriptors = tuple(
            ScheduledTaskEntry.model_validate(entry)
            for entry in load_system_processes().get("scheduled_tasks", ())
        )
        by_id: dict[str, ScheduledTaskEntry] = {}
        for descriptor in descriptors:
            if descriptor.id is None:  # pragma: no cover - boundary normalizer supplies it
                raise ValueError("scheduled task deployment descriptor requires an id")
            if descriptor.id in by_id:
                raise ValueError(f"duplicate scheduled task deployment id {descriptor.id!r}")
            by_id[descriptor.id] = descriptor
        _CACHED_SCHEDULED_TASK_DESCRIPTORS = descriptors
        _CACHED_SCHEDULED_TASK_BY_ID = by_id
        _CACHED_SCHEDULED_TASK_ORDINAL_BY_ID = {
            descriptor.id: ordinal
            for ordinal, descriptor in enumerate(descriptors)
            if descriptor.id is not None
        }
    return _CACHED_SCHEDULED_TASK_DESCRIPTORS


def _system_service_descriptors() -> dict[str, tuple[SystemServiceEntry, ...]]:
    """Validate and cache repository/overlay service descriptors once."""

    global _CACHED_SYSTEM_SERVICE_DESCRIPTORS
    global _CACHED_SYSTEM_SERVICE_BY_ID
    global _CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID
    if _CACHED_SYSTEM_SERVICE_DESCRIPTORS is None:
        pools = {
            role: tuple(SystemServiceEntry.model_validate(entry) for entry in entries)
            for role, entries in load_system_processes().get("system_services", {}).items()
        }
        by_id: dict[str, SystemServiceEntry] = {}
        ordinal_by_id: dict[str, tuple[str, int]] = {}
        for role, descriptors in pools.items():
            for ordinal, descriptor in enumerate(descriptors):
                if descriptor.id is None:  # pragma: no cover - boundary normalizer supplies it
                    raise ValueError("system service deployment descriptor requires an id")
                if descriptor.id in by_id:
                    raise ValueError(f"duplicate system service deployment id {descriptor.id!r}")
                by_id[descriptor.id] = descriptor
                ordinal_by_id[descriptor.id] = (role, ordinal)
        _CACHED_SYSTEM_SERVICE_DESCRIPTORS = pools
        _CACHED_SYSTEM_SERVICE_BY_ID = by_id
        _CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID = ordinal_by_id
    return _CACHED_SYSTEM_SERVICE_DESCRIPTORS


def scheduled_task_descriptor(task_id: str) -> ScheduledTaskEntry | None:
    """Return one exact task descriptor without scanning the task catalog."""

    _scheduled_task_descriptors()
    assert _CACHED_SCHEDULED_TASK_BY_ID is not None
    return _CACHED_SCHEDULED_TASK_BY_ID.get(task_id.strip())


def system_service_descriptor(service_id: str) -> SystemServiceEntry | None:
    """Return one exact service descriptor without scanning service pools."""

    _system_service_descriptors()
    assert _CACHED_SYSTEM_SERVICE_BY_ID is not None
    return _CACHED_SYSTEM_SERVICE_BY_ID.get(service_id.strip())


def ordered_scheduled_task_descriptors(
    task_ids: Iterable[str],
) -> tuple[ScheduledTaskEntry, ...]:
    """Resolve exact deployed task IDs in legacy catalog-selection order.

    This keeps production selection deterministic without scanning the authored
    catalog for every host/hour. Unknown non-catalog task capabilities are
    ignored because they cannot be materialized as scheduled processes.
    """

    _scheduled_task_descriptors()
    assert _CACHED_SCHEDULED_TASK_BY_ID is not None
    assert _CACHED_SCHEDULED_TASK_ORDINAL_BY_ID is not None
    descriptors = {
        descriptor.id: descriptor
        for task_id in task_ids
        if (descriptor := _CACHED_SCHEDULED_TASK_BY_ID.get(task_id.strip())) is not None
    }
    return tuple(
        sorted(
            descriptors.values(),
            key=lambda descriptor: _CACHED_SCHEDULED_TASK_ORDINAL_BY_ID[descriptor.id or ""],
        )
    )


def ordered_system_service_descriptors(
    service_ids: Iterable[str],
    *,
    host_type: str,
) -> tuple[SystemServiceEntry, ...]:
    """Resolve exact deployed service IDs in legacy host-pool order.

    The old selector enumerated the common pool and then the host-role pool.
    Retaining that ordinal is important because a deterministic RNG choice over
    a reordered pool would select a different service even with the same seed.
    """

    _system_service_descriptors()
    assert _CACHED_SYSTEM_SERVICE_BY_ID is not None
    assert _CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID is not None
    normalized_host_type = _normalize_system_type(host_type or "workstation")
    selected: dict[str, SystemServiceEntry] = {}
    for service_id in service_ids:
        normalized_id = service_id.strip()
        descriptor = _CACHED_SYSTEM_SERVICE_BY_ID.get(normalized_id)
        if descriptor is None:
            continue
        role, _ordinal = _CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID[normalized_id]
        if role not in {"all", normalized_host_type}:
            continue
        selected[normalized_id] = descriptor

    def selection_key(descriptor: SystemServiceEntry) -> tuple[int, int]:
        role, ordinal = _CACHED_SYSTEM_SERVICE_ORDINAL_BY_ID[descriptor.id or ""]
        return (0 if role == "all" else 1, ordinal)

    return tuple(sorted(selected.values(), key=selection_key))


def materialize_catalog_image_path(image: str, host: Any | None = None) -> str:
    """Resolve host-owned tokens in one already-selected deployment image path."""

    return _resolve_host_placeholders(image, host)


def get_deployed_scheduled_task_descriptors(
    host: Any | None = None,
) -> tuple[ScheduledTaskEntry, ...]:
    """Return the deterministic installed task set for one exact host."""

    entries = tuple(
        entry
        for entry in _scheduled_task_descriptors()
        if not entry.system_types
        or not _host_type_for_filter(host)
        or "all" in {_normalize_system_type(value) for value in entry.system_types}
        or _host_type_for_filter(host)
        in {_normalize_system_type(value) for value in entry.system_types}
    )
    grouped_options: dict[str, set[str]] = {}
    host_scoped_groups: set[str] = set()
    for entry in entries:
        if entry.compatibility_group and entry.compatibility_option:
            grouped_options.setdefault(entry.compatibility_group, set()).add(
                entry.compatibility_option
            )
            if entry.compatibility_scope == "host":
                host_scoped_groups.add(entry.compatibility_group)
    hostname = str(getattr(host, "hostname", "default") or "default")
    selected_options = {
        group: random.Random(
            _stable_seed(
                f"software_deployment:{hostname if group in host_scoped_groups else 'default'}:"
                f"{group}"
            )
        ).choice(sorted(options))
        for group, options in grouped_options.items()
    }
    return tuple(
        entry
        for entry in entries
        if not entry.compatibility_group
        or selected_options.get(entry.compatibility_group) == entry.compatibility_option
    )


def get_scheduled_task_entries(host: Any | None = None) -> list[dict[str, Any]]:
    """Return scheduled-task config entries allowed for a host."""
    data = load_system_processes()
    entries = [
        entry for entry in data.get("scheduled_tasks", []) if _scheduled_task_allowed(entry, host)
    ]
    grouped_options: dict[str, set[str]] = {}
    host_scoped_groups: set[str] = set()
    for entry in entries:
        group = str(entry.get("compatibility_group") or "")
        option = str(entry.get("compatibility_option") or "")
        if group and option:
            grouped_options.setdefault(group, set()).add(option)
            if entry.get("compatibility_scope") == "host":
                host_scoped_groups.add(group)
    hostname = str(getattr(host, "hostname", "default") or "default")
    selected_options = {
        group: random.Random(
            _stable_seed(
                f"software_deployment:{hostname if group in host_scoped_groups else 'default'}:"
                f"{group}"
            )
        ).choice(sorted(options))
        for group, options in grouped_options.items()
    }
    return [
        entry
        for entry in entries
        if not entry.get("compatibility_group")
        or selected_options.get(str(entry["compatibility_group"]))
        == str(entry.get("compatibility_option") or "")
    ]


def materialize_scheduled_task_entry(
    entry: dict[str, Any],
    rng: random.Random,
    host: Any | None = None,
) -> tuple[str, str, str]:
    """Materialize one scheduled-task config entry."""
    cmd_template = rng.choice(entry["command_templates"])
    cmd = _resolve_template(cmd_template, rng, entry.get("params"))
    return (
        _resolve_host_placeholders(entry["image"], host),
        _resolve_host_placeholders(cmd, host),
        entry.get("parent", "services"),
    )


def materialize_scheduled_task_descriptor(
    entry: ScheduledTaskEntry,
    rng: random.Random,
    host: Any | None = None,
) -> tuple[str, str, str]:
    """Materialize one exact compiled task descriptor."""

    cmd_template = rng.choice(entry.command_templates)
    cmd = _resolve_template(cmd_template, rng, entry.params)
    return (
        _resolve_host_placeholders(entry.image, host),
        _resolve_host_placeholders(cmd, host),
        entry.parent,
    )


def materialize_compiled_scheduled_task_descriptor(
    entry: ScheduledTaskEntry,
    rng: random.Random,
    host: Any,
) -> CompiledScheduledTaskMaterialization:
    """Materialize one task while preserving its exact compiled host identity."""

    hostname = str(getattr(host, "hostname", "") or "").strip()
    if not hostname:
        raise ValueError("compiled scheduled task materialization requires a hostname")
    if entry.id is None:  # pragma: no cover - config boundary supplies stable IDs
        raise ValueError("compiled scheduled task materialization requires a task ID")
    image_path, command_line, parent_key = materialize_scheduled_task_descriptor(
        entry,
        rng,
        host,
    )
    return CompiledScheduledTaskMaterialization(
        deployment_identity=CompiledTaskDeploymentIdentity(
            hostname=hostname,
            task_id=entry.id,
        ),
        image_path=image_path,
        command_line=command_line,
        parent_key=parent_key,
    )


def _task_weight(entry: dict[str, Any]) -> int:
    """Return a positive scheduled-task selection weight."""
    try:
        weight = int(entry.get("weight", 1))
    except (TypeError, ValueError, OverflowError):
        return 1
    return max(1, weight)


def pick_scheduled_task(rng: random.Random, host: Any | None = None) -> tuple[str, str, str]:
    """Pick a random scheduled task.

    Returns (image_path, command_line, parent_key).
    """
    tasks = get_scheduled_task_entries(host)
    if not tasks:
        return (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe /Run", "svchost_local_system")

    entry = rng.choices(tasks, weights=[_task_weight(candidate) for candidate in tasks], k=1)[0]
    return materialize_scheduled_task_entry(entry, rng, host)


def pick_system_service_process(
    rng: random.Random,
    host_type: str = "workstation",
    host: Any | None = None,
    deployment_key: str = "default",
) -> tuple[str, str, str]:
    """Pick a random system service process appropriate for the host role.

    Args:
        rng: Random instance.
        host_type: One of "workstation", "server", "domain_controller".

    Returns (image_path, command_line, parent_key).
    """
    pool = [
        entry.model_dump(exclude_none=True)
        for entry in get_deployed_system_service_descriptors(
            host_type=host_type,
            host=host,
            deployment_key=deployment_key,
        )
    ]

    if not pool:
        return (r"C:\Windows\System32\conhost.exe", "conhost.exe 0x4", "csrss_s0")

    entry = rng.choice(pool)
    cmd_template = rng.choice(entry["command_templates"])
    cmd = _resolve_template(cmd_template, rng, entry.get("params"))
    return (
        _resolve_host_placeholders(entry["image"], host),
        _resolve_host_placeholders(cmd, host),
        entry.get("parent", "services"),
    )


def get_deployed_system_service_descriptors(
    host_type: str = "workstation",
    host: Any | None = None,
    deployment_key: str = "default",
) -> tuple[SystemServiceEntry, ...]:
    """Return the deterministic installed service set for one exact host."""

    services = _system_service_descriptors()
    pool = list(services.get("all", ()))
    if host_type == "domain_controller":
        pool.extend(services.get("domain_controller", ()))
    elif host_type == "server":
        pool.extend(services.get("server", ()))
    else:
        pool.extend(services.get("workstation", ()))

    if host is not None:
        host_roles = {
            str(role).strip().casefold().replace("-", "_")
            for role in (getattr(host, "roles", None) or ())
        }
        host_services = {
            str(service).strip().casefold().replace("-", "_")
            for service in (getattr(host, "services", None) or ())
        }
        pool = [
            entry
            for entry in pool
            if (
                (not entry.roles_any and not entry.services_any)
                or bool(
                    host_roles.intersection(
                        role.strip().casefold().replace("-", "_") for role in entry.roles_any
                    )
                    or host_services.intersection(
                        service.strip().casefold().replace("-", "_")
                        for service in entry.services_any
                    )
                )
            )
        ]
    else:
        pool = [entry for entry in pool if not entry.roles_any and not entry.services_any]

    grouped_options: dict[str, set[str]] = {}
    for entry in pool:
        if entry.compatibility_group and entry.compatibility_option:
            grouped_options.setdefault(entry.compatibility_group, set()).add(
                entry.compatibility_option
            )
    host_scoped_groups = {
        entry.compatibility_group
        for entry in pool
        if entry.compatibility_group and entry.compatibility_scope == "host"
    }
    hostname = str(getattr(host, "hostname", "default") or "default")
    selected_options = {
        group: random.Random(
            _stable_seed(
                f"software_deployment:"
                f"{hostname if group in host_scoped_groups else deployment_key}:{group}"
            )
        ).choice(sorted(options))
        for group, options in grouped_options.items()
    }
    return tuple(
        entry
        for entry in pool
        if not entry.compatibility_group
        or selected_options.get(entry.compatibility_group) == entry.compatibility_option
    )


def materialize_system_service_descriptor(
    entry: SystemServiceEntry,
    rng: random.Random,
    host: Any | None = None,
) -> tuple[str, str, str]:
    """Materialize one exact compiled service descriptor."""

    cmd_template = rng.choice(entry.command_templates)
    cmd = _resolve_template(cmd_template, rng, entry.params)
    return (
        _resolve_host_placeholders(entry.image, host),
        _resolve_host_placeholders(cmd, host),
        entry.parent,
    )


def materialize_compiled_system_service_descriptor(
    entry: SystemServiceEntry,
    rng: random.Random,
    host: Any,
) -> CompiledSystemServiceMaterialization:
    """Materialize one service while preserving its exact compiled host identity."""

    hostname = str(getattr(host, "hostname", "") or "").strip()
    if not hostname:
        raise ValueError("compiled system service materialization requires a hostname")
    if entry.id is None:  # pragma: no cover - config boundary supplies stable IDs
        raise ValueError("compiled system service materialization requires a service ID")
    image_path, command_line, parent_key = materialize_system_service_descriptor(
        entry,
        rng,
        host,
    )
    return CompiledSystemServiceMaterialization(
        deployment_identity=CompiledServiceDeploymentIdentity(
            hostname=hostname,
            service_id=entry.id,
        ),
        image_path=image_path,
        command_line=command_line,
        parent_key=parent_key,
    )
