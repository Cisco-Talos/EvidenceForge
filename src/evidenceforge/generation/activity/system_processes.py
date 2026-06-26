# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Per-role baseline system process generation for Windows hosts.

Loads system_processes.yaml and provides functions to pick diverse
scheduled tasks and system service processes by host role.
"""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
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


def get_scheduled_task_entries(host: Any | None = None) -> list[dict[str, Any]]:
    """Return scheduled-task config entries allowed for a host."""
    data = load_system_processes()
    return [
        entry for entry in data.get("scheduled_tasks", []) if _scheduled_task_allowed(entry, host)
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
) -> tuple[str, str, str]:
    """Pick a random system service process appropriate for the host role.

    Args:
        rng: Random instance.
        host_type: One of "workstation", "server", "domain_controller".

    Returns (image_path, command_line, parent_key).
    """
    data = load_system_processes()
    services = data.get("system_services", {})

    # Combine "all" pool with role-specific pool
    pool = list(services.get("all", []))
    if host_type == "domain_controller":
        pool.extend(services.get("domain_controller", []))
    elif host_type == "server":
        pool.extend(services.get("server", []))
    else:
        pool.extend(services.get("workstation", []))

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
