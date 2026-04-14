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


def pick_scheduled_task(rng: random.Random) -> tuple[str, str, str]:
    """Pick a random scheduled task.

    Returns (image_path, command_line, parent_key).
    """
    data = load_system_processes()
    tasks = data.get("scheduled_tasks", [])
    if not tasks:
        return (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe /Run", "svchost_local_system")

    entry = rng.choice(tasks)
    cmd_template = rng.choice(entry["command_templates"])
    cmd = _resolve_template(cmd_template, rng, entry.get("params"))
    return entry["image"], cmd, entry.get("parent", "services")


def pick_system_service_process(
    rng: random.Random, host_type: str = "workstation"
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
    return entry["image"], cmd, entry.get("parent", "services")
