# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Extra syslog message loader with role/distro filtering.

Loads extra_syslog_messages.yaml and provides filtered message pools
for baseline syslog diversity generation.

Follows the same cached-loader pattern as dns_registry.py, spawn_rules.py, etc.
"""

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_MESSAGES_PATH = get_activity_directory() / "extra_syslog_messages.yaml"
_CACHED_DATA: list[dict[str, Any]] | None = None


def _merge_extra_syslog(default: dict, overlay: dict) -> dict:
    """Merge extra syslog messages overlay with package defaults."""
    result = dict(default)
    if "programs" in overlay:
        result["programs"] = extend_list(default.get("programs", []), overlay["programs"])
    return result


def load_extra_syslog_messages() -> list[dict[str, Any]]:
    """Load extra syslog message definitions from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    data = load_with_overlay(
        _MESSAGES_PATH,
        "activity/extra_syslog_messages.yaml",
        _merge_extra_syslog,
    )
    _CACHED_DATA = data.get("programs", [])
    return _CACHED_DATA


def filter_syslog_messages(
    programs: list[dict[str, Any]],
    is_rhel_like: bool,
    host_roles: list[str] | None,
) -> list[tuple[str, list[str], int]]:
    """Filter syslog programs by distro and host roles.

    Args:
        programs: Raw program entries from YAML.
        is_rhel_like: True for CentOS/RHEL/Rocky/Alma hosts.
        host_roles: List of roles assigned to the host, or None.

    Returns:
        List of (app_name, messages, weight) tuples matching the host context.
    """
    return [
        (entry["app"], entry["messages"], int(entry.get("weight", 10)))
        for entry in filter_syslog_message_entries(programs, is_rhel_like, host_roles)
    ]


def filter_syslog_message_entries(
    programs: list[dict[str, Any]],
    is_rhel_like: bool,
    host_roles: list[str] | None,
) -> list[dict[str, Any]]:
    """Filter syslog programs by distro and host roles, preserving entry metadata."""
    result: list[dict[str, Any]] = []
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

        result.append(entry)
    return result


def _service_template_values(system_services: list[str] | None, fallback: list[str]) -> list[str]:
    """Return service placeholder values that fit the current host when possible."""
    contextual: list[str] = []
    for service in system_services or []:
        normalized = service.strip().lower()
        if not normalized or normalized in {"dns-client", "systemd"}:
            continue
        if normalized == "ssh":
            normalized = "sshd"
        contextual.append(normalized)
    return contextual or fallback


def render_extra_syslog_message(
    entry: dict[str, Any],
    rng: Any,
    *,
    positional_value: Any,
    system_services: list[str] | None = None,
    values: dict[str, Any] | None = None,
) -> str:
    """Render a syslog message template with data-driven placeholder pools."""
    template = rng.choice(entry.get("messages", [""]))
    render_values: dict[str, Any] = dict(values or {})
    for key, candidates in (entry.get("params") or {}).items():
        pool = (
            _service_template_values(system_services, candidates)
            if key == "service"
            else candidates
        )
        if pool:
            render_values[key] = rng.choice(pool)
    for key, value in list(render_values.items()):
        if isinstance(value, str) and "{" in value:
            render_values[key] = value.format(positional_value, **render_values)
    return template.format(positional_value, **render_values)
