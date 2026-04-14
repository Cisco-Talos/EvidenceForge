# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Process-to-network service mapping loader.

Loads process_network_map.yaml and provides forward (exe→service) and
inverse (service→exe) indexes for process-network correlation and
PID attribution.

Follows the same cached-loader pattern as dns_registry.py, spawn_rules.py, etc.
"""

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_MAP_PATH = get_activity_directory() / "process_network_map.yaml"
_CACHED_DATA: list[dict[str, Any]] | None = None
_CACHED_EXE_TO_SERVICE: dict[str, dict[str, Any]] | None = None
_CACHED_SERVICE_TO_EXES: dict[str, list[str]] | None = None


def _merge_process_network_map(default: dict, overlay: dict) -> dict:
    """Merge process network map overlay with package defaults."""
    result = dict(default)
    if "mappings" in overlay:
        result["mappings"] = extend_list(default.get("mappings", []), overlay["mappings"])
    return result


def load_process_network_map() -> list[dict[str, Any]]:
    """Load process-network mappings from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    data = load_with_overlay(
        _MAP_PATH,
        "activity/process_network_map.yaml",
        _merge_process_network_map,
    )
    _CACHED_DATA = data.get("mappings", [])
    return _CACHED_DATA


def get_exe_to_service() -> dict[str, dict[str, Any]]:
    """Build exe→service index. Returns dict mapping exe name to {port, service, external}.

    Cached after first call.
    """
    global _CACHED_EXE_TO_SERVICE
    if _CACHED_EXE_TO_SERVICE is not None:
        return _CACHED_EXE_TO_SERVICE
    mappings = load_process_network_map()
    result: dict[str, dict[str, Any]] = {}
    for entry in mappings:
        info = {
            "dst_port": entry["port"],
            "service": entry["service"],
            "external": entry["external"],
        }
        for exe in entry["exe"]:
            result[exe] = info
    _CACHED_EXE_TO_SERVICE = result
    return result


def get_service_to_exes() -> dict[str, list[str]]:
    """Build service→exe inverse index. Returns dict mapping service name to exe list.

    Cached after first call.
    """
    global _CACHED_SERVICE_TO_EXES
    if _CACHED_SERVICE_TO_EXES is not None:
        return _CACHED_SERVICE_TO_EXES
    mappings = load_process_network_map()
    result: dict[str, list[str]] = {}
    for entry in mappings:
        service = entry["service"]
        if service not in result:
            result[service] = []
        for exe in entry["exe"]:
            result[service].append(exe.lower())
    _CACHED_SERVICE_TO_EXES = result
    return result
