# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Network realism parameters loaded from YAML with overlay support."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_CACHED_DATA: dict[str, Any] | None = None


def merge_network_params(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay network params into defaults."""
    result = dict(default)
    if "oui_prefixes" in overlay:
        result["oui_prefixes"] = extend_list(
            default.get("oui_prefixes", []), overlay["oui_prefixes"]
        )
    if "public_ntp_servers" in overlay:
        result["public_ntp_servers"] = extend_list(
            default.get("public_ntp_servers", []), overlay["public_ntp_servers"]
        )
    if "dns_tunnel_rtt" in overlay:
        result["dns_tunnel_rtt"] = dict(overlay["dns_tunnel_rtt"])
    return result


def load_network_params() -> dict[str, Any]:
    """Load network_params.yaml with project-local overlay support."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        path = get_activity_directory() / "network_params.yaml"
        _CACHED_DATA = load_with_overlay(
            path,
            "activity/network_params.yaml",
            merge_network_params,
        )
    return _CACHED_DATA


def reset_network_params_cache() -> None:
    """Clear cached network params for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def public_ntp_servers() -> list[dict[str, Any]]:
    """Return configured public NTP server profiles."""
    servers = load_network_params().get("public_ntp_servers", [])
    return [server for server in servers if isinstance(server, dict)]


def public_ntp_ips() -> list[str]:
    """Return configured public NTP server IPs."""
    return [
        str(server["ip"])
        for server in public_ntp_servers()
        if isinstance(server.get("ip"), str) and server["ip"]
    ]


def dns_tunnel_rtt_range() -> tuple[float, float]:
    """Return configured DNS tunnel RTT range in seconds."""
    rtt = load_network_params().get("dns_tunnel_rtt", {})
    if not isinstance(rtt, dict):
        return (0.04, 1.5)
    return (float(rtt.get("min_seconds", 0.04)), float(rtt.get("max_seconds", 1.5)))
