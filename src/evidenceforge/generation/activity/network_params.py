# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Network realism parameters loaded from YAML with overlay support."""

from __future__ import annotations

import math
from typing import Any

from pydantic import ValidationError

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay
from evidenceforge.config.schemas import DnsTunnelRttConfig

_CACHED_DATA: dict[str, Any] | None = None
_DEFAULT_DNS_TUNNEL_TTL_CHOICES: list[tuple[int, float]] = [
    (0, 4.0),
    (1, 11.0),
    (2, 17.0),
    (3, 7.0),
    (5, 22.0),
    (7, 5.0),
    (10, 14.0),
    (15, 8.0),
    (20, 3.0),
    (30, 5.0),
    (45, 2.0),
    (60, 2.0),
]


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
    if isinstance(overlay.get("dns_tunnel_rtt"), dict):
        result["dns_tunnel_rtt"] = dict(overlay["dns_tunnel_rtt"])
    if "dns_tunnel_response_templates" in overlay:
        result["dns_tunnel_response_templates"] = extend_list(
            default.get("dns_tunnel_response_templates", []),
            overlay["dns_tunnel_response_templates"],
        )
    if "dns_tunnel_ttl_choices" in overlay:
        result["dns_tunnel_ttl_choices"] = extend_list(
            default.get("dns_tunnel_ttl_choices", []),
            overlay["dns_tunnel_ttl_choices"],
        )
    if isinstance(overlay.get("dns_tunnel_rcode_weights"), dict):
        result["dns_tunnel_rcode_weights"] = dict(overlay["dns_tunnel_rcode_weights"])
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
        return (0.04, 0.35)
    try:
        validated = DnsTunnelRttConfig.model_validate(rtt)
    except ValidationError:
        return (0.04, 0.35)
    if not math.isfinite(validated.min_seconds) or not math.isfinite(validated.max_seconds):
        return (0.04, 0.35)
    return (validated.min_seconds, validated.max_seconds)


def dns_tunnel_response_templates() -> list[str]:
    """Return configured DNS tunnel response token templates."""
    templates = load_network_params().get("dns_tunnel_response_templates", [])
    if not isinstance(templates, list):
        return []
    return [str(template) for template in templates if isinstance(template, str) and template]


def dns_tunnel_ttl_choices() -> list[tuple[int, float]]:
    """Return configured weighted DNS tunnel response TTL choices."""
    choices = load_network_params().get("dns_tunnel_ttl_choices", [])
    if not isinstance(choices, list):
        return list(_DEFAULT_DNS_TUNNEL_TTL_CHOICES)

    cleaned: list[tuple[int, float]] = []
    for entry in choices:
        if not isinstance(entry, dict):
            continue
        try:
            raw_value = float(entry["value"])
            weight = float(entry.get("weight", 1.0))
        except (KeyError, OverflowError, TypeError, ValueError):
            continue
        if not math.isfinite(raw_value) or not raw_value.is_integer():
            continue
        value = int(raw_value)
        if 0 <= value <= 3600 and weight > 0 and math.isfinite(weight):
            cleaned.append((value, weight))
    if not cleaned:
        return list(_DEFAULT_DNS_TUNNEL_TTL_CHOICES)

    total_weight = sum(weight for _value, weight in cleaned)
    if math.isfinite(total_weight):
        return cleaned

    max_weight = max(weight for _value, weight in cleaned)
    return [(value, weight / max_weight) for value, weight in cleaned]


def dns_tunnel_rcode_weights() -> dict[str, float]:
    """Return configured DNS tunnel response-code weights."""
    weights = load_network_params().get("dns_tunnel_rcode_weights", {})
    if not isinstance(weights, dict):
        return {"NOERROR": 1.0}
    allowed = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
    cleaned: dict[str, float] = {}
    for key, value in weights.items():
        name = str(key).upper()
        if name not in allowed:
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        if numeric > 0 and math.isfinite(numeric):
            cleaned[name] = numeric
    if not cleaned:
        return {"NOERROR": 1.0}

    total_weight = sum(cleaned.values())
    if math.isfinite(total_weight):
        return cleaned

    max_weight = max(cleaned.values())
    return {name: weight / max_weight for name, weight in cleaned.items()}
