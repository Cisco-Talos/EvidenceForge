# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Network realism parameters loaded from YAML with overlay support."""

from __future__ import annotations

import math
import random
from typing import Any

from pydantic import ValidationError

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay, merge_keyed_list
from evidenceforge.config.schemas import DnsTunnelRttConfig
from evidenceforge.utils.rng import _stable_seed

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
_DEFAULT_PROXY_CONNECT_STATUS_MESSAGES: dict[int, list[str]] = {
    200: ["Connection Established"],
    403: ["Forbidden"],
    407: ["Proxy Authentication Required"],
    502: ["Bad Gateway"],
    503: ["Service Unavailable"],
    504: ["Gateway Timeout"],
}
_DEFAULT_EXTERNAL_SCANNER_PORT_PROFILES: list[dict[str, Any]] = [
    {
        "name": "broad_low_rate",
        "weight": 1.0,
        "ports": [
            {"port": 22, "weight": 1.0},
            {"port": 23, "weight": 1.0},
            {"port": 80, "weight": 1.0},
            {"port": 443, "weight": 1.0},
            {"port": 445, "weight": 1.0},
            {"port": 3389, "weight": 1.0},
            {"port": 8080, "weight": 1.0},
        ],
    }
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
    if "external_scanner_port_profiles" in overlay:
        result["external_scanner_port_profiles"] = merge_keyed_list(
            default.get("external_scanner_port_profiles", []),
            overlay["external_scanner_port_profiles"],
            "name",
        )
    if isinstance(overlay.get("dns_tunnel_rcode_weights"), dict):
        result["dns_tunnel_rcode_weights"] = dict(overlay["dns_tunnel_rcode_weights"])
    if isinstance(overlay.get("proxy_connect_status_messages"), dict):
        merged_messages = dict(default.get("proxy_connect_status_messages", {}))
        merged_messages.update(overlay["proxy_connect_status_messages"])
        result["proxy_connect_status_messages"] = merged_messages
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


def external_scanner_port_profiles() -> list[dict[str, Any]]:
    """Return cleaned source-sticky external scanner destination-port profiles."""
    raw_profiles = load_network_params().get("external_scanner_port_profiles", [])
    if not isinstance(raw_profiles, list):
        return list(_DEFAULT_EXTERNAL_SCANNER_PORT_PROFILES)

    profiles: list[dict[str, Any]] = []
    for raw_profile in raw_profiles:
        if not isinstance(raw_profile, dict):
            continue
        name = str(raw_profile.get("name", "")).strip()
        try:
            profile_weight = float(raw_profile.get("weight", 1.0))
        except (TypeError, ValueError):
            continue
        if not name or not math.isfinite(profile_weight) or profile_weight <= 0:
            continue
        ports: list[tuple[int, float]] = []
        for raw_port in raw_profile.get("ports", []):
            if not isinstance(raw_port, dict):
                continue
            try:
                port = int(raw_port["port"])
                weight = float(raw_port.get("weight", 1.0))
            except (KeyError, TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and math.isfinite(weight) and weight > 0:
                ports.append((port, weight))
        if ports:
            profiles.append({"name": name, "weight": profile_weight, "ports": ports})
    return profiles or list(_DEFAULT_EXTERNAL_SCANNER_PORT_PROFILES)


def external_scanner_port_profile_for_source(src_ip: str) -> dict[str, Any]:
    """Return a stable external scanner port profile for a scanner source IP."""
    profiles = external_scanner_port_profiles()
    rng = random.Random(_stable_seed(f"external_scanner_profile:{src_ip}"))
    return rng.choices(
        profiles,
        weights=[float(profile["weight"]) for profile in profiles],
        k=1,
    )[0]


def external_scanner_port_for_source(src_ip: str, rng: Any) -> int:
    """Pick a destination port from the stable scanner profile for this source."""
    profile = external_scanner_port_profile_for_source(src_ip)
    ports = list(profile.get("ports", []))
    if not ports:
        return 443
    values = [int(port) for port, _weight in ports]
    weights = [float(weight) for _port, weight in ports]
    return int(rng.choices(values, weights=weights, k=1)[0])


def proxy_connect_status_messages() -> dict[int, list[str]]:
    """Return configured proxy CONNECT status message choices by status code."""
    raw_messages = load_network_params().get("proxy_connect_status_messages", {})
    if not isinstance(raw_messages, dict):
        return dict(_DEFAULT_PROXY_CONNECT_STATUS_MESSAGES)

    cleaned: dict[int, list[str]] = {}
    for raw_code, raw_values in raw_messages.items():
        try:
            code = int(raw_code)
        except (TypeError, ValueError):
            continue
        if code < 100 or code > 599:
            continue
        if isinstance(raw_values, str):
            values = [raw_values]
        elif isinstance(raw_values, list):
            values = raw_values
        else:
            continue
        messages = [str(value).strip() for value in values if isinstance(value, str) and value]
        if messages:
            cleaned[code] = messages

    result = dict(_DEFAULT_PROXY_CONNECT_STATUS_MESSAGES)
    result.update(cleaned)
    return result


def proxy_connect_status_message(status_code: int, *seed_parts: object) -> str:
    """Return a deterministic source-native CONNECT status message."""
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return "Proxy Error"

    messages = proxy_connect_status_messages().get(code)
    if not messages:
        return "Connection Established" if code < 400 else "Proxy Error"
    if len(messages) == 1:
        return messages[0]
    seed = _stable_seed(
        "proxy_connect_status:" + "|".join(str(part) for part in (code, *seed_parts))
    )
    return messages[seed % len(messages)]
