# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Config-backed pools for suspicious-looking benign background activity."""

from __future__ import annotations

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_CONFIG_PATH = get_activity_directory() / "suspicious_benign.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_suspicious_benign(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge suspicious-benign overlay pools with package defaults."""
    result = dict(default)
    if "dns_hosts" in overlay:
        result["dns_hosts"] = merge_keyed_list(
            default.get("dns_hosts", []),
            overlay["dns_hosts"],
            key_field="hostname",
        )
    if "unusual_connections" in overlay:
        result["unusual_connections"] = merge_keyed_list(
            default.get("unusual_connections", []),
            overlay["unusual_connections"],
            key_field="hostname",
        )
    return result


def load_suspicious_benign() -> dict[str, Any]:
    """Load suspicious-looking benign pools, merged with local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/suspicious_benign.yaml",
        _merge_suspicious_benign,
    )
    return _CACHED_DATA


def reset_suspicious_benign_cache() -> None:
    """Clear cached suspicious-benign pools. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def pick_suspicious_dns_host(rng: random.Random) -> str:
    """Pick a configured suspicious-looking benign DNS hostname."""
    entries = [
        entry
        for entry in load_suspicious_benign().get("dns_hosts", [])
        if isinstance(entry, dict)
        and str(entry.get("hostname") or "").strip()
        and int(entry.get("weight", 0)) > 0
    ]
    if not entries:
        return "telemetry-x9k2m4.windows.com"
    weights = [int(entry.get("weight", 0)) for entry in entries]
    return str(rng.choices(entries, weights=weights, k=1)[0]["hostname"]).strip()


def pick_unusual_connection(rng: random.Random) -> dict[str, Any]:
    """Pick a configured unusual but benign outbound connection target."""
    entries = [
        entry
        for entry in load_suspicious_benign().get("unusual_connections", [])
        if isinstance(entry, dict)
        and str(entry.get("dst_ip") or "").strip()
        and int(entry.get("dst_port", 0)) > 0
        and int(entry.get("weight", 0)) > 0
    ]
    if not entries:
        return {
            "dst_ip": "151.101.0.63",
            "dst_port": 443,
            "service": "ssl",
            "hostname": "pypi.org",
            "desc": "PyPI package download",
        }
    weights = [int(entry.get("weight", 0)) for entry in entries]
    return dict(rng.choices(entries, weights=weights, k=1)[0])
