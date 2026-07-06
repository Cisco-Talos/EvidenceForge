# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Config-backed external actor fallback identity pools."""

from __future__ import annotations

import random
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_CONFIG_PATH = get_activity_directory() / "external_actor_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None

ExternalActorPool = Literal["logon_source_ips", "failed_logon_source_ips", "connection_c2_ips"]


def _merge_external_actor_profiles(
    default: dict[str, Any],
    overlay: dict[str, Any],
) -> dict[str, Any]:
    """Merge external actor overlay pools with package defaults."""
    result = dict(default)
    for field in ("logon_source_ips", "failed_logon_source_ips", "connection_c2_ips"):
        if field in overlay:
            result[field] = merge_keyed_list(
                default.get(field, []),
                overlay[field],
                key_field="ip",
            )
    return result


def load_external_actor_profiles() -> dict[str, Any]:
    """Load fallback public IP pools, merged with local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/external_actor_profiles.yaml",
        _merge_external_actor_profiles,
    )
    return _CACHED_DATA


def reset_external_actor_profiles_cache() -> None:
    """Clear cached external actor pools. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def pick_external_actor_ip(pool: ExternalActorPool, rng: random.Random) -> str:
    """Pick a public IP from a configured external actor pool."""
    data = load_external_actor_profiles()
    entries = [
        entry
        for entry in data.get(pool, [])
        if isinstance(entry, dict)
        and str(entry.get("ip") or "").strip()
        and int(entry.get("weight", 0)) > 0
    ]
    if not entries:
        return "198.51.100.10"
    weights = [int(entry.get("weight", 0)) for entry in entries]
    return str(rng.choices(entries, weights=weights, k=1)[0]["ip"]).strip()
