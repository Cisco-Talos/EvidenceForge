# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public DNS answer profiles for NS/MX/SOA companion lookups."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list

_PROFILES_PATH = get_activity_directory() / "public_dns_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_public_dns_profiles(default: dict, overlay: dict) -> dict:
    """Merge public DNS profile overlays by profile name."""
    result = dict(default)
    for key in ("nameserver_profiles", "mail_profiles"):
        if key in overlay:
            result[key] = merge_keyed_list(
                default.get(key, []),
                overlay[key],
                key_field="name",
            )
    for key, value in overlay.items():
        if key not in {"nameserver_profiles", "mail_profiles"}:
            result[key] = value
    return result


def load_public_dns_profiles() -> dict[str, Any]:
    """Load public DNS answer profiles, merged with local overlay if present."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _PROFILES_PATH,
        "activity/public_dns_profiles.yaml",
        _merge_public_dns_profiles,
    )
    return _CACHED_DATA


def reset_public_dns_profiles_cache() -> None:
    """Clear cached public DNS profiles. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None
