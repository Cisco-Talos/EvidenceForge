# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial-payload family + marker config loader (adversarial_payload event).

Data lives in ``config/activity/payload_families.yaml`` and may be extended via a
project-local overlay at ``.eforge/config/activity/payload_families.yaml``.
Families are keyed by ``name``; the marker list and domain allowlist extend. An
overlay can ADD families/markers but never remove the default marker or weaken the
host allowlist (enforced by ``PayloadFamiliesConfig`` at ``validate-config`` time).
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import (
    extend_list,
    load_with_overlay,
    merge_keyed_list,
)

_CONFIG_PATH = get_activity_directory() / "payload_families.yaml"
_OVERLAY_SUBPATH = "activity/payload_families.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_payload_families(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay into bundled payload-family config.

    Families merge by ``name`` (extend); the marker list and domain allowlist are
    appended; other scalar/dict keys are replaced by the overlay.
    """
    result = dict(default)
    for key, overlay_value in overlay.items():
        if key == "families":
            result["families"] = merge_keyed_list(
                default.get("families", []),
                overlay_value,
                key_field="name",
            )
        elif key == "markers":
            result["markers"] = extend_list(default.get("markers", []), overlay_value)
        elif key == "network_allowlist":
            merged = dict(default.get("network_allowlist", {}))
            for sub_key, sub_value in (overlay_value or {}).items():
                if sub_key == "domains":
                    merged["domains"] = extend_list(merged.get("domains", []), sub_value)
                else:
                    merged[sub_key] = sub_value
            result["network_allowlist"] = merged
        else:
            result[key] = overlay_value
    return result


def load_payload_families() -> dict[str, Any]:
    """Load adversarial-payload family config, merged with any project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            _OVERLAY_SUBPATH,
            _merge_payload_families,
        )
    return _CACHED_DATA


def reset_payload_families_cache() -> None:
    """Clear cached payload-family config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def family_names() -> set[str]:
    """Return the set of configured payload-family names."""
    return {f["name"] for f in load_payload_families().get("families", []) if isinstance(f, dict)}


def get_family(name: str) -> dict[str, Any] | None:
    """Return a payload-family definition by name, or None if unknown."""
    for family in load_payload_families().get("families", []):
        if isinstance(family, dict) and family.get("name") == name:
            return family
    return None


def payload_markers() -> list[str]:
    """Return substrings that mark a payload as synthetic/test content."""
    return list(load_payload_families().get("markers", []))


def default_marker() -> str:
    """Return the default poison marker every payload must carry (EFORGE_TEST)."""
    return str(load_payload_families().get("default_marker", "EFORGE_TEST"))


def canary_host() -> str:
    """Return the single canary host (canary.eforge.invalid)."""
    return str(load_payload_families().get("canary_host", "canary.eforge.invalid"))


def allowlisted_domains() -> list[str]:
    """Return domains permitted to appear inside a payload."""
    allowlist = load_payload_families().get("network_allowlist", {})
    return list(allowlist.get("domains", [])) if isinstance(allowlist, dict) else []
