# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Secret/credential family + safety-marker config loader (spillage event type).

Data lives in ``config/activity/secret_families.yaml`` and may be extended via a
project-local overlay at ``.eforge/config/activity/secret_families.yaml``.
Families are keyed by ``name``; marker lists and the domain allowlist extend.
"""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import (
    extend_list,
    load_with_overlay,
    merge_keyed_list,
)

_CONFIG_PATH = get_activity_directory() / "secret_families.yaml"
_OVERLAY_SUBPATH = "activity/secret_families.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_secret_families(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge overlay into bundled secret-family config.

    Families merge by ``name`` (extend); marker lists and the domain allowlist
    are appended; other scalar/dict keys are replaced by the overlay.
    """
    result = dict(default)
    for key, overlay_value in overlay.items():
        if key == "families":
            result["families"] = merge_keyed_list(
                default.get("families", []),
                overlay_value,
                key_field="name",
            )
        elif key in ("poison_markers", "vendor_fakes"):
            result[key] = extend_list(default.get(key, []), overlay_value)
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


def load_secret_families() -> dict[str, Any]:
    """Load secret-family config, merged with any project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            _OVERLAY_SUBPATH,
            _merge_secret_families,
        )
    return _CACHED_DATA


def reset_secret_families_cache() -> None:
    """Clear cached secret-family config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def family_names() -> set[str]:
    """Return the set of configured family names."""
    return {f["name"] for f in load_secret_families().get("families", []) if isinstance(f, dict)}


def get_family(name: str) -> dict[str, Any] | None:
    """Return a family definition by name, or None if unknown."""
    for family in load_secret_families().get("families", []):
        if isinstance(family, dict) and family.get("name") == name:
            return family
    return None


def poison_markers() -> list[str]:
    """Return substrings that mark a value as synthetic/test content."""
    return list(load_secret_families().get("poison_markers", []))


def vendor_fakes() -> list[str]:
    """Return verbatim vendor-published fake credentials (allowlisted)."""
    return list(load_secret_families().get("vendor_fakes", []))


def allowlisted_domains() -> list[str]:
    """Return domains permitted to appear inside an emitted value."""
    allowlist = load_secret_families().get("network_allowlist", {})
    return list(allowlist.get("domains", [])) if isinstance(allowlist, dict) else []
