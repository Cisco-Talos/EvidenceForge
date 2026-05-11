# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for web scan preset configuration.

Loads web_scan_presets.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/web_scan_presets.yaml if present.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

logger = logging.getLogger(__name__)

_PRESETS_PATH = get_activity_directory() / "web_scan_presets.yaml"
_CACHED: dict[str, Any] | None = None


def parse_positive_finite_rate(value: Any) -> float | None:
    """Return value as a positive finite float, or None when invalid."""
    if isinstance(value, bool):
        return None
    try:
        rate = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(rate) or rate <= 0.0:
        return None
    return rate


def _merge_presets(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level preset keys replace entirely.

    A user who overrides the `nikto:` preset gets exactly their config.
    New presets in the overlay are added. Presets not in the overlay are
    preserved from the defaults.
    """
    result = dict(default)
    overlay_presets = overlay.get("presets", {})
    if not isinstance(overlay_presets, dict):
        logger.warning(
            "Config overlay: web_scan presets has invalid structure "
            "(expected dict, got %s) — ignoring overlay presets",
            type(overlay_presets).__name__,
        )
        return result

    if overlay_presets:
        default_presets = result.get("presets", {})
        if not isinstance(default_presets, dict):
            logger.warning(
                "Config overlay: web_scan default presets has invalid structure "
                "(expected dict, got %s) — treating as empty",
                type(default_presets).__name__,
            )
            default_presets = {}
        merged = dict(default_presets)
        merged.update(overlay_presets)
        result["presets"] = merged
    return result


def load_web_scan_presets() -> dict[str, Any]:
    """Load web scan presets, merged with overlay. Cached after first call."""
    global _CACHED  # noqa: PLW0603
    if _CACHED is not None:
        return _CACHED

    _CACHED = load_with_overlay(
        _PRESETS_PATH,
        "activity/web_scan_presets.yaml",
        _merge_presets,
    )
    return _CACHED


def get_preset(name: str) -> dict[str, Any] | None:
    """Get a specific preset by name, or None if not found."""
    data = load_web_scan_presets()
    return data.get("presets", {}).get(name)


def list_preset_names() -> list[str]:
    """List available preset names."""
    data = load_web_scan_presets()
    return list(data.get("presets", {}).keys())
