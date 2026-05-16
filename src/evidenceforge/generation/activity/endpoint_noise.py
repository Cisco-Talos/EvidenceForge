# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Endpoint baseline noise policy loader."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "endpoint_noise.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_endpoint_noise(default: dict, overlay: dict) -> dict:
    """Merge endpoint noise overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_endpoint_noise() -> dict[str, Any]:
    """Load endpoint noise config from YAML, merged with overlay. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/endpoint_noise.yaml",
        _merge_endpoint_noise,
    )
    return _CACHED_DATA


def reset_endpoint_noise_cache() -> None:
    """Clear cached endpoint noise config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def windows_scheduled_process_config() -> dict[str, Any]:
    """Return Windows scheduled/background process timing policy."""
    return load_endpoint_noise().get("windows_scheduled_processes", {})


def registry_noise_config() -> dict[str, Any]:
    """Return ambient endpoint registry-noise policy."""
    return load_endpoint_noise().get("registry_noise", {})


def ecar_flow_identity_config() -> dict[str, Any]:
    """Return eCAR FLOW process/principal attribution policy."""
    return load_endpoint_noise().get("ecar_flow_identity", {})
