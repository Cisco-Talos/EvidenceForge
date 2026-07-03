# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Baseline authentication noise configuration loader."""

from __future__ import annotations

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "auth_noise.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_auth_noise_config() -> dict[str, Any]:
    """Load auth-noise config, merged with project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/auth_noise.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_auth_noise_cache() -> None:
    """Clear cached auth-noise config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def scheduled_stale_credentials_config() -> dict[str, Any]:
    """Return stale scheduled-credential failure settings."""
    config = load_auth_noise_config().get("scheduled_stale_credentials", {})
    return config if isinstance(config, dict) else {}


def service_account_delegation_config() -> dict[str, Any]:
    """Return service-account explicit-credential delegation settings."""
    config = load_auth_noise_config().get("service_account_delegation", {})
    return config if isinstance(config, dict) else {}
