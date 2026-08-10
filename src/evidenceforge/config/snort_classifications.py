# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Load source-native Snort classification display descriptions."""

from __future__ import annotations

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay

_CONFIG_PATH = get_activity_directory() / "snort_classifications.yaml"
_CACHED_CLASSIFICATIONS: dict[str, str] | None = None


def snort_classification_description(classification: str) -> str:
    """Resolve a Snort classtype identifier to its native display description."""
    global _CACHED_CLASSIFICATIONS
    if _CACHED_CLASSIFICATIONS is None:
        loaded = load_with_overlay(
            _CONFIG_PATH,
            "activity/snort_classifications.yaml",
            lambda default, overlay: {**default, **overlay},
        )
        descriptions = loaded.get("classifications", {})
        _CACHED_CLASSIFICATIONS = {str(key): str(value) for key, value in descriptions.items()}
    return _CACHED_CLASSIFICATIONS.get(classification, classification)


def reset_snort_classifications_cache() -> None:
    """Clear the cached classification mapping for tests."""
    global _CACHED_CLASSIFICATIONS
    _CACHED_CLASSIFICATIONS = None
