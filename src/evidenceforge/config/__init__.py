# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Centralized YAML data directory resolution for EvidenceForge.

All YAML lookup/reference data lives under src/evidenceforge/config/ with
subdirectories for each category. This module provides path helpers so that
loader modules across the codebase resolve data paths from a single authority
instead of computing them relative to their own __file__.
"""

from pathlib import Path

from evidenceforge.models.exceptions import ConfigurationError

_CONFIG_DIR = Path(__file__).parent


def get_config_directory() -> Path:
    """Return the root config data directory (src/evidenceforge/config/)."""
    return _CONFIG_DIR


def get_formats_directory() -> Path:
    """Return path to format definition YAML files.

    Raises:
        ConfigurationError: If the formats directory does not exist.
    """
    d = _CONFIG_DIR / "formats"
    if not d.exists():
        raise ConfigurationError(f"Format definitions directory not found: {d}")
    return d


def get_evaluation_directory() -> Path:
    """Return path to evaluation rule YAML files.

    Raises:
        ConfigurationError: If the evaluation directory does not exist.
    """
    d = _CONFIG_DIR / "evaluation"
    if not d.exists():
        raise ConfigurationError(f"Evaluation rules directory not found: {d}")
    return d


def get_activity_directory() -> Path:
    """Return path to activity generation YAML files.

    Raises:
        ConfigurationError: If the activity directory does not exist.
    """
    d = _CONFIG_DIR / "activity"
    if not d.exists():
        raise ConfigurationError(f"Activity data directory not found: {d}")
    return d


def get_personas_directory() -> Path:
    """Return path to persona YAML files.

    Raises:
        ConfigurationError: If the personas directory does not exist.
    """
    d = _CONFIG_DIR / "personas"
    if not d.exists():
        raise ConfigurationError(f"Personas directory not found: {d}")
    return d
