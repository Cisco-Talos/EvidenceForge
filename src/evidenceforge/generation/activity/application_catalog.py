# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unified application catalog loader for process generation.

Loads application_catalog.yaml and provides functions to query apps
by persona, OS, and category — replacing the separate PROCESS_TEMPLATES,
PERSONA_APP_INDICES, and _PE_METADATA data structures.
"""

from __future__ import annotations

import random
from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_CATALOG_PATH = get_activity_directory() / "application_catalog.yaml"
_CACHED_CATALOG: dict[str, Any] | None = None
_CACHED_PE: dict[str, tuple[str, str, str, str, str]] | None = None


def load_catalog() -> dict[str, Any]:
    """Load the application catalog YAML. Cached after first call."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _CACHED_CATALOG

    with open(_CATALOG_PATH) as f:
        _CACHED_CATALOG = yaml.safe_load(f)
    return _CACHED_CATALOG


def get_apps_for_persona(
    persona: str,
    os_category: str,
    category: str,
) -> list[dict[str, Any]]:
    """Return applications available to a persona on a given OS and category.

    Args:
        persona: Persona name (e.g., "developer", "hr"). Falls back to
            "default" if the persona doesn't appear in any app's list.
        os_category: "windows" or "linux".
        category: Category tag to filter on (e.g., "user_app", "code", "build", "query").

    Returns:
        List of matching application dicts from the catalog. Each dict
        has the platform-specific entry accessible via platforms[os_category].
    """
    data = load_catalog()
    persona_lower = persona.lower() if persona else "default"

    results = []
    for app in data["applications"]:
        # Must have a platform entry for this OS
        if os_category not in app.get("platforms", {}):
            continue
        # Must match the requested category
        if category not in app.get("categories", []):
            continue
        # Must allow this persona
        if persona_lower not in app.get("personas", []):
            continue
        results.append(app)

    # If no apps matched for this persona, try "default" as fallback
    if not results and persona_lower != "default":
        return get_apps_for_persona("default", os_category, category)

    return results


def get_pe_metadata(exe_basename: str) -> tuple[str, str, str, str, str]:
    """Look up PE metadata for a user-installed application by exe basename.

    Searches the application catalog for a matching Windows image path
    and returns (FileVersion, Description, Product, Company, OriginalFileName).
    Returns ("-", "-", "-", "-", "-") if not found.

    Args:
        exe_basename: Lowercase executable basename (e.g., "chrome.exe").
    """
    global _CACHED_PE
    if _CACHED_PE is None:
        _CACHED_PE = _build_pe_index()

    return _CACHED_PE.get(exe_basename.lower(), ("-", "-", "-", "-", "-"))


def _build_pe_index() -> dict[str, tuple[str, str, str, str, str]]:
    """Build a basename → PE metadata lookup from the catalog."""
    data = load_catalog()
    index: dict[str, tuple[str, str, str, str, str]] = {}
    for app in data["applications"]:
        win = app.get("platforms", {}).get("windows", {})
        pe = win.get("pe_metadata")
        if not pe:
            continue
        # Extract basename from image_path
        image_path = win.get("image_path", "")
        basename = image_path.rsplit("\\", 1)[-1].lower()
        if basename:
            index[basename] = (
                pe.get("file_version", "-"),
                pe.get("description", "-"),
                pe.get("product", "-"),
                pe.get("company", "-"),
                pe.get("original_filename", "-"),
            )
    return index


def pick_app_and_command(
    rng: random.Random,
    persona: str,
    os_category: str,
    category: str,
    username: str = "",
) -> tuple[str, str] | None:
    """Pick a random app for the persona and return (image_path, command_template).

    Returns None if no apps are available for this persona/OS/category.
    The command_template still contains {placeholders} for _parameterize_command().
    """
    apps = get_apps_for_persona(persona, os_category, category)
    if not apps:
        return None

    app = rng.choice(apps)
    platform = app["platforms"][os_category]
    image_path = platform["image_path"]
    if "{username}" in image_path:
        image_path = image_path.replace("{username}", username)
    command_line = rng.choice(platform["command_templates"])
    return image_path, command_line
