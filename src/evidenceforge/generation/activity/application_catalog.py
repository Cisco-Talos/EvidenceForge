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

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.generation.activity.system_processes import (
    get_system_binary_path,
)

_CATALOG_PATH = get_activity_directory() / "application_catalog.yaml"
_CACHED_CATALOG: dict[str, Any] | None = None
_CACHED_PE: dict[str, tuple[str, str, str, str, str]] | None = None
_CACHED_PATH_INDEX: dict[str, dict[str, str]] | None = None

# System binaries are now data-driven from system_processes.yaml.
# See get_system_binary_exes() and get_system_binary_path() in system_processes.py.


def _merge_catalog(default: dict, overlay: dict) -> dict:
    """Merge application catalog overlay with package defaults."""
    result = dict(default)
    if "applications" in overlay:
        result["applications"] = merge_keyed_list(
            default.get("applications", []),
            overlay["applications"],
            key_field="id",
        )
    return result


def load_catalog() -> dict[str, Any]:
    """Load the application catalog YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _CACHED_CATALOG

    _CACHED_CATALOG = load_with_overlay(
        _CATALOG_PATH,
        "activity/application_catalog.yaml",
        _merge_catalog,
    )
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

    # Only fall back to "default" if the persona is truly unknown
    # (not listed in ANY app's persona allowlist). Known personas with
    # no apps in a category should return empty — the caller skips
    # that activity type, preventing role-inappropriate tools.
    if not results and persona_lower != "default":
        known_personas = set()
        for app in data["applications"]:
            known_personas.update(app.get("personas", []))
        if persona_lower not in known_personas:
            return get_apps_for_persona("default", os_category, category)

    return results


def is_persona_allowed(exe_basename: str, os_category: str, persona: str) -> bool:
    """Check if a persona is allowed to use an application.

    Looks up the exe in the catalog and checks if the persona appears
    in its personas list. Returns True if the exe is not in the catalog
    (unknown apps are not restricted).
    """
    data = load_catalog()
    lower = exe_basename.lower()
    for app in data["applications"]:
        platform = app.get("platforms", {}).get(os_category)
        if not platform:
            continue
        path = platform["image_path"]
        if os_category == "windows":
            basename = path.rsplit("\\", 1)[-1].lower()
        else:
            basename = path.rsplit("/", 1)[-1].lower()
        if (
            basename == lower
            or (lower + ".exe") == basename
            or basename.replace(".exe", "") == lower
        ):
            return persona.lower() in app.get("personas", [])
    return True  # Unknown apps are unrestricted


def get_app_categories(exe_basename: str, os_category: str) -> list[str]:
    """Return the catalog categories for an executable, or [] if not found."""
    data = load_catalog()
    lower = exe_basename.lower()
    for app in data["applications"]:
        platform = app.get("platforms", {}).get(os_category)
        if not platform:
            continue
        path = platform["image_path"]
        if os_category == "windows":
            basename = path.rsplit("\\", 1)[-1].lower()
        else:
            basename = path.rsplit("/", 1)[-1].lower()
        if (
            basename == lower
            or (lower + ".exe") == basename
            or basename.replace(".exe", "") == lower
        ):
            return app.get("categories", [])
    return []


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


def has_catalog_entry(exe_basename: str, os_category: str) -> bool:
    """Check whether an executable has a catalog entry for the given OS."""
    global _CACHED_PATH_INDEX
    if _CACHED_PATH_INDEX is None:
        _CACHED_PATH_INDEX = _build_path_index()

    lower = exe_basename.lower()
    os_index = _CACHED_PATH_INDEX.get(os_category, {})
    if lower in os_index:
        return True
    # Try with .exe for extensionless Windows lookups
    if os_category == "windows" and not lower.endswith(".exe"):
        return f"{lower}.exe" in os_index
    return False


def resolve_image_path(exe_basename: str, os_category: str = "windows", username: str = "") -> str:
    """Resolve a bare executable name to its correct full filesystem path.

    Lookup order:
    1. Application catalog (user-installed apps like Chrome, Firefox, etc.)
    2. Known system binaries with special paths (explorer.exe → C:\\Windows\\)
    3. Known system binaries (System32 is correct for these)
    4. Last-resort fallback (System32 for Windows, /usr/bin for Linux)

    Args:
        exe_basename: Bare executable name (e.g., "chrome.exe", "git")
        os_category: "windows" or "linux"
        username: Optional username for profile-scoped apps (Teams, OneDrive).
            If empty and the path contains {username}, the bare basename is
            returned unchanged to avoid fabricating paths.
    """
    global _CACHED_PATH_INDEX
    if _CACHED_PATH_INDEX is None:
        _CACHED_PATH_INDEX = _build_path_index()

    lower = exe_basename.lower()
    key = lower

    # Also try with .exe appended for extensionless Windows lookups
    key_with_ext = f"{lower}.exe" if os_category == "windows" and not lower.endswith(".exe") else ""

    # 1. Check catalog
    os_index = _CACHED_PATH_INDEX.get(os_category, {})
    path = os_index.get(key) or (os_index.get(key_with_ext) if key_with_ext else None)
    if path:
        if "{username}" in path:
            if username:
                path = path.replace("{username}", username)
            else:
                # No username context — return basename to avoid fabricating paths
                return exe_basename
        return path

    # 2. Known system binaries with non-System32 paths
    _SPECIAL_PATHS = {
        "explorer.exe": r"C:\Windows\explorer.exe",
        "dwm.exe": r"C:\Windows\System32\dwm.exe",
    }
    if os_category == "windows" and lower in _SPECIAL_PATHS:
        return _SPECIAL_PATHS[lower]

    # 3. Data-driven system binary path lookup
    sys_path = get_system_binary_path(exe_basename)
    if sys_path:
        return sys_path

    # 4. Last resort — assume System32 (Windows) or /usr/bin (Linux)
    if os_category == "linux":
        return f"/usr/bin/{exe_basename}"
    return rf"C:\Windows\System32\{exe_basename}"


def _build_path_index() -> dict[str, dict[str, str]]:
    """Build basename → full path indexes for each OS from the catalog.

    Indexes both with and without .exe extension so that bare names
    like 'git' and 'git.exe' both resolve to the catalog path.
    """
    data = load_catalog()
    index: dict[str, dict[str, str]] = {"windows": {}, "linux": {}}
    for app in data["applications"]:
        for os_cat in ("windows", "linux"):
            platform = app.get("platforms", {}).get(os_cat)
            if not platform:
                continue
            image_path = platform["image_path"]
            if os_cat == "windows":
                basename = image_path.rsplit("\\", 1)[-1].lower()
            else:
                basename = image_path.rsplit("/", 1)[-1].lower()
            if basename and basename not in index[os_cat]:
                index[os_cat][basename] = image_path
                # Also index extensionless form (git.exe → git) for callers
                # that use bare names from process_network_map.yaml
                if basename.endswith(".exe"):
                    no_ext = basename[:-4]
                    if no_ext and no_ext not in index[os_cat]:
                        index[os_cat][no_ext] = image_path
    return index


def get_child_processes(os_category: str, parent_exe: str) -> list[dict[str, str]]:
    """Get child process definitions for a given parent executable.

    Children inherit the parent's image_path from the catalog.

    Args:
        os_category: "windows" or "linux"
        parent_exe: Parent executable basename (e.g., "chrome.exe")

    Returns:
        List of dicts with "image" and "command_line" keys, or empty list.
    """
    data = load_catalog()
    parent_lower = parent_exe.lower()
    for app in data["applications"]:
        platform = app.get("platforms", {}).get(os_category)
        if not platform:
            continue
        image_path = platform.get("image_path", "")
        # Match basename from image_path
        if os_category == "windows":
            basename = image_path.rsplit("\\", 1)[-1].lower()
        else:
            basename = image_path.rsplit("/", 1)[-1].lower()
        if basename != parent_lower:
            continue
        children = platform.get("children", [])
        if not children:
            return []
        return [{"image": image_path, "command_line": cmd} for cmd in children]
    return []


_USER_BROWSER_AFFINITY: dict[str, str] = {}

_BROWSER_IDS = frozenset({"chrome", "firefox", "edge"})


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

    For browser-category apps, applies per-user browser affinity: each user
    has a primary browser (90% of the time) with occasional secondary use (10%).
    """
    apps = get_apps_for_persona(persona, os_category, category)
    if not apps:
        return None

    # Per-user browser affinity: same user mostly uses the same browser
    browser_apps = [a for a in apps if a.get("id", "").lower() in _BROWSER_IDS]
    if browser_apps and len(browser_apps) > 1 and username and category == "browser":
        if username not in _USER_BROWSER_AFFINITY:
            # Deterministic primary browser per user
            from evidenceforge.utils.rng import _stable_seed

            idx = _stable_seed(f"browser_{username}") % len(browser_apps)
            _USER_BROWSER_AFFINITY[username] = browser_apps[idx]["id"]

        primary_id = _USER_BROWSER_AFFINITY[username]
        if rng.random() < 0.90:
            # Use primary browser
            app = next((a for a in browser_apps if a["id"] == primary_id), rng.choice(apps))
        else:
            # Occasionally use a different browser
            others = [a for a in browser_apps if a["id"] != primary_id]
            app = rng.choice(others) if others else rng.choice(apps)
    else:
        app = rng.choice(apps)

    platform = app["platforms"][os_category]
    image_path = platform["image_path"]
    if "{username}" in image_path:
        image_path = image_path.replace("{username}", username)
    command_line = rng.choice(platform["command_templates"])
    return image_path, command_line
