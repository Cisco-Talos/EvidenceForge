# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unified application catalog loader for process generation.

Loads application_catalog.yaml and provides functions to query apps
by persona, OS, and category — replacing the separate PROCESS_TEMPLATES,
PERSONA_APP_INDICES, and _PE_METADATA data structures.
"""

from __future__ import annotations

import random
import re
from collections.abc import Iterable
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.compatibility import warn_legacy_config
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.config.schemas import ApplicationCatalogConfig
from evidenceforge.generation.activity.system_processes import (
    get_system_binary_path,
)
from evidenceforge.utils.rng import _stable_seed

_CATALOG_PATH = get_activity_directory() / "application_catalog.yaml"
_CACHED_CATALOG: dict[str, Any] | None = None
_CACHED_PE: dict[str, tuple[str, str, str, str, str]] | None = None
_CACHED_PATH_INDEX: dict[str, dict[str, str]] | None = None
_CACHED_APPLICATION_BY_ID: dict[str, dict[str, Any]] | None = None
_CACHED_APPLICATION_ORDINAL_BY_ID: dict[str, int] | None = None
_CACHED_APPLICATION_IDS_BY_EXECUTABLE: dict[str, dict[str, tuple[str, ...]]] | None = None

# System binaries are now data-driven from system_processes.yaml.
# See get_system_binary_exes() and get_system_binary_path() in system_processes.py.


def _merge_catalog(default: dict, overlay: dict) -> dict:
    """Merge application catalog overlay with package defaults."""
    result = dict(default)
    overlay_version = overlay.get("schema_version")
    if overlay_version is not None:
        result["schema_version"] = overlay_version
    overlay_default = overlay.get("default_deployment")
    if overlay_default is not None:
        result["default_deployment"] = overlay_default
    if "applications" in overlay:
        overlay_entries = overlay["applications"]
        if not isinstance(overlay_entries, list):
            result["applications"] = merge_keyed_list(
                default.get("applications", []),
                overlay_entries,
                key_field="id",
            )
            return result
        overlay_is_current = overlay_version == 2 and isinstance(overlay_default, dict)
        overlay_applications = []
        for entry in overlay_entries:
            if not overlay_is_current and isinstance(entry, dict):
                application_id = str(entry.get("id") or "<unknown>")
                warn_legacy_config(
                    f"application_catalog overlay applications[{application_id}] unversioned entry",
                    "schema_version: 2 and default_deployment: {kind: legacy_static}",
                    stacklevel=4,
                )
            overlay_applications.append(entry)
        result["applications"] = merge_keyed_list(
            default.get("applications", []),
            overlay_applications,
            key_field="id",
        )
    return result


def load_catalog() -> dict[str, Any]:
    """Load the application catalog YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _CACHED_CATALOG

    merged = load_with_overlay(
        _CATALOG_PATH,
        "activity/application_catalog.yaml",
        _merge_catalog,
    )
    _CACHED_CATALOG = ApplicationCatalogConfig.model_validate(merged).model_dump(
        mode="python",
        exclude_none=True,
        exclude_unset=True,
    )
    return _CACHED_CATALOG


def _application_index() -> dict[str, dict[str, Any]]:
    """Build the exact application-ID index once at the catalog boundary."""

    global _CACHED_APPLICATION_BY_ID
    global _CACHED_APPLICATION_IDS_BY_EXECUTABLE
    global _CACHED_APPLICATION_ORDINAL_BY_ID
    if _CACHED_APPLICATION_BY_ID is None:
        by_id: dict[str, dict[str, Any]] = {}
        ordinal_by_id: dict[str, int] = {}
        ids_by_executable: dict[str, dict[str, list[str]]] = {}
        for ordinal, application in enumerate(load_catalog().get("applications", ())):
            application_id = str(application.get("id") or "").strip().casefold()
            if not application_id:
                raise ValueError("application catalog entries require a stable id")
            if application_id in by_id:
                raise ValueError(f"duplicate application catalog id {application_id!r}")
            by_id[application_id] = application
            ordinal_by_id[application_id] = ordinal
            for platform_name, platform in application.get("platforms", {}).items():
                image_path = str(platform.get("image_path") or "")
                executable = image_path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
                if executable:
                    ids_by_executable.setdefault(str(platform_name), {}).setdefault(
                        executable,
                        [],
                    ).append(application_id)
        _CACHED_APPLICATION_BY_ID = by_id
        _CACHED_APPLICATION_ORDINAL_BY_ID = ordinal_by_id
        _CACHED_APPLICATION_IDS_BY_EXECUTABLE = {
            platform: {
                executable: tuple(application_ids)
                for executable, application_ids in executable_map.items()
            }
            for platform, executable_map in ids_by_executable.items()
        }
    return _CACHED_APPLICATION_BY_ID


def application_descriptor(application_id: str) -> dict[str, Any] | None:
    """Return one exact application descriptor without scanning the catalog."""

    return _application_index().get(application_id.strip().casefold())


def application_ids_for_executables(
    executables: Iterable[str],
    os_category: str,
) -> tuple[str, ...]:
    """Return catalog-ordered IDs from the exact executable index."""

    _application_index()
    assert _CACHED_APPLICATION_IDS_BY_EXECUTABLE is not None
    matched: set[str] = set()
    executable_index = _CACHED_APPLICATION_IDS_BY_EXECUTABLE.get(os_category, {})
    for executable in executables:
        basename = str(executable).replace("\\", "/").rsplit("/", 1)[-1].casefold()
        matched.update(executable_index.get(basename, ()))
    assert _CACHED_APPLICATION_ORDINAL_BY_ID is not None
    return tuple(
        sorted(
            matched,
            key=_CACHED_APPLICATION_ORDINAL_BY_ID.__getitem__,
        )
    )


def ordered_application_ids(application_ids: Iterable[str]) -> tuple[str, ...]:
    """Return known exact application IDs in stable catalog order."""

    _application_index()
    assert _CACHED_APPLICATION_ORDINAL_BY_ID is not None
    requested = {
        application_id.strip().casefold()
        for application_id in application_ids
        if application_id.strip()
    }
    return tuple(
        sorted(
            (
                application_id
                for application_id in requested
                if application_id in _application_index()
            ),
            key=_CACHED_APPLICATION_ORDINAL_BY_ID.__getitem__,
        )
    )


def materialize_application_command(
    rng: random.Random,
    application_id: str,
    os_category: str,
    *,
    username: str = "",
    category: str | None = None,
) -> tuple[str, str] | None:
    """Materialize one exact compiled application without candidate-list construction."""

    application = application_descriptor(application_id)
    if application is None:
        return None
    if category is not None and category not in application.get("categories", ()):
        return None
    platform = application.get("platforms", {}).get(os_category)
    if platform is None:
        return None
    image_path = str(platform["image_path"])
    if "{username}" in image_path:
        image_path = image_path.replace("{username}", username)
    templates = platform.get("command_templates") or ()
    if not templates:
        return None
    command_line = rng.choice(templates)
    return image_path, parameterize_scoped_command(rng, command_line, platform)


_ALL_SYSTEM_TYPES = ["workstation", "server", "domain_controller"]


def get_apps_for_persona(
    persona: str,
    os_category: str,
    category: str,
    system_type: str | None = None,
    deployment_key: str = "default",
) -> list[dict[str, Any]]:
    """Return applications available to a persona on a given OS and category.

    Args:
        persona: Persona name (e.g., "developer", "hr"). Falls back to
            "default" if the persona doesn't appear in any app's list.
        os_category: "windows" or "linux".
        category: Category tag to filter on (e.g., "user_app", "code", "build", "query").
        system_type: Optional system type filter ("workstation", "server",
            "domain_controller"). Apps with a system_types field are only
            returned if the system type matches. Apps without system_types
            are available on all system types.

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
        # Must be available on this system type (if filtering)
        if system_type:
            allowed_types = app.get("system_types")
            if allowed_types is None:
                allowed_types = _ALL_SYSTEM_TYPES
            if system_type not in allowed_types:
                continue
        results.append(app)

    grouped_options: dict[str, set[str]] = {}
    for app in results:
        group = str(app.get("compatibility_group") or "")
        option = str(app.get("compatibility_option") or "")
        if group and option:
            grouped_options.setdefault(group, set()).add(option)
    selected_options = {
        group: random.Random(_stable_seed(f"software_deployment:{deployment_key}:{group}")).choice(
            sorted(options)
        )
        for group, options in grouped_options.items()
    }
    results = [
        app
        for app in results
        if not app.get("compatibility_group")
        or selected_options.get(str(app["compatibility_group"]))
        == str(app.get("compatibility_option") or "")
    ]

    # Only fall back to "default" if the persona is truly unknown
    # (not listed in ANY app's persona allowlist). Known personas with
    # no apps in a category should return empty — the caller skips
    # that activity type, preventing role-inappropriate tools.
    if not results and persona_lower != "default":
        known_personas = set()
        for app in data["applications"]:
            known_personas.update(app.get("personas", []))
        if persona_lower not in known_personas:
            return get_apps_for_persona(
                "default", os_category, category, system_type, deployment_key
            )

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


def is_system_type_allowed(
    exe_basename: str,
    os_category: str,
    system_type: str | None,
) -> bool:
    """Check if an app can be selected on the given system type.

    Unknown apps remain unrestricted so explicit scenario commands and raw
    process names are not blocked by catalog absence.
    """
    if not system_type:
        return True
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
            allowed_types = app.get("system_types")
            return system_type in (_ALL_SYSTEM_TYPES if allowed_types is None else allowed_types)
    return True


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
        win = app.get("platforms", {}).get("windows") or {}
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
        for child_command in win.get("children", []):
            child_image = _child_image_from_command("windows", str(child_command), image_path)
            child_basename = child_image.rsplit("\\", 1)[-1].lower()
            if not child_basename or child_basename in index:
                continue
            child_original_filename = child_image.rsplit("\\", 1)[-1]
            index[child_basename] = (
                pe.get("file_version", "-"),
                pe.get("description", "-"),
                pe.get("product", "-"),
                pe.get("company", "-"),
                child_original_filename,
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
    sys_path = get_system_binary_path(exe_basename, username=username)
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


def _child_image_from_command(
    os_category: str,
    command_line: str,
    fallback_image_path: str,
) -> str:
    """Return the executable image described by a child-process command line."""
    stripped = command_line.strip()
    if not stripped:
        return fallback_image_path

    if stripped.startswith('"'):
        closing_quote = stripped.find('"', 1)
        if closing_quote > 1:
            return stripped[1:closing_quote]

    if os_category == "windows":
        match = re.match(r"^([A-Za-z]:\\.*?\.exe)\b", stripped, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    elif stripped.startswith("/"):
        return stripped.split()[0]

    return fallback_image_path


def child_image_from_command(
    os_category: str,
    command_line: str,
    fallback_image_path: str,
) -> str:
    """Return the exact configured child image without scanning the catalog."""

    return _child_image_from_command(os_category, command_line, fallback_image_path)


def get_child_processes(os_category: str, parent_exe: str) -> list[dict[str, Any]]:
    """Get child process definitions for a given parent executable.

    Children use the executable named by their command line when it is present,
    otherwise they inherit the parent's image path from the catalog.

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
        return [
            {
                "image": _child_image_from_command(os_category, cmd, image_path),
                "command_line": cmd,
                "command_parameter_pools": platform.get("command_parameter_pools", {}),
            }
            for cmd in children
        ]
    return []


# Compatibility-only inspection surface. Browser affinity is a pure function
# for legacy callers and compiled per user profile in DeploymentContentRegistry.
_USER_BROWSER_AFFINITY: dict[str, str] = {}

_BROWSER_IDS = frozenset({"chrome", "firefox", "edge"})


def _apply_browser_affinity(
    rng: random.Random,
    apps: list[dict[str, Any]],
    selected_app: dict[str, Any],
    username: str,
) -> dict[str, Any]:
    """Keep a user's selected browser family stable across user-app launches."""
    selected_id = selected_app.get("id", "").lower()
    if selected_id not in _BROWSER_IDS or not username:
        return selected_app

    browser_apps = [app for app in apps if app.get("id", "").lower() in _BROWSER_IDS]
    if len(browser_apps) <= 1:
        return selected_app

    primary_id = browser_apps[_stable_seed(f"browser_{username}") % len(browser_apps)]["id"]
    if rng.random() < 0.90:
        return next((app for app in browser_apps if app["id"] == primary_id), selected_app)

    others = [app for app in browser_apps if app["id"] != primary_id]
    return rng.choice(others) if others else selected_app


def pick_app_and_command(
    rng: random.Random,
    persona: str,
    os_category: str,
    category: str,
    username: str = "",
    system_type: str | None = None,
    deployment_key: str = "default",
    application_ids: Iterable[str] | None = None,
) -> tuple[str, str] | None:
    """Pick a random app for the persona and return (image_path, command_template).

    Returns None if no apps are available for this persona/OS/category.
    The command_template still contains {placeholders} for _parameterize_command().

    For browser-category apps, applies per-user browser affinity: each user
    has a primary browser (90% of the time) with occasional secondary use (10%).
    """
    if application_ids is None:
        apps = get_apps_for_persona(persona, os_category, category, system_type, deployment_key)
    else:
        persona_lower = persona.casefold() if persona else "default"
        apps = [
            app
            for app in get_applications_for_ids(application_ids, os_category)
            if category in app.get("categories", ())
            and persona_lower in app.get("personas", ())
            and (
                system_type is None
                or app.get("system_types") is None
                or system_type in app["system_types"]
            )
        ]
    if not apps:
        return None

    weights = [int(app.get("selection_weight", 10)) for app in apps]
    app = rng.choices(apps, weights=weights, k=1)[0]
    app = _apply_browser_affinity(rng, apps, app, username)

    platform = app["platforms"][os_category]
    image_path = platform["image_path"]
    if "{username}" in image_path:
        image_path = image_path.replace("{username}", username)
    command_line = rng.choice(platform["command_templates"])
    command_line = parameterize_scoped_command(rng, command_line, platform)
    return image_path, command_line


def parameterize_scoped_command(
    rng: random.Random,
    command_line: str,
    platform: dict[str, Any],
) -> str:
    """Expand only the parameter pools attached to the selected process platform."""

    pools = platform.get("command_parameter_pools", {})
    if not isinstance(pools, dict):
        return command_line
    for _pass in range(3):
        changed = False
        for key, raw_values in pools.items():
            if not isinstance(raw_values, list):
                continue
            values = [str(value) for value in raw_values if str(value)]
            if not values:
                continue
            placeholder = "{" + str(key) + "}"
            while placeholder in command_line:
                command_line = command_line.replace(placeholder, rng.choice(values), 1)
                changed = True
        if not changed:
            break
    return command_line


def get_applications_for_ids(
    application_ids: Iterable[str],
    os_category: str,
) -> list[dict[str, Any]]:
    """Return exact OS-compatible catalog entries for pack application bindings."""

    by_id = _application_index()
    assert _CACHED_APPLICATION_ORDINAL_BY_ID is not None
    requested = {application_id.strip().casefold() for application_id in application_ids}
    return sorted(
        (
            by_id[application_id]
            for application_id in requested
            if application_id in by_id and os_category in by_id[application_id].get("platforms", {})
        ),
        key=lambda app: _CACHED_APPLICATION_ORDINAL_BY_ID[str(app["id"]).casefold()],
    )


def get_executables_for_application_ids(
    application_ids: list[str],
    os_category: str,
) -> list[str]:
    """Return exact executable basenames for public pack application bindings."""

    executables: list[str] = []
    for app in get_applications_for_ids(application_ids, os_category):
        image_path = str(app["platforms"][os_category].get("image_path") or "")
        basename = image_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if basename:
            executables.append(basename)
    return list(dict.fromkeys(executables))


def is_browser_application_process(
    application_ids: list[str],
    os_category: str,
    process_image: str,
) -> bool:
    """Return whether the selected exact process is cataloged as a browser."""

    selected_executable = process_image.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for app in get_applications_for_ids(application_ids, os_category):
        platform = app["platforms"][os_category]
        executable = (
            str(platform.get("image_path") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        )
        if executable == selected_executable and "browser" in app.get("categories", []):
            return True
    return False


def is_singleton_application_image(image_path: str, os_category: str) -> bool:
    """Return whether a catalog application permits one live instance per session."""
    normalized = image_path.replace("/", "\\").lower()
    for app in load_catalog().get("applications", []):
        platform = app.get("platforms", {}).get(os_category)
        if not platform:
            continue
        candidate = str(platform.get("image_path") or "").replace("/", "\\").lower()
        matches = candidate == normalized
        if "{username}" in candidate:
            prefix, suffix = candidate.split("{username}", 1)
            matches = (
                normalized.startswith(prefix)
                and normalized.endswith(suffix)
                and len(normalized) > len(prefix) + len(suffix)
            )
        if matches:
            return bool(app.get("singleton_per_session"))
    return False


def is_deployment_compatible_application(
    image_or_exe: str,
    os_category: str,
    deployment_key: str,
) -> bool:
    """Return whether a catalog app belongs to the selected deployment cohort."""
    catalog = load_catalog().get("applications", [])
    grouped_options: dict[str, set[str]] = {}
    for app in catalog:
        if os_category not in app.get("platforms", {}):
            continue
        group = str(app.get("compatibility_group") or "")
        option = str(app.get("compatibility_option") or "")
        if group and option:
            grouped_options.setdefault(group, set()).add(option)
    selected_options = {
        group: random.Random(_stable_seed(f"software_deployment:{deployment_key}:{group}")).choice(
            sorted(options)
        )
        for group, options in grouped_options.items()
    }

    candidate = image_or_exe.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    for app in catalog:
        platform = app.get("platforms", {}).get(os_category)
        if not platform:
            continue
        app_exe = (
            str(platform.get("image_path") or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
        )
        if candidate != app_exe and candidate.replace(".exe", "") != app_exe.replace(".exe", ""):
            continue
        group = str(app.get("compatibility_group") or "")
        if not group:
            return True
        return selected_options.get(group) == str(app.get("compatibility_option") or "")
    return True
