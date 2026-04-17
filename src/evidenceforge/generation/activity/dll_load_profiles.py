# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unified DLL load profile loader for Sysmon Event 7 (ImageLoaded).

Collects loaded_modules data from two sources:
- system_processes.yaml: common_loaded_modules, process_loaded_modules,
  and inline loaded_modules on system_services entries
- application_catalog.yaml: platforms.windows.loaded_modules on app entries

Provides a single lookup: exe basename → list of DLL dicts with defaults applied.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_VALID_SIGNATURE_STATUSES = {"Valid", "Expired", "Revoked", "Unavailable"}

_CACHED_PROFILES: dict[str, list[dict[str, Any]]] | None = None


def _apply_defaults(entry: dict[str, Any]) -> dict[str, Any]:
    """Apply default field values to a loaded_modules entry."""
    return {
        "path": entry["path"],
        "signed": entry.get("signed", True),
        "signature": entry.get("signature", "Microsoft Windows"),
        "signature_status": entry.get("signature_status", "Valid"),
    }


def _validate_entry(entry: Any, source: str) -> bool:
    """Validate a single loaded_modules entry. Returns True if valid."""
    if not isinstance(entry, dict):
        logger.warning(
            "DLL profile entry in %s must be a mapping, got %s — skipping",
            source,
            type(entry).__name__,
        )
        return False

    path = entry.get("path", "")
    if not isinstance(path, str):
        logger.warning(
            "DLL profile entry in %s has non-string path %r — skipping",
            source,
            path,
        )
        return False
    if not path:
        logger.warning("DLL profile entry in %s has empty path — skipping", source)
        return False
    if "\\" not in path:
        logger.warning(
            "DLL profile path %r in %s does not look like a Windows path — skipping",
            path,
            source,
        )
        return False
    sig_status = entry.get("signature_status", "Valid")
    if sig_status not in _VALID_SIGNATURE_STATUSES:
        logger.error(
            "DLL profile path %r in %s has invalid signature_status %r "
            "(must be one of %s) — skipping",
            path,
            source,
            sig_status,
            _VALID_SIGNATURE_STATUSES,
        )
        return False
    return True


def _extract_exe_basename(image_path: str) -> str:
    """Extract lowercase exe basename from a full Windows or Unix path."""
    return image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def load_dll_profiles() -> dict[str, list[dict[str, Any]]]:
    """Build unified exe→DLL mapping from system_processes + app catalog.

    Returns:
        Dict keyed by lowercase exe basename (plus "_common" for the
        OS loader chain). Each value is a list of dicts with keys:
        path, signed, signature, signature_status.
    """
    global _CACHED_PROFILES
    if _CACHED_PROFILES is not None:
        return _CACHED_PROFILES

    from evidenceforge.generation.activity.application_catalog import (
        load_catalog,
    )
    from evidenceforge.generation.activity.system_processes import (
        load_system_processes,
    )

    profiles: dict[str, list[dict[str, Any]]] = {}

    # --- Source 1: system_processes.yaml ---
    sys_data = load_system_processes()

    # Common loaded modules (OS loader chain)
    common_raw = (sys_data.get("common_loaded_modules") or {}).get("windows") or []
    if not common_raw:
        logger.error(
            "common_loaded_modules.windows is missing or empty in "
            "system_processes.yaml — every Windows process needs ntdll"
        )
    common = []
    for entry in common_raw:
        if _validate_entry(entry, "common_loaded_modules"):
            common.append(_apply_defaults(entry))
    profiles["_common"] = common

    # process_loaded_modules section (keyed by exe basename)
    for exe_name, modules in (sys_data.get("process_loaded_modules") or {}).items():
        key = exe_name.lower()
        validated = []
        for entry in modules or []:
            if _validate_entry(entry, f"process_loaded_modules.{exe_name}"):
                validated.append(_apply_defaults(entry))
        if validated:
            profiles[key] = validated

    # Inline loaded_modules on system_services entries
    for _role, services in (sys_data.get("system_services") or {}).items():
        for svc in services or []:
            modules = svc.get("loaded_modules")
            if not modules:
                continue
            exe = _extract_exe_basename(svc.get("image", ""))
            if not exe:
                continue
            key = exe.lower()
            validated = []
            for entry in modules:
                if _validate_entry(entry, f"system_services.{exe}"):
                    validated.append(_apply_defaults(entry))
            if validated:
                # Merge with any existing profile (e.g., from process_loaded_modules)
                existing = profiles.get(key, [])
                existing_paths = {e["path"].lower() for e in existing}
                for v in validated:
                    if v["path"].lower() not in existing_paths:
                        existing.append(v)
                        existing_paths.add(v["path"].lower())
                profiles[key] = existing

    # --- Source 2: application_catalog.yaml ---
    catalog = load_catalog()
    for app in catalog.get("applications") or []:
        win_platform = (app.get("platforms") or {}).get("windows") or {}
        modules = win_platform.get("loaded_modules")
        if not modules:
            continue
        image_path = win_platform.get("image_path", "")
        exe = _extract_exe_basename(image_path)
        if not exe:
            continue
        key = exe.lower()
        app_id = app.get("id", exe)
        validated = []
        for entry in modules:
            if _validate_entry(entry, f"application_catalog.{app_id}"):
                validated.append(_apply_defaults(entry))
        if validated:
            existing = profiles.get(key, [])
            existing_paths = {e["path"].lower() for e in existing}
            for v in validated:
                if v["path"].lower() not in existing_paths:
                    existing.append(v)
                    existing_paths.add(v["path"].lower())
            profiles[key] = existing

    # --- Duplicate detection: warn if process-specific DLLs duplicate common ---
    common_paths = {e["path"].lower() for e in common}
    for exe_key, dlls in profiles.items():
        if exe_key == "_common":
            continue
        for dll in dlls:
            if dll["path"].lower() in common_paths:
                logger.warning(
                    "DLL %r in profile %r duplicates a common_loaded_modules entry",
                    dll["path"],
                    exe_key,
                )

    _CACHED_PROFILES = profiles
    return profiles


def get_dlls_for_process(exe_basename: str) -> list[dict[str, Any]]:
    """Return common + process-specific DLLs for a given executable.

    Args:
        exe_basename: e.g., "explorer.exe" (case-insensitive)

    Returns:
        List of dicts with keys: path, signed, signature, signature_status.
        Falls back to common-only if no profile exists for this process.
    """
    profiles = load_dll_profiles()
    common = list(profiles.get("_common", []))
    specific = profiles.get(exe_basename.lower(), [])
    return common + specific
