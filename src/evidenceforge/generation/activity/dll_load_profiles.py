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
_CACHED_MODULE_PE: dict[str, tuple[str, str, str, str, str]] | None = None


def _apply_defaults(entry: dict[str, Any]) -> dict[str, Any]:
    """Apply default field values to a loaded_modules entry."""
    return {
        "path": entry["path"],
        "signed": entry.get("signed", True),
        "signature": entry.get("signature", "Microsoft Windows"),
        "signature_status": entry.get("signature_status", "Valid"),
        "pe_metadata": entry.get("pe_metadata"),
    }


def _validate_entry(entry: dict[str, Any], source: str) -> bool:
    """Validate a single loaded_modules entry. Returns True if valid."""
    path = entry.get("path", "")
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


def _is_windows_system_module_path(image_path: str) -> bool:
    """Return True for DLL paths owned by the Windows OS installation tree."""
    normalized = image_path.replace("/", "\\").lower()
    return "\\windows\\" in normalized


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


def _metadata_tuple(pe: dict[str, str], fallback_name: str) -> tuple[str, str, str, str, str]:
    """Convert a PE metadata mapping to the tuple shape used by Sysmon rendering."""
    return (
        pe.get("file_version", "-"),
        pe.get("description", f"{fallback_name} module"),
        pe.get("product", "-"),
        pe.get("company", "-"),
        pe.get("original_filename", fallback_name),
    )


def _inherit_application_module_metadata(
    module: dict[str, Any],
    app_pe: dict[str, str],
) -> tuple[str, str, str, str, str] | None:
    """Return module metadata inherited from the owning application package."""
    module_name = _extract_exe_basename(module.get("path", ""))
    if not module_name or not app_pe:
        return None
    explicit = module.get("pe_metadata")
    if explicit:
        return _metadata_tuple(explicit, module_name)
    if _is_windows_system_module_path(module.get("path", "")):
        return None
    company = module.get("signature") or app_pe.get("company", "-")
    return (
        app_pe.get("file_version", "-"),
        f"{module_name} module",
        app_pe.get("product", "-"),
        company,
        module_name,
    )


def load_module_pe_metadata() -> dict[str, tuple[str, str, str, str, str]]:
    """Build a loaded-module path/name → PE metadata index from config data."""
    global _CACHED_MODULE_PE
    if _CACHED_MODULE_PE is not None:
        return _CACHED_MODULE_PE

    from evidenceforge.generation.activity.application_catalog import load_catalog
    from evidenceforge.generation.activity.system_processes import load_system_processes

    index: dict[str, tuple[str, str, str, str, str]] = {}

    def add(path: str, metadata: tuple[str, str, str, str, str]) -> None:
        normalized = path.replace("/", "\\").lower()
        basename = _extract_exe_basename(path)
        index[normalized] = metadata
        index.setdefault(basename, metadata)

    catalog = load_catalog()
    for app in catalog.get("applications") or []:
        win_platform = (app.get("platforms") or {}).get("windows") or {}
        app_pe = win_platform.get("pe_metadata") or {}
        for module in win_platform.get("loaded_modules") or []:
            metadata = _inherit_application_module_metadata(module, app_pe)
            if metadata:
                add(module["path"], metadata)

    sys_data = load_system_processes()
    module_groups: list[list[dict[str, Any]]] = []
    module_groups.append((sys_data.get("common_loaded_modules") or {}).get("windows") or [])
    module_groups.extend((sys_data.get("process_loaded_modules") or {}).values())
    for services in (sys_data.get("system_services") or {}).values():
        for svc in services or []:
            modules = svc.get("loaded_modules")
            if modules:
                module_groups.append(modules)
    for modules in module_groups:
        for module in modules or []:
            explicit = module.get("pe_metadata")
            if explicit:
                add(
                    module["path"], _metadata_tuple(explicit, _extract_exe_basename(module["path"]))
                )

    _CACHED_MODULE_PE = index
    return index


def get_module_pe_metadata(image_path: str) -> tuple[str, str, str, str, str]:
    """Look up PE metadata for a loaded DLL/module path."""
    index = load_module_pe_metadata()
    normalized = image_path.replace("/", "\\").lower()
    basename = _extract_exe_basename(image_path)
    if _is_windows_system_module_path(image_path):
        return index.get(normalized) or ("-", "-", "-", "-", "-")
    return index.get(normalized) or index.get(basename) or ("-", "-", "-", "-", "-")


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
