# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SMB file-transfer realism configuration loader."""

import random
import string
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "smb_file_transfers.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_smb_file_transfers(default: dict, overlay: dict) -> dict:
    """Merge SMB file-transfer overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_smb_file_transfers() -> dict[str, Any]:
    """Load SMB file-transfer config from YAML, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/smb_file_transfers.yaml",
        _merge_smb_file_transfers,
    )
    return _CACHED_DATA


def reset_smb_file_transfers_cache() -> None:
    """Clear cached SMB file-transfer config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


_SHARES = ("Shared", "Departments", "Projects", "Public", "Operations")
_DEPARTMENTS = ("Finance", "HR", "Legal", "IT", "Operations", "Sales")
_PROJECTS = ("Phoenix", "Orion", "Atlas", "Northwind", "Quarterly")
_BASENAMES = (
    "budget-review",
    "vendor-list",
    "roadmap",
    "staffing-plan",
    "incident-notes",
    "change-request",
    "customer-export",
    "runbook",
    "inventory",
    "meeting-notes",
)
_BINARY_EXTENSIONS = ("zip", "msi", "bak", "dat", "cab")


def pick_smb_filename(
    rng: random.Random,
    config: dict[str, Any],
    *,
    mime_type: str,
    server: str,
    user: str = "Public",
) -> str:
    """Pick a data-driven SMB filename/path for a Zeek files.log row."""
    templates = config.get("filename_templates", [])
    if not isinstance(templates, list) or not templates:
        return ""

    eligible: list[dict[str, Any]] = []
    for entry in templates:
        if not isinstance(entry, dict):
            continue
        mime_types = entry.get("mime_types", [])
        if not mime_types or mime_type in {str(value) for value in mime_types}:
            eligible.append(entry)
    if not eligible:
        eligible = [entry for entry in templates if isinstance(entry, dict)]
    if not eligible:
        return ""

    weights = [int(entry.get("weight", 1)) for entry in eligible]
    selected = rng.choices(eligible, weights=weights, k=1)[0]
    candidate_templates = selected.get("templates", [])
    if not isinstance(candidate_templates, list) or not candidate_templates:
        return ""

    basename = rng.choice(_BASENAMES)
    if rng.random() < 0.35:
        basename = f"{basename}-{rng.randint(2023, 2026)}"
    if rng.random() < 0.15:
        suffix = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        basename = f"{basename}-{suffix}"

    placeholders = {
        "server": server.split(".")[0] or "fileserver",
        "share": rng.choice(_SHARES),
        "department": rng.choice(_DEPARTMENTS),
        "project": rng.choice(_PROJECTS),
        "basename": basename,
        "ext": rng.choice(_BINARY_EXTENSIONS),
        "user": user or "Public",
    }
    return str(rng.choice(candidate_templates)).format(**placeholders)
