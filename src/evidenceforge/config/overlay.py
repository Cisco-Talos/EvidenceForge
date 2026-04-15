# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Project-local config overlay system for EvidenceForge.

Discovers a `.eforge/config/` overlay directory in the current working directory
and merges user-provided YAML files with package defaults at load time. This
allows users to add domains, applications, personas, and other config entries
without modifying the installed Python package.

Overlay files contain ONLY the user's additions/overrides (partial files).
The merge logic combines them with package defaults using per-file strategies:

- merge_keyed_list: For lists with unique identifiers (domains, applications).
  User entries with matching keys replace defaults (with warning); new entries
  are appended.
- deep_merge_dict: For nested dicts (traffic profiles, spawn rules).
  User keys recursively override defaults (with warning at leaf level).
- extend_list: For simple lists (schedules, programs, OUI prefixes).
  User entries are appended to defaults.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_OVERLAY_DIR_NAME = ".eforge/config"


def get_overlay_directory() -> Path | None:
    """Discover the project-local overlay config directory.

    Looks for `.eforge/config/` in the current working directory.

    Returns:
        Path to the overlay directory, or None if it doesn't exist.
    """
    overlay = Path.cwd() / _OVERLAY_DIR_NAME
    if overlay.is_dir():
        return overlay
    return None


def list_overlay_files(overlay_dir: Path | None = None) -> list[str]:
    """List all YAML files in the overlay directory as relative paths.

    Returns:
        Sorted list of relative paths (e.g., ["activity/dns_registry.yaml"]).
    """
    if overlay_dir is None:
        overlay_dir = get_overlay_directory()
    if overlay_dir is None or not overlay_dir.is_dir():
        return []
    return sorted(
        str(p.relative_to(overlay_dir)) for p in overlay_dir.rglob("*.yaml") if p.is_file()
    )


def load_with_overlay(
    package_path: Path,
    overlay_subpath: str,
    merge_fn: Any,
) -> dict[str, Any]:
    """Load package YAML, then merge overlay if it exists.

    Args:
        package_path: Absolute path to the package YAML file.
        overlay_subpath: Relative path within the overlay directory
            (e.g., "activity/dns_registry.yaml").
        merge_fn: Callable(default_data, overlay_data) -> merged_data.
            Specific to each file's structure.

    Returns:
        The (possibly merged) config data.
    """
    with open(package_path) as f:
        data = yaml.safe_load(f)

    overlay_dir = get_overlay_directory()
    if overlay_dir is None:
        return data

    overlay_path = overlay_dir / overlay_subpath
    if not overlay_path.exists():
        return data

    logger.info("Merging overlay config: %s", overlay_path)
    with open(overlay_path) as f:
        overlay_data = yaml.safe_load(f)

    if overlay_data is None:
        return data

    return merge_fn(data, overlay_data)


# ---------------------------------------------------------------------------
# Merge strategies
# ---------------------------------------------------------------------------


def merge_keyed_list(
    default_list: list[dict],
    overlay_list: list[dict],
    key_field: str,
) -> list[dict]:
    """Merge two lists of dicts using a unique key field.

    By default, matched entries are merged with ``deep_merge_dict`` —
    list fields are **extended** (appended) and scalar fields are replaced.
    This is the common case: ``{id: chrome, personas: [nurse]}`` adds
    ``nurse`` to Chrome's persona list.

    If an overlay entry includes ``_replace: true``, all its fields
    **replace** the default's fields (including lists). This is for cases
    like retagging a DNS domain: ``{domain: x.com, tags: [dev], _replace: true}``
    sets tags to exactly ``[dev]`` instead of extending. Unmentioned fields
    are still preserved from the default. The ``_replace`` key is stripped
    from the merged result.

    Overlay entries with new keys (no match in defaults) are appended.

    Args:
        default_list: Package default entries.
        overlay_list: User overlay entries.
        key_field: Field name used as the unique identifier (e.g., "domain", "id").

    Returns:
        Merged list.
    """
    # Validate overlay entries before merging
    seen_keys: dict[str, int] = {}
    for i, entry in enumerate(overlay_list):
        if key_field not in entry:
            logger.warning(
                "Config overlay: entry #%d is missing required key field %r — skipping: %s",
                i + 1,
                key_field,
                {k: v for k, v in entry.items() if k != "_replace"},
            )
        else:
            key = entry[key_field]
            if key in seen_keys:
                logger.warning(
                    "Config overlay: duplicate %s=%r (entries #%d and #%d) — last entry wins",
                    key_field,
                    key,
                    seen_keys[key],
                    i + 1,
                )
            seen_keys[key] = i + 1

    overlay_by_key = {entry[key_field]: entry for entry in overlay_list if key_field in entry}
    result = []

    for entry in default_list:
        key = entry.get(key_field)
        if key and key in overlay_by_key:
            overlay_entry = dict(overlay_by_key.pop(key))  # copy so pop doesn't mutate
            replace_mode = overlay_entry.pop("_replace", False)
            logger.info(
                "Config overlay: %s fields into %s=%r",
                "replacing" if replace_mode else "merging",
                key_field,
                key,
            )
            if replace_mode:
                merged = _replace_entry(entry, overlay_entry, f"{key_field}={key}")
            else:
                merged = deep_merge_dict(entry, overlay_entry, f"{key_field}={key}")
            result.append(merged)
        else:
            result.append(entry)

    # Append remaining overlay entries (new additions); strip _replace if present
    for new_entry in overlay_by_key.values():
        cleaned = {k: v for k, v in new_entry.items() if k != "_replace"}
        result.append(cleaned)
    return result


def _replace_entry(
    default: dict[str, Any],
    overlay: dict[str, Any],
    path: str,
) -> dict[str, Any]:
    """Merge an overlay entry into a default using replace semantics.

    Every field present in the overlay replaces the default's value
    (including lists). Fields not in the overlay are preserved from
    the default. Dict fields are still deep-merged.
    """
    result = dict(default)
    for key, overlay_value in overlay.items():
        full_key = f"{path}.{key}"
        if key in result:
            default_value = result[key]
            if isinstance(default_value, dict) and isinstance(overlay_value, dict):
                result[key] = deep_merge_dict(default_value, overlay_value, full_key)
            else:
                if default_value != overlay_value:
                    logger.warning("Config overlay: replacing value at %r", full_key)
                result[key] = overlay_value
        else:
            result[key] = overlay_value
    return result


def deep_merge_dict(
    default: dict[str, Any],
    overlay: dict[str, Any],
    _path: str = "",
) -> dict[str, Any]:
    """Recursively merge overlay dict into default dict.

    Overlay keys win at leaf level (with a warning if replacing an existing
    non-dict value). New keys in overlay are added.

    Args:
        default: Package default dict.
        overlay: User overlay dict.
        _path: Internal — tracks the key path for warning messages.

    Returns:
        Merged dict.
    """
    result = dict(default)
    for key, overlay_value in overlay.items():
        full_key = f"{_path}.{key}" if _path else key
        if key in result:
            default_value = result[key]
            if isinstance(default_value, dict) and isinstance(overlay_value, dict):
                result[key] = deep_merge_dict(default_value, overlay_value, full_key)
            elif isinstance(default_value, list) and isinstance(overlay_value, list):
                # For leaf lists within a dict merge, extend rather than replace
                result[key] = default_value + overlay_value
            else:
                if default_value != overlay_value:
                    logger.warning(
                        "Config overlay: replacing default value at %r",
                        full_key,
                    )
                result[key] = overlay_value
        else:
            result[key] = overlay_value
    return result


def extend_list(
    default_list: list,
    overlay_list: list,
) -> list:
    """Append overlay entries to default list.

    For simple lists without unique keys (schedules, programs, OUI prefixes).

    Args:
        default_list: Package default entries.
        overlay_list: User overlay entries.

    Returns:
        Combined list (defaults + overlay).
    """
    return default_list + overlay_list
