# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for CallTrace pattern configuration.

Loads calltrace_patterns.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/calltrace_patterns.yaml if present.
"""

from __future__ import annotations

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_CALLTRACE_PATH = get_activity_directory() / "calltrace_patterns.yaml"
_CACHED_CONFIG: dict[str, Any] | None = None
_CACHED_PATTERNS: list[dict[str, Any]] | None = None


def _merge_calltrace(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely."""
    result = dict(default)
    for key, value in overlay.items():
        result[key] = value
    return result


def load_calltrace_patterns() -> list[dict[str, Any]]:
    """Load CallTrace pattern config, merged with overlay. Cached after first call."""
    global _CACHED_PATTERNS
    if _CACHED_PATTERNS is not None:
        return _CACHED_PATTERNS

    _CACHED_PATTERNS = load_calltrace_config().get("patterns", [])
    return _CACHED_PATTERNS


def load_calltrace_config() -> dict[str, Any]:
    """Load the complete CallTrace config, merged with overlay."""
    global _CACHED_CONFIG
    if _CACHED_CONFIG is not None:
        return _CACHED_CONFIG
    data = load_with_overlay(
        _CALLTRACE_PATH,
        "activity/calltrace_patterns.yaml",
        _merge_calltrace,
    )
    _CACHED_CONFIG = data
    return data


def _image_basename(image: str) -> str:
    """Return a lower-case executable name from a Windows or POSIX path."""
    return image.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def source_family_for_image(source_image: str) -> str:
    """Return the configured CallTrace source family for a process image."""
    config = load_calltrace_config()
    source_exe = _image_basename(source_image)
    families = config.get("source_families", {})
    if not isinstance(families, dict):
        return "generic"

    for family_name, family_config in families.items():
        if family_name == "generic" or not isinstance(family_config, dict):
            continue
        matches = family_config.get("match_exes", [])
        if any(_image_basename(str(match)) == source_exe for match in matches):
            return str(family_name)
    return "generic"


def _patterns_by_id() -> dict[str, dict[str, Any]]:
    """Return configured patterns keyed by stable pattern id."""
    patterns: dict[str, dict[str, Any]] = {}
    for index, pattern in enumerate(load_calltrace_patterns()):
        pattern_id = str(pattern.get("id") or f"pattern_{index}")
        patterns[pattern_id] = pattern
    return patterns


def _pattern_ids_for_family(family: str) -> list[str]:
    """Return configured pattern IDs for a source family."""
    config = load_calltrace_config()
    families = config.get("source_families", {})
    if not isinstance(families, dict):
        return list(_patterns_by_id())
    family_config = families.get(family)
    if not isinstance(family_config, dict):
        family_config = families.get("generic")
    if not isinstance(family_config, dict):
        return list(_patterns_by_id())
    ids = [str(pattern_id) for pattern_id in family_config.get("pattern_ids", [])]
    available = _patterns_by_id()
    return [pattern_id for pattern_id in ids if pattern_id in available] or list(available)


def _render_pattern(pattern: dict[str, Any], hostname: str) -> str:
    """Render one pattern with host-stable module offsets."""
    modules = pattern.get("modules", [])
    ranges = pattern.get("offset_ranges", {})
    pattern_id = str(pattern.get("id") or "|".join(str(module) for module in modules))
    parts: list[str] = []
    for module in modules:
        module_name = str(module)
        offset_range = ranges.get(module_name, [0x1000, 0x2000])
        lo, hi = int(offset_range[0]), int(offset_range[1])
        rng = random.Random(_stable_seed(f"calltrace_offset:{hostname}:{pattern_id}:{module_name}"))
        off = rng.randint(lo, hi)
        parts.append(f"C:\\Windows\\SYSTEM32\\{module_name}+{off:X}")
    return "|".join(parts)


def render_call_trace_for_source(
    source_image: str,
    hostname: str,
    *,
    seed_parts: tuple[Any, ...] = (),
) -> str:
    """Render a source-image-aware CallTrace string for one ProcessAccess event."""
    patterns = _patterns_by_id()
    if not patterns:
        return ""
    family = source_family_for_image(source_image)
    candidate_ids = _pattern_ids_for_family(family)
    seed = ":".join(
        str(part) for part in (hostname, family, _image_basename(source_image), *seed_parts)
    )
    rng = random.Random(_stable_seed(f"calltrace_choice:{seed}"))
    pattern_id = rng.choice(candidate_ids)
    return _render_pattern(patterns[pattern_id], hostname)
