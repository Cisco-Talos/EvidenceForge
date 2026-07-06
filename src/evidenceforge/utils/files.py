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

"""File I/O utilities for EvidenceForge."""

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.models.exceptions import ConfigurationError, ScenarioIncludeError

SCENARIO_INCLUDE_KEY = "includes"
SCENARIO_INCLUDE_ALIAS = "include"


def load_yaml(path: Path | str) -> dict:
    """Load and parse YAML file safely.

    Args:
        path: Path to YAML file

    Returns:
        Parsed dict structure

    Raises:
        FileNotFoundError: If file doesn't exist
        ConfigurationError: If YAML is invalid
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in {path}: {e}") from e


def load_scenario_yaml(path: Path | str) -> dict[str, Any]:
    """Load a scenario YAML file and expand top-level includes.

    Scenario include paths are resolved relative to the file that declares them.
    Included mappings are merged before the including file's own fields. Any
    duplicate field ownership is rejected instead of being treated as an
    override.

    Args:
        path: Path to scenario YAML file

    Returns:
        Expanded scenario dictionary

    Raises:
        FileNotFoundError: If the scenario file doesn't exist
        ConfigurationError: If YAML is invalid
        ScenarioIncludeError: If include expansion fails
    """
    scenario_path = Path(path).resolve()
    data, _origins = _load_yaml_with_includes(scenario_path, stack=())
    return data


def _load_raw_yaml(path: Path) -> dict[str, Any]:
    """Load YAML from an already-resolved path without expanding includes."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in {path}: {e}") from e

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ScenarioIncludeError(f"Scenario include file must contain a YAML mapping: {path}")
    return data


def _load_yaml_with_includes(
    path: Path,
    *,
    stack: tuple[Path, ...],
) -> tuple[dict[str, Any], dict[tuple[str, ...], Path]]:
    """Load a YAML mapping, recursively expanding its scenario includes."""
    if path in stack:
        chain = " -> ".join(str(p) for p in (*stack, path))
        raise ScenarioIncludeError(f"Circular scenario include detected: {chain}")

    data = _load_raw_yaml(path)
    include_entries = _extract_include_entries(data, path)

    merged: dict[str, Any] = {}
    origins: dict[tuple[str, ...], Path] = {}
    next_stack = (*stack, path)

    for include_entry in include_entries:
        include_path = _resolve_include_path(include_entry, path)
        if not include_path.exists():
            raise ScenarioIncludeError(
                f"Scenario include not found: {include_path} (referenced from {path})"
            )
        include_data, include_origins = _load_yaml_with_includes(
            include_path,
            stack=next_stack,
        )
        _merge_disjoint_mapping(
            merged,
            include_data,
            origins,
            include_origins,
            path=(),
            incoming_source=include_path,
        )

    own_data = {
        key: value
        for key, value in data.items()
        if key not in {SCENARIO_INCLUDE_KEY, SCENARIO_INCLUDE_ALIAS}
    }
    own_origins: dict[tuple[str, ...], Path] = {}
    _record_origins(own_data, (), path, own_origins)
    _merge_disjoint_mapping(
        merged,
        own_data,
        origins,
        own_origins,
        path=(),
        incoming_source=path,
    )
    return merged, origins


def _extract_include_entries(data: dict[str, Any], path: Path) -> list[str]:
    """Normalize scenario include syntax from a loaded YAML mapping."""
    has_canonical = SCENARIO_INCLUDE_KEY in data
    has_alias = SCENARIO_INCLUDE_ALIAS in data
    if has_canonical and has_alias:
        raise ScenarioIncludeError(
            f"{path}: use either '{SCENARIO_INCLUDE_KEY}' or '{SCENARIO_INCLUDE_ALIAS}', not both"
        )
    if not has_canonical and not has_alias:
        return []

    raw_entries = data[SCENARIO_INCLUDE_KEY] if has_canonical else data[SCENARIO_INCLUDE_ALIAS]
    if isinstance(raw_entries, str):
        return [raw_entries]
    if isinstance(raw_entries, list) and all(isinstance(entry, str) for entry in raw_entries):
        return raw_entries
    raise ScenarioIncludeError(
        f"{path}: '{SCENARIO_INCLUDE_KEY}' must be a string path or a list of string paths"
    )


def _resolve_include_path(include_entry: str, including_path: Path) -> Path:
    """Resolve one include path relative to its declaring YAML file."""
    include_path = Path(include_entry)
    if not include_path.is_absolute():
        include_path = including_path.parent / include_path
    return include_path.resolve()


def _merge_disjoint_mapping(
    target: dict[str, Any],
    incoming: dict[str, Any],
    origins: dict[tuple[str, ...], Path],
    incoming_origins: dict[tuple[str, ...], Path],
    *,
    path: tuple[str, ...],
    incoming_source: Path,
) -> None:
    """Merge two mappings while rejecting duplicate non-mapping fields."""
    for key, incoming_value in incoming.items():
        key_path = (*path, str(key))
        if key not in target:
            target[key] = copy.deepcopy(incoming_value)
            _copy_origins_for_path(incoming_origins, origins, key_path)
            continue

        existing_value = target[key]
        if isinstance(existing_value, dict) and isinstance(incoming_value, dict):
            _merge_disjoint_mapping(
                existing_value,
                incoming_value,
                origins,
                incoming_origins,
                path=key_path,
                incoming_source=incoming_source,
            )
            continue

        existing_source = _origin_for_path(origins, key_path)
        new_source = _origin_for_path(incoming_origins, key_path) or incoming_source
        field_path = _format_field_path(key_path)
        raise ScenarioIncludeError(
            "Conflicting scenario include value at "
            f"'{field_path}': {existing_source} already defines it, and "
            f"{new_source} defines it too. Move this field into exactly one file."
        )


def _record_origins(
    value: Any,
    path: tuple[str, ...],
    source: Path,
    origins: dict[tuple[str, ...], Path],
) -> None:
    """Record leaf field ownership for include conflict diagnostics."""
    if isinstance(value, dict):
        if not value:
            origins[path] = source
            return
        for key, child in value.items():
            _record_origins(child, (*path, str(key)), source, origins)
        return
    origins[path] = source


def _copy_origins_for_path(
    source_origins: dict[tuple[str, ...], Path],
    destination_origins: dict[tuple[str, ...], Path],
    path: tuple[str, ...],
) -> None:
    """Copy origin entries for a newly-added subtree."""
    copied = False
    for origin_path, source in source_origins.items():
        if origin_path == path or origin_path[: len(path)] == path:
            destination_origins[origin_path] = source
            copied = True
    if not copied:
        source = _origin_for_path(source_origins, path)
        if source is not None:
            destination_origins[path] = source


def _origin_for_path(origins: dict[tuple[str, ...], Path], path: tuple[str, ...]) -> Path | None:
    """Find the source file for a field path or one of its descendants."""
    source = origins.get(path)
    if source is not None:
        return source
    for origin_path, origin_source in origins.items():
        if origin_path[: len(path)] == path:
            return origin_source
    return None


def _format_field_path(path: tuple[str, ...]) -> str:
    """Format a tuple path for human-readable include diagnostics."""
    return ".".join(path) if path else "<root>"


def write_yaml(data: dict, path: Path | str) -> None:
    """Write dict to YAML file.

    Args:
        data: Dict to serialize
        path: Output path
    """
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def ensure_directory(path: Path | str) -> Path:
    """Ensure directory exists, creating if needed.

    Args:
        path: Directory path

    Returns:
        Resolved Path object

    Raises:
        PermissionError: If can't create directory
    """
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_output_path(path: Path | str) -> Path:
    """Validate output path is writable.

    Args:
        path: Path to validate

    Returns:
        Resolved Path object

    Raises:
        PermissionError: If path is not writable
    """
    path = Path(path).resolve()

    # Check if parent directory is writable
    if path.exists():
        if not os.access(path, os.W_OK):
            raise PermissionError(f"Path not writable: {path}")
    else:
        # Check parent directory
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        if not os.access(parent, os.W_OK):
            raise PermissionError(f"Parent directory not writable: {parent}")

    return path
