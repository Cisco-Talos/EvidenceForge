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
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.models.exceptions import (
    ConfigurationError,
    GenerationError,
    ScenarioIncludeError,
)

SCENARIO_INCLUDE_KEY = "includes"
SCENARIO_INCLUDE_ALIAS = "include"


@dataclass(frozen=True, slots=True)
class ScenarioIncludeBudget:
    """Hard safety limits for recursive scenario composition."""

    max_depth: int = 32
    max_files: int = 256
    max_bytes: int = 16 * 1024 * 1024
    max_nodes: int = 1_000_000

    def __post_init__(self) -> None:
        """Reject nonsensical include-budget configuration."""

        if self.max_depth < 1 or self.max_files < 1 or self.max_bytes < 1 or self.max_nodes < 1:
            raise ValueError("Scenario include budgets must be positive")


@dataclass(slots=True)
class ScenarioIncludeBudgetState:
    """Mutable counters shared by one bounded composition load."""

    budget: ScenarioIncludeBudget
    files: int = 0
    bytes: int = 0
    nodes: int = 0

    @property
    def remaining_bytes(self) -> int:
        """Return the maximum bytes that the next source read may consume."""

        return max(0, self.budget.max_bytes - self.bytes)

    def check_before_read(self, path: Path, *, depth: int) -> None:
        """Reject depth or file-count overflow before opening another source."""

        if depth > self.budget.max_depth:
            raise ScenarioIncludeError(
                f"Scenario include depth exceeds limit {self.budget.max_depth}: {path}"
            )
        if self.files >= self.budget.max_files:
            raise ScenarioIncludeError(
                f"Scenario include file count exceeds limit {self.budget.max_files}: {path}"
            )

    def consume(self, path: Path, *, depth: int, size: int) -> None:
        """Account for one file before reading it and reject budget overflow."""

        if depth > self.budget.max_depth:
            raise ScenarioIncludeError(
                f"Scenario include depth exceeds limit {self.budget.max_depth}: {path}"
            )
        self.files += 1
        self.bytes += size
        if self.files > self.budget.max_files:
            raise ScenarioIncludeError(
                f"Scenario include file count exceeds limit {self.budget.max_files}: {path}"
            )
        if self.bytes > self.budget.max_bytes:
            raise ScenarioIncludeError(
                "Scenario include bytes exceed limit "
                f"{self.budget.max_bytes}: loaded {self.bytes} bytes at {path}"
            )

    def consume_nodes(self, value: Any, *, path: Path) -> None:
        """Account for parsed logical nodes without trusting alias graph shape."""

        active: set[int] = set()

        def visit(node: Any) -> None:
            self.nodes += 1
            if self.nodes > self.budget.max_nodes:
                raise ScenarioIncludeError(
                    f"Scenario expanded node count exceeds limit {self.budget.max_nodes}: {path}"
                )
            if not isinstance(node, (dict, list, tuple, set)):
                return
            node_id = id(node)
            if node_id in active:
                raise ScenarioIncludeError(f"Recursive YAML alias graph is not supported: {path}")
            active.add(node_id)
            try:
                if isinstance(node, dict):
                    for key, child in node.items():
                        visit(key)
                        visit(child)
                else:
                    for child in node:
                        visit(child)
            finally:
                active.remove(node_id)

        visit(value)


@dataclass(frozen=True, slots=True)
class LoadedScenarioSource:
    """One exact YAML source read while expanding a scenario."""

    path: Path
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class LoadedSourceGraph:
    """Expanded scenario plus exact sources and declaring-file field origins."""

    root: Path
    data: dict[str, Any]
    origins: dict[tuple[str, ...], Path]
    sources: tuple[LoadedScenarioSource, ...]


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
        from evidenceforge.utils.yaml_loader import load_yaml_file

        data = load_yaml_file(path)
        return data or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in {path}: {e}") from e


def load_scenario_yaml(
    path: Path | str,
    *,
    include_budget: ScenarioIncludeBudget | None = None,
    allowed_root: Path | None = None,
) -> dict[str, Any]:
    """Load a scenario YAML file and expand top-level includes.

    Scenario include paths are resolved relative to the file that declares them.
    Included mappings are merged before the including file's own fields. Any
    duplicate field ownership is rejected instead of being treated as an
    override.

    Args:
        path: Path to scenario YAML file
        include_budget: Optional bounded composition policy. Defaults to the documented hard
            safety limits.
        allowed_root: Optional lexical root that every source must remain beneath. Include
            candidates are checked before filesystem access.

    Returns:
        Expanded scenario dictionary

    Raises:
        FileNotFoundError: If the scenario file doesn't exist
        ConfigurationError: If YAML is invalid
        ScenarioIncludeError: If include expansion fails
    """
    return load_scenario_source_graph(
        path,
        include_budget=include_budget,
        allowed_root=allowed_root,
    ).data


def load_scenario_source_graph(
    path: Path | str,
    *,
    include_budget: ScenarioIncludeBudget | None = None,
    include_budget_state: ScenarioIncludeBudgetState | None = None,
    allowed_root: Path | None = None,
) -> LoadedSourceGraph:
    """Load an authored scenario once while retaining sources and field origins.

    Args:
        path: Root YAML document to load.
        include_budget: Optional limits for this source graph. Mutually exclusive with
            ``include_budget_state``.
        include_budget_state: Optional mutable counters shared across several related source
            graphs, such as all semantic documents in one pack.
        allowed_root: Optional lexical root that every source must remain beneath.
    """

    if include_budget is not None and include_budget_state is not None:
        raise ValueError("include_budget and include_budget_state are mutually exclusive")

    scenario_path = Path(os.path.abspath(Path(path)))
    lexical_allowed_root = Path(os.path.abspath(allowed_root)) if allowed_root is not None else None
    _assert_source_within_allowed_root(
        scenario_path,
        lexical_allowed_root,
        referenced_from=None,
    )
    budget_state = include_budget_state or ScenarioIncludeBudgetState(
        include_budget or ScenarioIncludeBudget()
    )
    sources: dict[Path, LoadedScenarioSource] = {}
    budget_state.check_before_read(scenario_path, depth=1)
    root_content = _read_source_bytes(scenario_path, max_bytes=budget_state.remaining_bytes)
    root_data = _load_raw_yaml(scenario_path, root_content)
    if root_data.get("kind") == "evidenceforge.resolved-scenario":
        budget_state.consume(scenario_path, depth=1, size=len(root_content))
        budget_state.consume_nodes(root_data, path=scenario_path)
        root_source = LoadedScenarioSource(
            path=scenario_path,
            content=root_content,
            sha256=hashlib.sha256(root_content).hexdigest(),
        )
        origins: dict[tuple[str, ...], Path] = {}
        _record_origins(root_data, (), scenario_path, origins)
        return LoadedSourceGraph(
            root=scenario_path,
            data=root_data,
            origins=origins,
            sources=(root_source,),
        )
    data, origins = _load_yaml_with_includes(
        scenario_path,
        stack=(),
        budget_state=budget_state,
        sources=sources,
        preloaded={scenario_path: (root_content, root_data)},
        allowed_root=lexical_allowed_root,
    )
    return LoadedSourceGraph(
        root=scenario_path,
        data=data,
        origins=origins,
        sources=tuple(sources[path] for path in sorted(sources, key=str)),
    )


def _read_source_bytes(path: Path, *, max_bytes: int | None = None) -> bytes:
    """Read one source without following a final-component symlink."""

    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ScenarioIncludeError(f"Scenario source cannot be a symlink: {path}")
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ScenarioIncludeError(f"Unable to safely open scenario source {path}: {exc}") from exc
    with os.fdopen(descriptor, "rb") as source_file:
        metadata = os.fstat(source_file.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ScenarioIncludeError(f"Scenario source is not a regular file: {path}")
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise ScenarioIncludeError(f"Scenario include bytes exceed limit {max_bytes}: {path}")
        content = source_file.read() if max_bytes is None else source_file.read(max_bytes + 1)
        if max_bytes is not None and len(content) > max_bytes:
            raise ScenarioIncludeError(f"Scenario include bytes exceed limit {max_bytes}: {path}")
        return content


def _load_raw_yaml(path: Path, content: bytes) -> dict[str, Any]:
    """Load YAML from an already-resolved path without expanding includes."""
    try:
        from evidenceforge.utils.yaml_loader import load_yaml_text

        data = load_yaml_text(content.decode("utf-8"), source=str(path))
    except UnicodeError as exc:
        raise ConfigurationError(f"Scenario source is not valid UTF-8: {path}") from exc
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
    budget_state: ScenarioIncludeBudgetState,
    sources: dict[Path, LoadedScenarioSource],
    preloaded: dict[Path, tuple[bytes, dict[str, Any]]] | None = None,
    allowed_root: Path | None = None,
) -> tuple[dict[str, Any], dict[tuple[str, ...], Path]]:
    """Load a YAML mapping, recursively expanding its scenario includes."""
    if path in stack:
        chain = " -> ".join(str(p) for p in (*stack, path))
        raise ScenarioIncludeError(f"Circular scenario include detected: {chain}")

    if preloaded is not None and path in preloaded:
        content, data = preloaded.pop(path)
    else:
        depth = len(stack) + 1
        budget_state.check_before_read(path, depth=depth)
        content = _read_source_bytes(path, max_bytes=budget_state.remaining_bytes)
        data = _load_raw_yaml(path, content)
    budget_state.consume(path, depth=len(stack) + 1, size=len(content))
    sources[path] = LoadedScenarioSource(
        path=path,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )
    budget_state.consume_nodes(data, path=path)
    include_entries = _extract_include_entries(data, path)

    merged: dict[str, Any] = {}
    origins: dict[tuple[str, ...], Path] = {}
    next_stack = (*stack, path)

    for include_entry in include_entries:
        include_path = _resolve_include_path(include_entry, path)
        _assert_source_within_allowed_root(
            include_path,
            allowed_root,
            referenced_from=path,
        )
        if not include_path.exists():
            raise ScenarioIncludeError(
                f"Scenario include not found: {include_path} (referenced from {path})"
            )
        include_data, include_origins = _load_yaml_with_includes(
            include_path,
            stack=next_stack,
            budget_state=budget_state,
            sources=sources,
            preloaded=preloaded,
            allowed_root=allowed_root,
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


def resolve_safe_child_path(root: Path, filename: str, *, label: str = "output filename") -> Path:
    """Resolve one untrusted filename beneath a root without traversal or symlink escape."""

    candidate = Path(filename)
    if not filename or candidate.is_absolute() or candidate.name != filename:
        raise GenerationError(f"Unsafe {label}: expected one filename component, got {filename!r}")
    resolved_root = root.resolve()
    destination = (resolved_root / candidate).resolve()
    if not destination.is_relative_to(resolved_root) or destination == resolved_root:
        raise GenerationError(f"Unsafe {label}: path escapes output root: {filename!r}")
    return destination


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
    return Path(os.path.abspath(include_path))


def _assert_source_within_allowed_root(
    path: Path,
    allowed_root: Path | None,
    *,
    referenced_from: Path | None,
) -> None:
    """Reject an out-of-root source before any filesystem operation can observe it."""

    if allowed_root is None:
        return
    try:
        path.relative_to(allowed_root)
    except ValueError as exc:
        context = f" (referenced from {referenced_from})" if referenced_from is not None else ""
        raise ScenarioIncludeError(
            f"Scenario source escapes allowed root {allowed_root}: {path}{context}"
        ) from exc


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
    if isinstance(value, list):
        if not value:
            origins[path] = source
            return
        for index, child in enumerate(value):
            _record_origins(child, (*path, str(index)), source, origins)
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
