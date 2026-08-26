# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic package/project/path repository for data-only scenario packs."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from evidenceforge.config import get_config_directory
from evidenceforge.models.exceptions import ConfigurationError, PackError
from evidenceforge.utils import (
    LoadedSourceGraph,
    ScenarioIncludeBudget,
    ScenarioIncludeBudgetState,
    load_scenario_source_graph,
)
from evidenceforge.utils.yaml_loader import load_yaml_text

from .models import (
    ApplicationCatalogDocument,
    BaselineActivityFragment,
    DestinationCatalogDocument,
    EnvironmentFragment,
    PackLock,
    PackManifest,
    PackReference,
    PackSource,
    PackType,
    PersonaCatalogDocument,
    ProcessCatalogDocument,
    SelectedPack,
    StorageCatalogDocument,
    TrafficCatalogDocument,
)
from .semantic_validation import (
    packaged_builtin_application_ids,
    packaged_builtin_dns_domains,
    packaged_builtin_dns_tags,
    packaged_builtin_executable_claims,
    packaged_builtin_persona_ids,
    packaged_builtin_storage_preset_ids,
    validate_selected_pack_semantics,
)

PACK_CAPABILITY_VERSION = "2.0.0"
PACK_MANIFEST_FILENAME = "pack.yaml"
PACK_LOCK_FILENAME = "pack.lock.yaml"
PACKAGED_INDEX_FILENAME = "index.json"
ALLOWED_NONSEMANTIC_FILES = {"README.md", "LICENSE", "LICENSE.md", "COPY_PROVENANCE.md"}

# YAML expansion and whole-tree traversal have separate counters. The former
# bounds the aggregate parser workload across every semantic document in one
# pack; the latter also accounts for non-semantic companion files and empty
# directories before any pack payload is read or copied.
PACK_SEMANTIC_BUDGET = ScenarioIncludeBudget()


@dataclass(frozen=True, slots=True)
class PackTreeBudget:
    """Hard limits for one complete data-only pack tree."""

    max_depth: int = 32
    max_files: int = 256
    max_entries: int = 512
    max_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        """Reject nonsensical pack-tree limits."""

        if min(self.max_depth, self.max_files, self.max_entries, self.max_bytes) < 1:
            raise ValueError("Pack tree budgets must be positive")


PACK_TREE_BUDGET = PackTreeBudget()

CATALOG_FILES: tuple[tuple[str, str, type[BaseModel]], ...] = (
    ("persona_catalog", "catalogs/persona_catalog.yaml", PersonaCatalogDocument),
    ("process_catalog", "catalogs/process_catalog.yaml", ProcessCatalogDocument),
    ("application_catalog", "catalogs/application_catalog.yaml", ApplicationCatalogDocument),
    ("destination_catalog", "catalogs/destination_catalog.yaml", DestinationCatalogDocument),
    ("traffic_catalog", "catalogs/traffic_catalog.yaml", TrafficCatalogDocument),
    ("storage_catalog", "catalogs/storage_catalog.yaml", StorageCatalogDocument),
)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """One validated whole pack."""

    manifest: PackManifest
    lock: PackLock
    source: PackSource
    root: Path
    digest: str
    catalogs: dict[str, dict[str, Any]]
    environment: dict[str, Any]
    baseline_activity: dict[str, Any]
    assets: dict[str, str]
    semantic_file_bytes: tuple[tuple[str, bytes], ...]
    companion_file_bytes: tuple[tuple[str, bytes], ...]
    source_directories: frozenset[str]
    payload_files: frozenset[str]
    catalog_field_origins: dict[str, str]
    organization_model_origins: dict[str, str]
    industry_dependency_declaring_files: tuple[Path, ...]

    def selected(self) -> SelectedPack:
        """Return portable identity metadata for compiled/resolved documents."""

        location = (
            f"{self.source}:{self.manifest.type}:{self.manifest.name}@{self.manifest.version}"
        )
        return SelectedPack(
            source=self.source,
            type=self.manifest.type,
            name=self.manifest.name,
            version=self.manifest.version,
            digest=self.digest,
            location=location,
        )


@dataclass(frozen=True, slots=True)
class _PackTreeEntry:
    """One bounded, no-follow entry in a validated pack tree."""

    path: Path
    relative_path: Path
    is_directory: bool
    size: int = 0


def _version_tuple(value: str) -> tuple[int, int, int]:
    """Parse the exact semantic-version subset used by public pack manifests."""

    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise PackError(f"invalid semantic version {value!r}; expected X.Y.Z")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _check_requires_evidenceforge(specifier: str) -> None:
    """Validate a comma-separated >=,>,<=,<,== compatibility expression."""

    current = _version_tuple(PACK_CAPABILITY_VERSION)
    for raw_clause in specifier.split(","):
        clause = raw_clause.strip()
        match = re.fullmatch(r"(>=|<=|==|>|<)(\d+\.\d+\.\d+)", clause)
        if match is None:
            raise PackError(
                "requires_evidenceforge must use comma-separated exact comparisons "
                "such as '>=2.0.0,<3.0.0'"
            )
        operator, raw_version = match.groups()
        required = _version_tuple(raw_version)
        accepted = {
            ">=": current >= required,
            "<=": current <= required,
            "==": current == required,
            ">": current > required,
            "<": current < required,
        }[operator]
        if not accepted:
            raise PackError(
                f"pack requires EvidenceForge {specifier}, but pack capability is "
                f"{PACK_CAPABILITY_VERSION}"
            )


def _canonical_digest(files: dict[str, bytes]) -> str:
    """Digest semantic paths and exact bytes in stable order."""

    digest = hashlib.sha256()
    for relative_path in sorted(files):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[relative_path])
        digest.update(b"\0")
    return digest.hexdigest()


def _safe_pack_file(root: Path, relative_path: str) -> Path:
    """Resolve one fixed pack path without traversal or symlink escape."""

    candidate = root / relative_path
    relative_components = candidate.relative_to(root).parts
    current = root
    if any((current := current / component).is_symlink() for component in relative_components):
        raise PackError(f"pack semantic file cannot be a symlink: {candidate}")
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise PackError(f"pack semantic path escapes pack root: {relative_path}")
    if not resolved.is_file():
        raise PackError(f"required pack file is missing: {relative_path}")
    return resolved


def _path_exists(path: Path) -> bool:
    """Return whether a filesystem entry exists, including a dangling symlink."""

    return os.path.lexists(path)


def _bounded_pack_tree(root: Path) -> tuple[_PackTreeEntry, ...]:
    """Inventory a complete pack without following links or exceeding hard limits."""

    root = Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir():
        raise PackError(f"pack root must be a regular directory: {root}")

    budget = PACK_TREE_BUDGET
    discovered: list[_PackTreeEntry] = []
    directories: list[Path] = [root]
    entry_count = 0
    file_count = 0
    total_bytes = 0

    while directories:
        directory = directories.pop()
        descriptor: int | None = None
        try:
            descriptor = os.open(directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise PackError(f"pack path is not a directory: {directory}")
            with os.scandir(descriptor) as iterator:
                entries = [
                    (entry.name, entry.stat(follow_symlinks=False))
                    for entry in sorted(iterator, key=lambda item: item.name)
                ]
        except PackError:
            raise
        except OSError as exc:
            raise PackError(f"unable to safely inspect pack directory {directory}: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

        for entry_name, entry_metadata in entries:
            path = directory / entry_name
            relative_path = path.relative_to(root)
            depth = len(relative_path.parts)
            entry_count += 1
            if entry_count > budget.max_entries:
                raise PackError(f"pack tree entry count exceeds limit {budget.max_entries}: {path}")
            if depth > budget.max_depth:
                raise PackError(f"pack tree depth exceeds limit {budget.max_depth}: {path}")
            mode = entry_metadata.st_mode
            if stat.S_ISLNK(mode):
                raise PackError(f"pack path cannot be a symlink: {path}")
            if stat.S_ISDIR(mode):
                discovered.append(
                    _PackTreeEntry(
                        path=path,
                        relative_path=relative_path,
                        is_directory=True,
                    )
                )
                directories.append(path)
                continue
            if not stat.S_ISREG(mode):
                raise PackError(f"pack path must be a regular file or directory: {path}")
            file_count += 1
            total_bytes += entry_metadata.st_size
            if file_count > budget.max_files:
                raise PackError(f"pack file count exceeds limit {budget.max_files}: {path}")
            if total_bytes > budget.max_bytes:
                raise PackError(
                    f"pack bytes exceed limit {budget.max_bytes}: "
                    f"found {total_bytes} bytes at {path}"
                )
            discovered.append(
                _PackTreeEntry(
                    path=path,
                    relative_path=relative_path,
                    is_directory=False,
                    size=entry_metadata.st_size,
                )
            )

    return tuple(
        sorted(
            discovered,
            key=lambda item: (len(item.relative_path.parts), item.relative_path.as_posix()),
        )
    )


def _read_regular_file_no_follow(path: Path, *, max_bytes: int | None = None) -> bytes:
    """Read one regular file without following it or exceeding a validated size."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PackError(f"pack path is not a regular file: {path}")
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise PackError(f"pack file exceeds bounded size {max_bytes}: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            content = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
            if max_bytes is not None and len(content) > max_bytes:
                raise PackError(f"pack file exceeds bounded size {max_bytes}: {path}")
            return content
    except PackError:
        raise
    except OSError as exc:
        raise PackError(f"unable to safely read pack file {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_pack_snapshot(
    file_bytes: dict[str, bytes],
    directories: frozenset[str],
) -> None:
    """Recheck immutable snapshot paths and resource bounds before a copy."""

    budget = PACK_TREE_BUDGET
    if len(file_bytes) > budget.max_files:
        raise PackError(f"pack file count exceeds limit {budget.max_files}")
    if len(file_bytes) + len(directories) > budget.max_entries:
        raise PackError(f"pack tree entry count exceeds limit {budget.max_entries}")
    total_bytes = sum(len(content) for content in file_bytes.values())
    if total_bytes > budget.max_bytes:
        raise PackError(
            f"pack bytes exceed limit {budget.max_bytes}: found {total_bytes} snapshot bytes"
        )

    file_paths = {Path(relative) for relative in file_bytes}
    directory_paths = {Path(relative) for relative in directories}
    for relative in file_paths | directory_paths:
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or relative == Path(".")
        ):
            raise PackError(f"pack snapshot contains an unsafe path: {relative}")
        if len(relative.parts) > budget.max_depth:
            raise PackError(f"pack tree depth exceeds limit {budget.max_depth}: {relative}")
    collisions = file_paths & directory_paths
    if collisions:
        raise PackError(f"pack snapshot path is both a file and directory: {min(collisions)}")
    for path in file_paths:
        if path.parent != Path(".") and path.parent not in directory_paths:
            raise PackError(f"pack snapshot is missing parent directory: {path.parent}")


def _write_new_file_no_follow(path: Path, content: bytes) -> None:
    """Create one new regular file without following or replacing a link."""

    parent_descriptor: int | None = None
    descriptor: int | None = None
    created = False
    completed = False
    try:
        parent_descriptor = os.open(path.parent, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        completed = True
    except FileExistsError as exc:
        raise PackError(f"refusing to overwrite staged pack file: {path}") from exc
    except OSError as exc:
        raise PackError(f"unable to safely create staged pack file {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created and not completed:
            try:
                os.unlink(path.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _rewrite_self_reference(value: Any, old_name: str, new_name: str) -> tuple[Any, bool]:
    """Rewrite one exact qualified self-reference, never a prose substring."""

    if not isinstance(value, str):
        return value, False
    match = re.fullmatch(rf"{re.escape(old_name)}:([A-Za-z0-9][A-Za-z0-9_.-]*)", value)
    if match is None:
        return value, False
    return f"{new_name}:{match.group(1)}", True


def _rewrite_reference_list(
    container: dict[str, Any], key: str, old_name: str, new_name: str
) -> bool:
    """Rewrite exact self-references in one known list-valued reference field."""

    values = container.get(key)
    if not isinstance(values, list):
        return False
    changed = False
    rewritten: list[Any] = []
    for value in values:
        replacement, item_changed = _rewrite_self_reference(value, old_name, new_name)
        rewritten.append(replacement)
        changed = changed or item_changed
    if changed:
        container[key] = rewritten
    return changed


def _rewrite_pack_self_references(document: Any, *, old_name: str, new_name: str) -> bool:
    """Rewrite only typed semantic self-reference fields in one pack YAML mapping."""

    if not isinstance(document, dict):
        return False
    changed = False

    personas = document.get("persona_catalog")
    if isinstance(personas, dict):
        for entry in personas.values():
            if not isinstance(entry, dict):
                continue
            replacement, item_changed = _rewrite_self_reference(
                entry.get("name"), old_name, new_name
            )
            if item_changed:
                entry["name"] = replacement
                changed = True

    applications = document.get("application_catalog")
    if isinstance(applications, dict):
        for entry in applications.values():
            data = entry.get("data") if isinstance(entry, dict) else None
            if not isinstance(data, dict):
                continue
            changed = _rewrite_reference_list(data, "personas", old_name, new_name) or changed
            changed = _rewrite_reference_list(data, "processes", old_name, new_name) or changed
            connections = data.get("connections")
            connection_values = connections.values() if isinstance(connections, dict) else []
            for connection in connection_values:
                if not isinstance(connection, dict):
                    continue
                replacement, item_changed = _rewrite_self_reference(
                    connection.get("destination"), old_name, new_name
                )
                if item_changed:
                    connection["destination"] = replacement
                    changed = True

    destinations = document.get("destination_catalog")
    if isinstance(destinations, dict):
        for entry in destinations.values():
            data = entry.get("data") if isinstance(entry, dict) else None
            if isinstance(data, dict):
                changed = _rewrite_reference_list(data, "tags", old_name, new_name) or changed

    traffic = document.get("traffic_catalog")
    if isinstance(traffic, dict):
        for entry in traffic.values():
            data = entry.get("data") if isinstance(entry, dict) else None
            if not isinstance(data, dict):
                continue
            changed = _rewrite_reference_list(data, "audience", old_name, new_name) or changed
            application_traffic = data.get("applications")
            if isinstance(application_traffic, list):
                for application in application_traffic:
                    if not isinstance(application, dict):
                        continue
                    replacement, item_changed = _rewrite_self_reference(
                        application.get("application"), old_name, new_name
                    )
                    if item_changed:
                        application["application"] = replacement
                        changed = True
            outbound = data.get("outbound")
            if isinstance(outbound, list):
                for connection in outbound:
                    if isinstance(connection, dict):
                        changed = (
                            _rewrite_reference_list(
                                connection,
                                "dns_tags",
                                old_name,
                                new_name,
                            )
                            or changed
                        )

    environment = document.get("environment")
    if isinstance(environment, dict):
        users = environment.get("users")
        if isinstance(users, list):
            for user in users:
                if not isinstance(user, dict):
                    continue
                replacement, item_changed = _rewrite_self_reference(
                    user.get("persona"), old_name, new_name
                )
                if item_changed:
                    user["persona"] = replacement
                    changed = True
        storage = environment.get("storage")
        servers = storage.get("servers") if isinstance(storage, dict) else None
        if isinstance(servers, list):
            for server in servers:
                shares = server.get("shares") if isinstance(server, dict) else None
                if not isinstance(shares, list):
                    continue
                for share in shares:
                    if not isinstance(share, dict):
                        continue
                    replacement, item_changed = _rewrite_self_reference(
                        share.get("preset"), old_name, new_name
                    )
                    if item_changed:
                        share["preset"] = replacement
                        changed = True

    baseline_activity = document.get("baseline_activity")
    if isinstance(baseline_activity, dict):
        for collection_name in ("traffic_affinities", "traffic_suppression"):
            entries = baseline_activity.get(collection_name)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                audience = entry.get("audience") if isinstance(entry, dict) else None
                if isinstance(audience, dict):
                    changed = (
                        _rewrite_reference_list(
                            audience,
                            "personas",
                            old_name,
                            new_name,
                        )
                        or changed
                    )
    return changed


def _qualify_organization_reference(
    reference: Any,
    *,
    owner: str,
    local_exports: set[str],
    builtin_ids: set[str],
) -> Any:
    """Qualify local shorthand while preserving packaged built-in shorthand."""

    if not isinstance(reference, str) or ":" in reference:
        return reference
    local_reference = f"{owner}:{reference}"
    if local_reference in local_exports or reference not in builtin_ids:
        return local_reference
    return reference


def _qualify_organization_environment_references(
    environment: dict[str, Any],
    owner: str,
    *,
    local_persona_exports: set[str],
    local_storage_exports: set[str],
    builtin_persona_ids: set[str],
    builtin_storage_preset_ids: set[str],
) -> None:
    """Qualify local organization references without claiming packaged built-ins."""

    for user in environment.get("users", []):
        if not isinstance(user, dict):
            continue
        user["persona"] = _qualify_organization_reference(
            user.get("persona"),
            owner=owner,
            local_exports=local_persona_exports,
            builtin_ids=builtin_persona_ids,
        )
    storage = environment.get("storage")
    if not isinstance(storage, dict):
        return
    for server in storage.get("servers", []):
        if not isinstance(server, dict):
            continue
        for share in server.get("shares", []):
            if not isinstance(share, dict):
                continue
            share["preset"] = _qualify_organization_reference(
                share.get("preset"),
                owner=owner,
                local_exports=local_storage_exports,
                builtin_ids=builtin_storage_preset_ids,
            )


def _qualify_organization_baseline_references(
    baseline_activity: dict[str, Any],
    owner: str,
    *,
    local_persona_exports: set[str],
    builtin_persona_ids: set[str],
) -> None:
    """Qualify local organization selectors while preserving built-in personas."""

    for collection_name in ("traffic_affinities", "traffic_suppression"):
        for entry in baseline_activity.get(collection_name, []):
            audience = entry.get("audience") if isinstance(entry, dict) else None
            if not isinstance(audience, dict):
                continue
            personas = audience.get("personas")
            if isinstance(personas, list):
                audience["personas"] = [
                    _qualify_organization_reference(
                        persona,
                        owner=owner,
                        local_exports=local_persona_exports,
                        builtin_ids=builtin_persona_ids,
                    )
                    for persona in personas
                ]


def _load_pack_document(
    root: Path,
    relative_path: str,
    model: type[BaseModel],
    *,
    include_budget_state: ScenarioIncludeBudgetState | None = None,
) -> tuple[BaseModel, LoadedSourceGraph]:
    """Load one pack YAML document and enforce include containment."""

    try:
        path = _safe_pack_file(root, relative_path)
        graph = load_scenario_source_graph(
            path,
            include_budget_state=include_budget_state,
            allowed_root=root,
        )
    except PackError:
        raise
    except (ConfigurationError, FileNotFoundError, OSError, yaml.YAMLError) as exc:
        raise PackError(f"invalid {relative_path}: {exc}") from exc
    try:
        return model.model_validate(graph.data), graph
    except ValidationError as exc:
        raise PackError(f"invalid {relative_path}: {exc}") from exc


def _declaring_file_for(graph: LoadedSourceGraph, path: tuple[str, ...]) -> Path:
    """Return the source that declared a field, falling back through its parents."""

    current = path
    while current:
        source = graph.origins.get(current)
        if source is not None:
            return source
        current = current[:-1]
    return graph.root


def _portable_pack_field_origins(
    graph: LoadedSourceGraph,
    *,
    root: Path,
) -> dict[str, str]:
    """Return include-aware field origins as portable paths relative to one pack."""

    resolved_root = root.resolve()
    return {
        ".".join(path): source.resolve().relative_to(resolved_root).as_posix()
        for path, source in sorted(graph.origins.items())
    }


def _portable_catalog_field_origins(
    graph: LoadedSourceGraph,
    *,
    root: Path,
    catalog_name: str,
    owner: str,
) -> dict[str, str]:
    """Return portable catalog origins using the runtime-qualified export identity."""

    resolved_root = root.resolve()
    origins: dict[str, str] = {}
    for path, source in sorted(graph.origins.items()):
        qualified_path = list(path)
        if len(qualified_path) >= 2 and qualified_path[0] == catalog_name:
            qualified_path[1] = f"{owner}:{qualified_path[1]}"
        origins[".".join(qualified_path)] = source.resolve().relative_to(resolved_root).as_posix()
    return origins


def _capture_graph_source_bytes(
    captured: dict[Path, bytes],
    graph: LoadedSourceGraph,
    *,
    root: Path,
) -> None:
    """Retain the exact bytes parsed by a graph and reject inconsistent rereads."""

    lexical_root = Path(os.path.abspath(root))
    for source in graph.sources:
        path = Path(os.path.abspath(source.path))
        try:
            path.relative_to(lexical_root)
        except ValueError as exc:
            raise PackError(f"captured pack source escapes pack root: {path}") from exc
        previous = captured.get(path)
        if previous is not None and previous != source.content:
            raise PackError(f"pack source changed while being validated: {path}")
        captured[path] = source.content


class PackRepository:
    """Resolve exact whole-pack references from explicit, bounded roots."""

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        self.package_root = (get_config_directory() / "packs").resolve()
        # Keep this path lexical so an existing .eforge/packs symlink cannot be
        # silently collapsed into an out-of-project authoring destination.
        self.project_pack_root = self.project_root / ".eforge" / "packs"

    def _assert_project_path_safe(self, path: Path) -> None:
        """Require a lexical project-pack path with no existing symlink component."""

        absolute = path.absolute()
        try:
            relative = absolute.relative_to(self.project_root)
            absolute.relative_to(self.project_pack_root)
        except ValueError as exc:
            raise PackError(f"project pack path escapes project root: {absolute}") from exc
        current = self.project_root
        for component in relative.parts:
            current /= component
            if current.is_symlink():
                raise PackError(f"project pack path cannot contain a symlink: {current}")

    def _ensure_project_directory(self, path: Path) -> Path:
        """Create a contained project-pack directory tree without accepting symlinks."""

        self._assert_project_path_safe(path)
        relative = path.absolute().relative_to(self.project_root)
        current = self.project_root
        for component in relative.parts:
            current /= component
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise PackError(
                    f"unable to create project pack directory {current}: {exc}"
                ) from exc
            if current.is_symlink() or not current.is_dir():
                raise PackError(f"project pack path is not a safe directory: {current}")
        return current

    @staticmethod
    def _validated_authoring_manifest(
        *,
        pack_type: PackType,
        name: str,
        version: str,
        source_manifest: PackManifest | None = None,
    ) -> PackManifest:
        """Freshly validate an authoring identity before it participates in a path."""

        if source_manifest is None:
            document: dict[str, Any] = {
                "pack_schema_version": "1.0",
                "type": pack_type,
                "name": name,
                "version": version,
                "description": f"{name} {pack_type} pack",
            }
        else:
            document = source_manifest.model_dump(mode="json", exclude_none=True)
            document.update({"type": pack_type, "name": name, "version": version})
        try:
            return PackManifest.model_validate(document)
        except ValidationError as exc:
            raise PackError(f"invalid pack identity {name!r}@{version!r}: {exc}") from exc

    def _authoring_paths(self, manifest: PackManifest) -> tuple[Path, Path, Path]:
        """Return a safe parent, destination, and new sibling staging directory."""

        parent = self.project_pack_root / manifest.type / manifest.name
        parent = self._ensure_project_directory(parent)
        destination = parent / manifest.version
        self._assert_project_path_safe(destination)
        if _path_exists(destination):
            raise PackError(f"pack destination already exists: {destination}")
        try:
            staging = Path(
                tempfile.mkdtemp(prefix=f".{manifest.version}.tmp-", dir=parent)
            ).absolute()
        except OSError as exc:
            raise PackError(f"unable to create staged pack beside {destination}: {exc}") from exc
        self._assert_project_path_safe(staging)
        if staging.parent != parent or staging.is_symlink() or not staging.is_dir():
            self._remove_owned_path(staging)
            raise PackError(f"staged pack path is unsafe: {staging}")
        return parent, destination, staging

    @staticmethod
    def _remove_owned_path(path: Path) -> None:
        """Remove a staging or destination path created by this repository operation."""

        if path.is_symlink():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)
        elif _path_exists(path):
            path.unlink(missing_ok=True)

    def _publish_staged_pack(self, staging: Path, destination: Path) -> None:
        """Atomically publish a stage after exclusively reserving its destination."""

        self._assert_project_path_safe(staging)
        self._assert_project_path_safe(destination)
        if staging.parent != destination.parent:
            raise PackError("staged pack must be a sibling of its destination")
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise PackError(f"pack destination already exists: {destination}") from exc
        except OSError as exc:
            raise PackError(f"unable to reserve pack destination {destination}: {exc}") from exc
        try:
            os.replace(staging, destination)
        except OSError as exc:
            try:
                destination.rmdir()
            except OSError:
                pass
            raise PackError(f"unable to publish staged pack at {destination}: {exc}") from exc

    def _reload_authored_pack(self, destination: Path, manifest: PackManifest) -> LoadedPack:
        """Load a newly published project pack through the normal repository path."""

        reference = PackReference(
            source="project",
            name=manifest.name,
            version=manifest.version,
        )
        loaded = self.resolve(reference, expected_type=manifest.type)
        if loaded.root != destination.resolve():
            raise PackError(
                f"published pack resolved to an unexpected repository path: {loaded.root}"
            )
        self.validate_semantics(loaded)
        return loaded

    def validate_semantics(self, pack: LoadedPack) -> list[LoadedPack]:
        """Validate one pack together with its exact declared industry dependencies."""

        dependencies = [
            self.resolve(
                dependency,
                expected_type="industry",
                declaring_file=pack.industry_dependency_declaring_files[index],
            )
            for index, dependency in enumerate(pack.manifest.industry_dependencies)
        ]
        validate_selected_pack_semantics(
            [*dependencies, pack],
            builtin_application_ids=packaged_builtin_application_ids(),
            builtin_dns_tags=packaged_builtin_dns_tags(),
            builtin_executable_claims=packaged_builtin_executable_claims(),
            builtin_dns_domains=packaged_builtin_dns_domains(),
            builtin_persona_ids=packaged_builtin_persona_ids(),
            builtin_storage_preset_ids=packaged_builtin_storage_preset_ids(),
        )
        return dependencies

    def root_for(self, source: PackSource) -> Path:
        """Return a package or project repository root."""

        if source == "package":
            return self.package_root
        if source == "project":
            self._assert_project_path_safe(self.project_pack_root)
            return self.project_pack_root
        raise PackError("source: path does not have a repository root")

    def list(self) -> list[LoadedPack]:
        """List valid package and project packs without consulting a global registry."""

        packs: list[LoadedPack] = []
        for source in ("package", "project"):
            root = self.root_for(source)
            if not root.is_dir():
                continue
            for pack_type in ("industry", "organization"):
                type_root = root / pack_type
                if not type_root.is_dir():
                    continue
                for name_root in sorted(type_root.iterdir()):
                    if not name_root.is_dir() or name_root.is_symlink():
                        continue
                    for version_root in sorted(name_root.iterdir()):
                        if not version_root.is_dir() or version_root.is_symlink():
                            continue
                        try:
                            reference = PackReference(
                                source=source,
                                name=name_root.name,
                                version=version_root.name,
                            )
                        except ValidationError as exc:
                            raise PackError(
                                f"invalid {source} pack directory identity: {version_root}"
                            ) from exc
                        packs.append(self.resolve(reference, expected_type=pack_type))
        return packs

    def resolve(
        self,
        reference: PackReference,
        *,
        expected_type: PackType,
        declaring_file: Path | None = None,
    ) -> LoadedPack:
        """Resolve and validate one exact reference."""

        if reference.source == "path":
            if declaring_file is None:
                base = self.project_root
            else:
                base = declaring_file.resolve().parent
            raw_root = Path(reference.path or "")
            unresolved_root = raw_root if raw_root.is_absolute() else base / raw_root
            unresolved_root = Path(os.path.abspath(unresolved_root))
            if any(
                component.is_symlink() for component in (unresolved_root, *unresolved_root.parents)
            ):
                raise PackError(f"explicit pack path cannot contain a symlink: {unresolved_root}")
            root = unresolved_root.resolve()
        else:
            unresolved_root = (
                self.root_for(reference.source) / expected_type / reference.name / reference.version
            )
            if reference.source == "project":
                self._assert_project_path_safe(unresolved_root)
            root = unresolved_root.resolve()
            if reference.source == "project" and not root.is_relative_to(
                self.project_pack_root.resolve()
            ):
                raise PackError(f"project pack path escapes repository root: {root}")
        if root.is_symlink() or not root.is_dir():
            raise PackError(
                f"{reference.source} {expected_type} pack "
                f"{reference.name}@{reference.version} was not found at {root}"
            )
        return self._load(
            root, source=reference.source, reference=reference, expected_type=expected_type
        )

    def _load(
        self,
        root: Path,
        *,
        source: PackSource,
        reference: PackReference,
        expected_type: PackType,
    ) -> LoadedPack:
        """Load and validate a resolved pack directory."""

        tree_entries = _bounded_pack_tree(root)
        include_budget_state = ScenarioIncludeBudgetState(PACK_SEMANTIC_BUDGET)
        semantic_bytes_by_path: dict[Path, bytes] = {}
        try:
            manifest_document, manifest_graph = _load_pack_document(
                root,
                PACK_MANIFEST_FILENAME,
                PackManifest,
                include_budget_state=include_budget_state,
            )
            manifest = PackManifest.model_validate(manifest_document)
            _capture_graph_source_bytes(
                semantic_bytes_by_path,
                manifest_graph,
                root=root,
            )
        except PackError:
            raise
        except (ConfigurationError, ValidationError, OSError, yaml.YAMLError) as exc:
            raise PackError(
                f"invalid pack manifest {root / PACK_MANIFEST_FILENAME}: {exc}"
            ) from exc
        if manifest.type != expected_type:
            raise PackError(
                f"pack type mismatch: expected {expected_type}, manifest declares {manifest.type}"
            )
        if manifest.name != reference.name or manifest.version != reference.version:
            raise PackError(
                "pack reference identity does not match manifest: "
                f"requested {reference.name}@{reference.version}, found "
                f"{manifest.name}@{manifest.version}"
            )
        if source != "path":
            expected_suffix = Path(expected_type) / manifest.name / manifest.version
            if root.parts[-3:] != expected_suffix.parts:
                raise PackError(f"pack directory identity does not match manifest: {root}")
        _check_requires_evidenceforge(manifest.requires_evidenceforge)

        lock = PackLock()
        lock_files: set[Path] = set()
        lock_path = root / PACK_LOCK_FILENAME
        if lock_path.is_file():
            try:
                lock_document, lock_graph = _load_pack_document(
                    root,
                    PACK_LOCK_FILENAME,
                    PackLock,
                    include_budget_state=include_budget_state,
                )
                lock = PackLock.model_validate(lock_document)
                _capture_graph_source_bytes(semantic_bytes_by_path, lock_graph, root=root)
                lock_files = {source.path for source in lock_graph.sources}
            except (ConfigurationError, ValidationError, OSError, yaml.YAMLError) as exc:
                raise PackError(f"invalid pack lock {lock_path}: {exc}") from exc
        elif manifest.pack_schema_version == "2.0":
            raise PackError(f"pack schema 2.0 requires {PACK_LOCK_FILENAME}: {root}")

        catalogs: dict[str, dict[str, Any]] = {}
        catalog_field_origins: dict[str, str] = {}
        semantic_files: set[Path] = {source.path for source in manifest_graph.sources} | lock_files
        payload_files: set[Path] = set()
        for catalog_name, relative_path, model in CATALOG_FILES:
            document, document_graph = _load_pack_document(
                root,
                relative_path,
                model,
                include_budget_state=include_budget_state,
            )
            raw_entries = document.model_dump(mode="json")[catalog_name]
            qualified_entries: dict[str, Any] = {}
            for entry_name, entry in raw_entries.items():
                qualified_name = f"{manifest.name}:{entry_name}"
                qualified_entry = copy.deepcopy(entry)
                if catalog_name == "persona_catalog":
                    qualified_entry["name"] = qualified_name
                elif catalog_name == "traffic_catalog":
                    audience = qualified_entry["data"].get("audience", [])
                    qualified_entry["data"]["audience"] = [
                        name if ":" in name else f"{manifest.name}:{name}" for name in audience
                    ]
                qualified_entries[qualified_name] = qualified_entry
            catalogs[catalog_name] = qualified_entries
            document_files = {source.path for source in document_graph.sources}
            _capture_graph_source_bytes(
                semantic_bytes_by_path,
                document_graph,
                root=root,
            )
            semantic_files.update(document_files)
            payload_files.update(document_files)
            catalog_field_origins.update(
                _portable_catalog_field_origins(
                    document_graph,
                    root=root,
                    catalog_name=catalog_name,
                    owner=manifest.name,
                )
            )

        environment: dict[str, Any] = {}
        baseline_activity: dict[str, Any] = {}
        organization_model_origins: dict[str, str] = {}
        if manifest.type == "organization":
            environment_document, environment_graph = _load_pack_document(
                root,
                "model/environment.yaml",
                EnvironmentFragment,
                include_budget_state=include_budget_state,
            )
            baseline_document, baseline_graph = _load_pack_document(
                root,
                "model/baseline_activity.yaml",
                BaselineActivityFragment,
                include_budget_state=include_budget_state,
            )
            environment = environment_document.model_dump(mode="json")["environment"]
            baseline_activity = baseline_document.model_dump(mode="json")["baseline_activity"]
            builtin_personas = packaged_builtin_persona_ids()
            _qualify_organization_environment_references(
                environment,
                manifest.name,
                local_persona_exports=set(catalogs["persona_catalog"]),
                local_storage_exports=set(catalogs["storage_catalog"]),
                builtin_persona_ids=builtin_personas,
                builtin_storage_preset_ids=packaged_builtin_storage_preset_ids(),
            )
            _qualify_organization_baseline_references(
                baseline_activity,
                manifest.name,
                local_persona_exports=set(catalogs["persona_catalog"]),
                builtin_persona_ids=builtin_personas,
            )
            environment_files = {source.path for source in environment_graph.sources}
            baseline_files = {source.path for source in baseline_graph.sources}
            _capture_graph_source_bytes(
                semantic_bytes_by_path,
                environment_graph,
                root=root,
            )
            _capture_graph_source_bytes(
                semantic_bytes_by_path,
                baseline_graph,
                root=root,
            )
            semantic_files.update(environment_files | baseline_files)
            payload_files.update(environment_files | baseline_files)
            organization_model_origins.update(
                _portable_pack_field_origins(environment_graph, root=root)
            )
            organization_model_origins.update(
                _portable_pack_field_origins(baseline_graph, root=root)
            )

        dependency_declaring_files = tuple(
            _declaring_file_for(
                manifest_graph,
                ("industry_dependencies", str(index), "path"),
            )
            for index, _dependency in enumerate(manifest.industry_dependencies)
        )

        all_yaml = {
            entry.path
            for entry in tree_entries
            if not entry.is_directory and entry.path.suffix in {".yaml", ".yml"}
        }
        orphan_yaml = sorted(all_yaml - semantic_files, key=str)
        if orphan_yaml:
            names = ", ".join(str(path.relative_to(root)) for path in orphan_yaml)
            raise PackError(f"pack contains unreferenced semantic YAML file(s): {names}")
        companion_file_bytes: dict[str, bytes] = {}
        for entry in tree_entries:
            if entry.is_directory or entry.path.suffix in {".yaml", ".yml"}:
                continue
            if entry.path.name not in ALLOWED_NONSEMANTIC_FILES:
                raise PackError(f"pack contains forbidden unconstrained asset: {entry.path}")
            companion_file_bytes[entry.relative_path.as_posix()] = _read_regular_file_no_follow(
                entry.path,
                max_bytes=entry.size,
            )

        file_bytes = {
            str(path.relative_to(root)): semantic_bytes_by_path[path]
            for path in sorted(semantic_bytes_by_path, key=str)
        }
        source_directories = frozenset(
            entry.relative_path.as_posix() for entry in tree_entries if entry.is_directory
        )
        _validate_pack_snapshot(
            {**file_bytes, **companion_file_bytes},
            source_directories,
        )
        digest = _canonical_digest(file_bytes)
        if source == "package":
            self._verify_packaged_digest(manifest, digest)
        assets = {
            relative: content.decode("utf-8")
            for relative, content in file_bytes.items()
            if relative != PACK_MANIFEST_FILENAME
        }
        return LoadedPack(
            manifest=manifest,
            lock=lock,
            source=source,
            root=root,
            digest=digest,
            catalogs=catalogs,
            environment=environment,
            baseline_activity=baseline_activity,
            assets=assets,
            semantic_file_bytes=tuple(sorted(file_bytes.items())),
            companion_file_bytes=tuple(sorted(companion_file_bytes.items())),
            source_directories=source_directories,
            payload_files=frozenset(
                str(path.relative_to(root)) for path in sorted(payload_files, key=str)
            ),
            catalog_field_origins=catalog_field_origins,
            organization_model_origins=organization_model_origins,
            industry_dependency_declaring_files=dependency_declaring_files,
        )

    def _verify_packaged_digest(self, manifest: PackManifest, digest: str) -> None:
        """Enforce the installed packaged-pack immutability index when present."""

        index_path = self.package_root / PACKAGED_INDEX_FILENAME
        if not index_path.is_file():
            raise PackError(f"packaged pack digest index is missing: {index_path}")
        try:
            data = json.loads(
                _read_regular_file_no_follow(
                    index_path,
                    max_bytes=PACK_TREE_BUDGET.max_bytes,
                ).decode("utf-8")
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PackError(f"packaged pack digest index is invalid: {index_path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("packs"), dict):
            raise PackError(
                f"packaged pack digest index must contain a 'packs' mapping: {index_path}"
            )
        key = f"{manifest.type}/{manifest.name}/{manifest.version}"
        expected = data["packs"].get(key)
        if expected is None:
            raise PackError(f"packaged pack {key} is missing from the digest index")
        if expected != digest:
            raise PackError(f"packaged pack digest mismatch for {key}")

    def create_skeleton(self, pack_type: PackType, name: str, version: str) -> Path:
        """Create a complete project-local pack skeleton without overwriting."""

        manifest = self._validated_authoring_manifest(
            pack_type=pack_type,
            name=name,
            version=version,
        )
        _parent, destination, staging = self._authoring_paths(manifest)
        published = False
        try:
            (staging / "catalogs").mkdir(mode=0o700)
            _write_new_file_no_follow(
                staging / PACK_MANIFEST_FILENAME,
                yaml.safe_dump(
                    manifest.model_dump(mode="json", exclude_none=True), sort_keys=False
                ).encode("utf-8"),
            )
            _write_new_file_no_follow(
                staging / PACK_LOCK_FILENAME,
                yaml.safe_dump(PackLock().model_dump(mode="json"), sort_keys=False).encode("utf-8"),
            )
            for catalog_name, relative_path, _model in CATALOG_FILES:
                _write_new_file_no_follow(
                    staging / relative_path,
                    yaml.safe_dump({catalog_name: {}}, sort_keys=False).encode("utf-8"),
                )
            if pack_type == "organization":
                (staging / "model").mkdir(mode=0o700)
                _write_new_file_no_follow(staging / "model/environment.yaml", b"environment: {}\n")
                _write_new_file_no_follow(
                    staging / "model/baseline_activity.yaml", b"baseline_activity: {}\n"
                )
            self._load(
                staging,
                source="path",
                reference=PackReference(
                    source="path",
                    path=str(staging),
                    name=manifest.name,
                    version=manifest.version,
                ),
                expected_type=manifest.type,
            )
            self._publish_staged_pack(staging, destination)
            published = True
            self._reload_authored_pack(destination, manifest)
        except (PackError, OSError, ValueError) as exc:
            if published:
                self._remove_owned_path(destination)
            if isinstance(exc, PackError):
                raise
            raise PackError(f"unable to create pack skeleton: {exc}") from exc
        finally:
            if _path_exists(staging):
                self._remove_owned_path(staging)
        return destination

    @staticmethod
    def _copied_file_bytes(
        path: Path,
        content: bytes,
        *,
        old_name: str,
        new_name: str,
    ) -> bytes:
        """Rewrite typed YAML self-references in one captured source file when needed."""

        if path.suffix not in {".yaml", ".yml"}:
            return content
        try:
            document = load_yaml_text(content.decode("utf-8"), source=str(path))
        except (UnicodeError, yaml.YAMLError) as exc:
            raise PackError(f"invalid copied pack YAML {path}: {exc}") from exc
        if not _rewrite_pack_self_references(
            document,
            old_name=old_name,
            new_name=new_name,
        ):
            return content
        return yaml.safe_dump(document, sort_keys=False).encode("utf-8")

    @classmethod
    def _copy_pack_tree(
        cls,
        source_pack: LoadedPack,
        staging: Path,
        *,
        old_name: str,
        new_name: str,
    ) -> None:
        """Copy only the immutable, bounded source snapshot retained at validation."""

        file_bytes = dict(source_pack.semantic_file_bytes)
        file_bytes.update(source_pack.companion_file_bytes)
        _validate_pack_snapshot(file_bytes, source_pack.source_directories)

        for relative_text in sorted(
            source_pack.source_directories,
            key=lambda value: (len(Path(value).parts), value),
        ):
            relative = Path(relative_text)
            target = staging / relative
            try:
                target.mkdir(mode=0o700)
            except FileExistsError as exc:
                if target.is_symlink() or not target.is_dir():
                    raise PackError(f"staged pack directory is unsafe: {target}") from exc

        for relative_text, captured_content in sorted(file_bytes.items()):
            relative = Path(relative_text)
            target = staging / relative
            if relative_text in {PACK_MANIFEST_FILENAME, "COPY_PROVENANCE.md"}:
                continue
            if (
                relative.suffix in {".yaml", ".yml"}
                and relative_text not in source_pack.payload_files
                and relative_text != PACK_LOCK_FILENAME
            ):
                # The destination writes one canonical flattened manifest. YAML
                # used only by the source manifest include graph would otherwise
                # become an orphan semantic file in the copied pack.
                continue
            content = cls._copied_file_bytes(
                relative,
                captured_content,
                old_name=old_name,
                new_name=new_name,
            )
            _write_new_file_no_follow(target, content)

    @staticmethod
    def _relocate_path_dependencies(
        source_pack: LoadedPack,
        manifest: PackManifest,
        *,
        destination: Path,
    ) -> PackManifest:
        """Keep relative path dependencies pointed at the same target after a copy."""

        if len(source_pack.industry_dependency_declaring_files) != len(
            manifest.industry_dependencies
        ):
            raise PackError("pack dependency provenance is incomplete; refusing unsafe copy")
        relocated_dependencies = []
        for index, dependency in enumerate(manifest.industry_dependencies):
            raw_path = Path(dependency.path or "")
            if dependency.source != "path" or raw_path.is_absolute():
                relocated_dependencies.append(dependency)
                continue
            declaring_file = source_pack.industry_dependency_declaring_files[index]
            target = Path(os.path.abspath(declaring_file.parent / raw_path))
            relocated = Path(os.path.relpath(target, start=destination)).as_posix()
            relocated_dependencies.append(dependency.model_copy(update={"path": relocated}))
        return PackManifest.model_validate(
            {
                **manifest.model_dump(mode="json", exclude_none=True),
                "industry_dependencies": [
                    dependency.model_dump(mode="json", exclude_none=True)
                    for dependency in relocated_dependencies
                ],
            }
        )

    def copy(
        self,
        source_pack: LoadedPack,
        *,
        name: str,
        version: str,
    ) -> Path:
        """Copy one validated pack into the project repository with a new identity."""

        manifest = self._validated_authoring_manifest(
            pack_type=source_pack.manifest.type,
            name=name,
            version=version,
            source_manifest=source_pack.manifest,
        )
        _parent, destination, staging = self._authoring_paths(manifest)
        manifest = self._relocate_path_dependencies(
            source_pack,
            manifest,
            destination=destination,
        )
        copied_from = (
            f"{source_pack.source}:{source_pack.manifest.type}:"
            f"{source_pack.manifest.name}@{source_pack.manifest.version}"
        )
        source_location = str(source_pack.root) if source_pack.source == "path" else copied_from
        published = False
        try:
            self._copy_pack_tree(
                source_pack,
                staging,
                old_name=source_pack.manifest.name,
                new_name=manifest.name,
            )
            _write_new_file_no_follow(
                staging / PACK_MANIFEST_FILENAME,
                yaml.safe_dump(
                    manifest.model_dump(mode="json", exclude_none=True), sort_keys=False
                ).encode("utf-8"),
            )
            _write_new_file_no_follow(
                staging / "COPY_PROVENANCE.md",
                (
                    "# Copy provenance\n\n"
                    f"Copied from `{copied_from}` for project-local development.\n\n"
                    f"- Source reference: `{copied_from}`\n"
                    f"- Source location: `{source_location}`\n"
                    f"- Source digest: `sha256:{source_pack.digest}`\n\n"
                    "This file is non-semantic and is not included in the pack digest.\n"
                ).encode(),
            )
            self._load(
                staging,
                source="path",
                reference=PackReference(
                    source="path",
                    path=str(staging),
                    name=manifest.name,
                    version=manifest.version,
                ),
                expected_type=manifest.type,
            )
            self._publish_staged_pack(staging, destination)
            published = True
            self._reload_authored_pack(destination, manifest)
        except (PackError, OSError, ValueError) as exc:
            if published:
                self._remove_owned_path(destination)
            if isinstance(exc, PackError):
                raise
            raise PackError(f"unable to copy pack: {exc}") from exc
        finally:
            if _path_exists(staging):
                self._remove_owned_path(staging)
        return destination


def parse_pack_cli_reference(value: str) -> tuple[PackReference, PackType | None]:
    """Parse ``source:type:name@version`` or return a path reference candidate."""

    match = re.fullmatch(
        r"(package|project):(industry|organization):([a-z0-9][a-z0-9-]*)@(\d+\.\d+\.\d+)",
        value,
    )
    if match:
        source, pack_type, name, version = match.groups()
        return PackReference(source=source, name=name, version=version), pack_type  # type: ignore[arg-type]
    path = Path(value)
    manifest_path = path / PACK_MANIFEST_FILENAME if path.is_dir() else path
    if manifest_path.name != PACK_MANIFEST_FILENAME or not manifest_path.is_file():
        raise PackError(
            "pack reference must be source:type:name@version or a pack directory/path to pack.yaml"
        )
    if any(component.is_symlink() for component in (manifest_path, *manifest_path.parents)):
        raise PackError(f"pack manifest path cannot contain a symlink: {manifest_path}")
    try:
        root = manifest_path.parent.resolve()
        manifest_document, _manifest_graph = _load_pack_document(
            root,
            PACK_MANIFEST_FILENAME,
            PackManifest,
        )
        manifest = PackManifest.model_validate(manifest_document)
    except PackError:
        raise
    except (ConfigurationError, ValidationError, OSError, yaml.YAMLError) as exc:
        raise PackError(f"invalid pack manifest {manifest_path}: {exc}") from exc
    return (
        PackReference(
            source="path",
            path=str(root),
            name=manifest.name,
            version=manifest.version,
        ),
        manifest.type,
    )
