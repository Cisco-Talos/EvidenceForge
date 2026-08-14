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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from evidenceforge.config import get_config_directory
from evidenceforge.models.exceptions import PackError
from evidenceforge.utils import load_scenario_source_graph
from evidenceforge.utils.yaml_loader import load_yaml_file

from .models import (
    ApplicationCatalogDocument,
    BaselineActivityFragment,
    DestinationCatalogDocument,
    EnvironmentFragment,
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

PACK_CAPABILITY_VERSION = "2.0.0"
PACK_MANIFEST_FILENAME = "pack.yaml"
PACKAGED_INDEX_FILENAME = "index.json"
ALLOWED_NONSEMANTIC_FILES = {"README.md", "LICENSE", "LICENSE.md", "COPY_PROVENANCE.md"}

CATALOG_FILES: tuple[tuple[str, str, type[BaseModel]], ...] = (
    ("persona_catalog", "catalogs/persona_catalog.yaml", PersonaCatalogDocument),
    ("process_catalog", "catalogs/process_catalog.yaml", ProcessCatalogDocument),
    ("application_catalog", "catalogs/application_catalog.yaml", ApplicationCatalogDocument),
    ("destination_catalog", "catalogs/destination_catalog.yaml", DestinationCatalogDocument),
    ("traffic_catalog", "catalogs/traffic_catalog.yaml", TrafficCatalogDocument),
    ("storage_catalog", "catalogs/storage_catalog.yaml", StorageCatalogDocument),
)


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """One validated whole pack."""

    manifest: PackManifest
    source: PackSource
    root: Path
    digest: str
    catalogs: dict[str, dict[str, Any]]
    environment: dict[str, Any]
    baseline_activity: dict[str, Any]
    assets: dict[str, str]

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


def _load_pack_document(
    root: Path, relative_path: str, model: type[BaseModel]
) -> tuple[BaseModel, set[Path]]:
    """Load one pack YAML document and enforce include containment."""

    path = _safe_pack_file(root, relative_path)
    graph = load_scenario_source_graph(path)
    for source in graph.sources:
        if not source.path.is_relative_to(root.resolve()):
            raise PackError(
                f"pack include escapes pack root: {source.path} referenced by {relative_path}"
            )
    try:
        return model.model_validate(graph.data), {source.path for source in graph.sources}
    except ValidationError as exc:
        raise PackError(f"invalid {relative_path}: {exc}") from exc


class PackRepository:
    """Resolve exact whole-pack references from explicit, bounded roots."""

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        self.package_root = (get_config_directory() / "packs").resolve()
        self.project_pack_root = (self.project_root / ".eforge" / "packs").resolve()

    def root_for(self, source: PackSource) -> Path:
        """Return a package or project repository root."""

        if source == "package":
            return self.package_root
        if source == "project":
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
                        reference = PackReference(
                            source=source,
                            name=name_root.name,
                            version=version_root.name,
                        )
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
            root = (
                self.root_for(reference.source) / expected_type / reference.name / reference.version
            ).resolve()
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

        try:
            manifest_document, manifest_files = _load_pack_document(
                root, PACK_MANIFEST_FILENAME, PackManifest
            )
            manifest = PackManifest.model_validate(manifest_document)
        except (ValidationError, yaml.YAMLError) as exc:
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

        catalogs: dict[str, dict[str, Any]] = {}
        semantic_files: set[Path] = set(manifest_files)
        for catalog_name, relative_path, model in CATALOG_FILES:
            document, document_files = _load_pack_document(root, relative_path, model)
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
            semantic_files.update(document_files)

        environment: dict[str, Any] = {}
        baseline_activity: dict[str, Any] = {}
        if manifest.type == "organization":
            environment_document, environment_files = _load_pack_document(
                root, "model/environment.yaml", EnvironmentFragment
            )
            baseline_document, baseline_files = _load_pack_document(
                root, "model/baseline_activity.yaml", BaselineActivityFragment
            )
            environment = environment_document.model_dump(mode="json")["environment"]
            baseline_activity = baseline_document.model_dump(mode="json")["baseline_activity"]
            semantic_files.update(environment_files | baseline_files)

        all_yaml: set[Path] = set()
        yaml_paths = [*root.rglob("*.yaml"), *root.rglob("*.yml")]
        for path in yaml_paths:
            if path.is_symlink():
                raise PackError(f"pack YAML path is unsafe: {path}")
            resolved_path = path.resolve()
            if not resolved_path.is_relative_to(root.resolve()):
                raise PackError(f"pack YAML path is unsafe: {path}")
            all_yaml.add(resolved_path)
        orphan_yaml = sorted(all_yaml - semantic_files, key=str)
        if orphan_yaml:
            names = ", ".join(str(path.relative_to(root)) for path in orphan_yaml)
            raise PackError(f"pack contains unreferenced semantic YAML file(s): {names}")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise PackError(f"pack path cannot be a symlink: {path}")
            if path.is_file() and path.suffix not in {".yaml", ".yml"}:
                if path.name not in ALLOWED_NONSEMANTIC_FILES:
                    raise PackError(f"pack contains forbidden unconstrained asset: {path}")

        file_bytes = {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(semantic_files, key=str)
        }
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
            source=source,
            root=root,
            digest=digest,
            catalogs=catalogs,
            environment=environment,
            baseline_activity=baseline_activity,
            assets=assets,
        )

    def _verify_packaged_digest(self, manifest: PackManifest, digest: str) -> None:
        """Enforce the installed packaged-pack immutability index when present."""

        index_path = self.package_root / PACKAGED_INDEX_FILENAME
        if not index_path.is_file():
            raise PackError(f"packaged pack digest index is missing: {index_path}")
        data = json.loads(index_path.read_text(encoding="utf-8"))
        key = f"{manifest.type}/{manifest.name}/{manifest.version}"
        expected = data.get("packs", {}).get(key)
        if expected is None:
            raise PackError(f"packaged pack {key} is missing from the digest index")
        if expected != digest:
            raise PackError(f"packaged pack digest mismatch for {key}")

    def create_skeleton(self, pack_type: PackType, name: str, version: str) -> Path:
        """Create a complete project-local pack skeleton without overwriting."""

        manifest = PackManifest(
            type=pack_type,
            name=name,
            version=version,
            description=f"{name} {pack_type} pack",
        )
        destination = self.project_pack_root / pack_type / name / version
        if destination.exists() or destination.is_symlink():
            raise PackError(f"pack destination already exists: {destination}")
        (destination / "catalogs").mkdir(parents=True)
        (destination / PACK_MANIFEST_FILENAME).write_text(
            yaml.safe_dump(manifest.model_dump(mode="json", exclude_none=True), sort_keys=False),
            encoding="utf-8",
        )
        for catalog_name, relative_path, _model in CATALOG_FILES:
            (destination / relative_path).write_text(
                yaml.safe_dump({catalog_name: {}}, sort_keys=False), encoding="utf-8"
            )
        if pack_type == "organization":
            (destination / "model").mkdir()
            (destination / "model/environment.yaml").write_text(
                "environment: {}\n", encoding="utf-8"
            )
            (destination / "model/baseline_activity.yaml").write_text(
                "baseline_activity: {}\n", encoding="utf-8"
            )
        return destination

    def copy(
        self,
        source_pack: LoadedPack,
        *,
        name: str,
        version: str,
    ) -> Path:
        """Copy one validated pack into the project repository with a new identity."""

        destination = self.project_pack_root / source_pack.manifest.type / name / version
        if destination.exists() or destination.is_symlink():
            raise PackError(f"pack destination already exists: {destination}")
        shutil.copytree(source_pack.root, destination, symlinks=False)
        manifest_path = destination / PACK_MANIFEST_FILENAME
        copied_from = (
            f"{source_pack.source}:{source_pack.manifest.type}:"
            f"{source_pack.manifest.name}@{source_pack.manifest.version}"
        )
        manifest = source_pack.manifest.model_copy(update={"name": name, "version": version})
        manifest_path.write_text(
            yaml.safe_dump(manifest.model_dump(mode="json", exclude_none=True), sort_keys=False),
            encoding="utf-8",
        )
        (destination / "COPY_PROVENANCE.md").write_text(
            "# Copy provenance\n\n"
            f"Copied from `{copied_from}` for project-local development. "
            "This file is non-semantic and is not included in the pack digest.\n",
            encoding="utf-8",
        )
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
    manifest = PackManifest.model_validate(load_yaml_file(manifest_path))
    return (
        PackReference(
            source="path",
            path=str(manifest_path.parent),
            name=manifest.name,
            version=manifest.version,
        ),
        manifest.type,
    )
