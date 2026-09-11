#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Reissue a project-authored pack as an official package default.

This is intentionally a developer-maintainer utility rather than an ``eforge``
command.  It creates a new publisher-qualified identity, optionally promotes
the exact industry dependencies locked by an organization pack, and updates
the immutable package digest index only when ``apply`` is requested.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition.models import LockedPack, PackLock, PackType
from evidenceforge.composition.packs import (
    PACK_LOCK_FILENAME,
    PACK_MANIFEST_FILENAME,
    LoadedPack,
    PackRepository,
    pack_namespace,
    parse_pack_cli_reference,
)
from evidenceforge.composition.semantic_validation import (
    packaged_builtin_application_ids,
    packaged_builtin_dns_domains,
    packaged_builtin_dns_tags,
    packaged_builtin_executable_claims,
    packaged_builtin_persona_ids,
    packaged_builtin_storage_preset_ids,
    validate_selected_pack_semantics,
)
from evidenceforge.models.exceptions import PackError

LOGGER = logging.getLogger(__name__)
OFFICIAL_PUBLISHER = "evidenceforge"
DEFAULT_PUBLISHER_DISPLAY_NAME = "EvidenceForge"


class PromotionError(PackError):
    """Raised when a promotion cannot be made safely."""


class PromotionItem(BaseModel):
    """One package payload that will be created or reused."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["create", "reuse"]
    type: PackType
    name: str
    version: str
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    package_path: str
    files: list[str]


class PromotionPlan(BaseModel):
    """Machine-readable dry-run result for a promotion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source: str
    target_publisher: str
    target_publisher_display_name: str
    target_repo_root: str
    target_package_root: str
    root: PromotionItem
    dependencies: list[PromotionItem]
    namespace_rewrites: dict[str, str]
    index_updates: dict[str, str]
    applied: bool = False


class PreparedPromotion:
    """Validated promotion plan plus the captured package bytes to publish."""

    def __init__(
        self,
        *,
        plan: PromotionPlan,
        payloads: dict[tuple[PackType, str, str], LoadedPack],
        index_document: dict[str, Any],
    ) -> None:
        self.plan = plan
        self.payloads = payloads
        self.index_document = index_document


def _write_yaml(path: Path, document: Any) -> None:
    """Write one canonical YAML document used by the staged pack."""

    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML mapping from a staged semantic file."""

    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PromotionError(f"cannot read YAML file {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise PromotionError(f"expected YAML mapping in {path}")
    return document


def _rewrite_qualified_value(value: Any, rewrites: dict[str, str]) -> tuple[Any, bool]:
    """Rewrite an exact qualified public reference, never a prose substring."""

    if not isinstance(value, str):
        return value, False
    for old_namespace, new_namespace in sorted(rewrites.items(), key=lambda item: -len(item[0])):
        if value == old_namespace or value.startswith(f"{old_namespace}:"):
            return f"{new_namespace}{value[len(old_namespace) :]}", True
    return value, False


def _rewrite_dependency_references(value: Any, rewrites: dict[str, str]) -> tuple[Any, bool]:
    """Rewrite exact dependency export references in typed YAML structures."""

    if isinstance(value, dict):
        changed = False
        rewritten: dict[Any, Any] = {}
        for key, nested in value.items():
            replacement, nested_changed = _rewrite_dependency_references(nested, rewrites)
            rewritten[key] = replacement
            changed = changed or nested_changed
        return rewritten, changed
    if isinstance(value, list):
        changed = False
        rewritten_list: list[Any] = []
        for nested in value:
            replacement, nested_changed = _rewrite_dependency_references(nested, rewrites)
            rewritten_list.append(replacement)
            changed = changed or nested_changed
        return rewritten_list, changed
    return _rewrite_qualified_value(value, rewrites)


def _rewrite_dependency_yaml(root: Path, rewrites: dict[str, str]) -> None:
    """Rewrite dependency-qualified references in copied YAML payloads."""

    if not rewrites:
        return
    for path in sorted(root.rglob("*.yaml")):
        if path.name in {PACK_MANIFEST_FILENAME, PACK_LOCK_FILENAME}:
            continue
        document = _load_yaml(path)
        rewritten, changed = _rewrite_dependency_references(document, rewrites)
        if changed:
            _write_yaml(path, rewritten)


def _load_pack_at_path(
    repository: PackRepository, path: Path, expected_type: PackType
) -> LoadedPack:
    """Load a pack by path without consulting the installed package registry."""

    reference, parsed_type = parse_pack_cli_reference(str(path))
    if parsed_type != expected_type:
        raise PromotionError(f"expected a {expected_type} pack at {path}")
    return repository.resolve(reference, expected_type=expected_type)


def _package_path(package_root: Path, pack: LoadedPack) -> Path:
    """Return the package-default path for a loaded pack identity."""

    manifest = pack.manifest
    return package_root / manifest.publisher / manifest.type / manifest.name / manifest.version


def _index_key(pack: LoadedPack) -> str:
    """Return the immutable package index key for a pack."""

    manifest = pack.manifest
    return f"{manifest.publisher}/{manifest.type}/{manifest.name}/{manifest.version}"


def _load_index(path: Path) -> dict[str, Any]:
    """Load and validate the package digest index."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"cannot read package index {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("packs"), dict):
        raise PromotionError(f"package index must contain a packs mapping: {path}")
    return document


def _load_source_pack(
    repository: PackRepository, source: str, expected_type: PackType | None
) -> LoadedPack:
    """Resolve and semantically validate the requested source pack."""

    reference, parsed_type = parse_pack_cli_reference(source)
    pack_type = expected_type or parsed_type
    if pack_type is None:
        raise PromotionError("source pack type is required for an ambiguous reference")
    pack = repository.resolve(reference, expected_type=pack_type)
    repository.validate_semantics(pack)
    return pack


def _manifest_with_dependencies(
    path: Path,
    source_pack: LoadedPack,
    *,
    publisher: str,
    dependency_source: Literal["project", "package"],
) -> None:
    """Replace organization dependency identities while preserving constraints."""

    document = _load_yaml(path)
    dependencies = document.get("industry_dependencies")
    if not isinstance(dependencies, list):
        raise PromotionError(f"organization manifest has invalid dependencies: {path}")
    if len(dependencies) != len(source_pack.manifest.industry_dependencies):
        raise PromotionError("organization dependency provenance is incomplete")
    rewritten_dependencies: list[dict[str, Any]] = []
    for raw_dependency in dependencies:
        if not isinstance(raw_dependency, dict):
            raise PromotionError(f"organization dependency must be a mapping: {path}")
        rewritten = dict(raw_dependency)
        rewritten["source"] = dependency_source
        rewritten["publisher"] = publisher
        rewritten["type"] = "industry"
        rewritten.pop("path", None)
        rewritten_dependencies.append(rewritten)
    document["industry_dependencies"] = rewritten_dependencies
    _write_yaml(path, document)


def _write_lock(path: Path, dependencies: list[LoadedPack]) -> None:
    """Write an exact official lock for the staged organization pack."""

    lock = PackLock(
        dependencies=[
            LockedPack(
                publisher=pack.manifest.publisher,
                type=pack.manifest.type,
                name=pack.manifest.name,
                version=pack.manifest.version,
                digest=pack.digest,
            )
            for pack in dependencies
        ]
    )
    _write_yaml(path, lock.model_dump(mode="json"))


def _item(
    action: Literal["create", "reuse"], package_root: Path, pack: LoadedPack
) -> PromotionItem:
    """Build a plan item from one validated pack."""

    relative_files = sorted(
        {relative for relative, _content in pack.semantic_file_bytes}
        | {relative for relative, _content in pack.companion_file_bytes}
    )
    target = _package_path(package_root, pack)
    return PromotionItem(
        action=action,
        type=pack.manifest.type,
        name=pack.manifest.name,
        version=pack.manifest.version,
        digest=pack.digest,
        package_path=str(target),
        files=[str(target / relative) for relative in relative_files],
    )


def _validate_official_closure(dependencies: list[LoadedPack], root: LoadedPack) -> None:
    """Validate the final package-shaped closure without ambient project resolution."""

    validate_selected_pack_semantics(
        [*dependencies, root],
        builtin_application_ids=packaged_builtin_application_ids(),
        builtin_dns_tags=packaged_builtin_dns_tags(),
        builtin_executable_claims=packaged_builtin_executable_claims(),
        builtin_dns_domains=packaged_builtin_dns_domains(),
        builtin_persona_ids=packaged_builtin_persona_ids(),
        builtin_storage_preset_ids=packaged_builtin_storage_preset_ids(),
    )


class PackPromoter:
    """Prepare and apply an official package promotion."""

    def __init__(
        self,
        *,
        source_project_root: Path,
        target_repo_root: Path,
        target_package_root: Path,
        target_publisher: str,
        target_publisher_display_name: str,
        promote_dependencies: bool,
    ) -> None:
        self.source_repo = PackRepository(source_project_root.resolve())
        self.target_repo_root = target_repo_root.resolve()
        self.target_package_root = target_package_root.resolve()
        self.target_publisher = target_publisher
        self.target_publisher_display_name = target_publisher_display_name
        self.promote_dependencies = promote_dependencies
        self.index_path = self.target_package_root / "index.json"

        if not (self.target_repo_root / "src/evidenceforge").is_dir():
            raise PromotionError(
                f"target repository does not look like EvidenceForge: {self.target_repo_root}"
            )
        if self.target_publisher == OFFICIAL_PUBLISHER and not self.target_publisher_display_name:
            raise PromotionError("official publisher display name must not be empty")

    def prepare(
        self, source: str, target_name: str | None, target_version: str
    ) -> PreparedPromotion:
        """Resolve, reissue, validate, and describe a promotion without writing the target."""

        source_pack = _load_source_pack(self.source_repo, source, expected_type=None)
        if source_pack.manifest.publisher == self.target_publisher:
            raise PromotionError(
                "source pack already uses the target publisher; promotion requires a new identity"
            )
        if target_name is None:
            target_name = source_pack.manifest.name

        index_document = _load_index(self.index_path)
        pack_index = index_document["packs"]

        with tempfile.TemporaryDirectory(prefix="eforge-pack-promotion-") as temporary_root:
            staging_repo = PackRepository(Path(temporary_root))
            dependency_source_packs = self.source_repo.validate_semantics(source_pack)
            dependency_namespace_rewrites: dict[str, str] = {}
            staged_dependencies: list[LoadedPack] = []
            dependency_items: list[PromotionItem] = []
            dependency_actions: list[Literal["create", "reuse"]] = []

            for dependency in dependency_source_packs:
                # ``PackRepository.copy`` validates an organization immediately after
                # publishing it.  Keep a private copy of the original dependency in
                # the disposable staging project so that validation can pass before
                # the manifest is reissued under the official namespace below.
                staging_repo.copy(
                    dependency,
                    name=dependency.manifest.name,
                    version=dependency.manifest.version,
                    publisher=dependency.manifest.publisher,
                    publisher_display_name=dependency.manifest.publisher_display_name,
                )
                old_namespace = pack_namespace(
                    dependency.manifest.publisher, dependency.manifest.name
                )
                new_namespace = pack_namespace(self.target_publisher, dependency.manifest.name)
                dependency_namespace_rewrites[old_namespace] = new_namespace
                candidate_path = staging_repo.copy(
                    dependency,
                    name=dependency.manifest.name,
                    version=dependency.manifest.version,
                    publisher=self.target_publisher,
                    publisher_display_name=self.target_publisher_display_name,
                )
                candidate = _load_pack_at_path(staging_repo, candidate_path, "industry")
                existing_path = _package_path(self.target_package_root, candidate)
                key = _index_key(candidate)
                if existing_path.exists():
                    if key not in pack_index:
                        raise PromotionError(f"official dependency payload is not indexed: {key}")
                    if not existing_path.is_dir() or existing_path.is_symlink():
                        raise PromotionError(
                            f"official dependency index/path is inconsistent for {key}: "
                            f"expected directory {existing_path}"
                        )
                    existing = _load_pack_at_path(staging_repo, existing_path, "industry")
                    if pack_index[key] != existing.digest:
                        raise PromotionError(
                            f"official dependency index digest mismatch for {key}: "
                            f"index has {pack_index[key]}, payload has {existing.digest}"
                        )
                    if existing.digest != candidate.digest:
                        raise PromotionError(
                            f"official dependency {key} already exists with a different digest; "
                            "choose a new official version or reconcile the pack first"
                        )
                    staged_dependencies.append(candidate)
                    dependency_actions.append("reuse")
                    dependency_items.append(_item("reuse", self.target_package_root, existing))
                elif key in pack_index:
                    raise PromotionError(
                        f"official dependency index/path is inconsistent for {key}: "
                        f"index entry exists but payload is missing at {existing_path}"
                    )
                else:
                    if not self.promote_dependencies:
                        raise PromotionError(
                            f"organization depends on personal industry pack "
                            f"{dependency.manifest.publisher}/{dependency.manifest.name}@"
                            f"{dependency.manifest.version}; rerun with --promote-dependencies"
                        )
                    staged_dependencies.append(candidate)
                    dependency_actions.append("create")
                    dependency_items.append(_item("create", self.target_package_root, candidate))

            copy_source_pack = source_pack
            if source_pack.manifest.type == "organization":
                # The copy helper validates immediately, so normalize dependency
                # source locations to the disposable project staging repository
                # before copying.  The final package manifest is changed to
                # source: package after the official lock is rebuilt.
                staging_dependencies = [
                    dependency.model_copy(update={"source": "project", "path": None})
                    for dependency in source_pack.manifest.industry_dependencies
                ]
                staging_manifest = source_pack.manifest.model_copy(
                    update={"industry_dependencies": staging_dependencies}
                )
                copy_source_pack = replace(source_pack, manifest=staging_manifest)
            root_path = staging_repo.copy(
                copy_source_pack,
                name=target_name,
                version=target_version,
                publisher=self.target_publisher,
                publisher_display_name=self.target_publisher_display_name,
            )
            root = _load_pack_at_path(staging_repo, root_path, source_pack.manifest.type)
            if root.manifest.type == "organization":
                _rewrite_dependency_yaml(root_path, dependency_namespace_rewrites)
                _manifest_with_dependencies(
                    root_path / PACK_MANIFEST_FILENAME,
                    source_pack,
                    publisher=self.target_publisher,
                    dependency_source="project",
                )
                _write_lock(root_path / PACK_LOCK_FILENAME, staged_dependencies)
                root = _load_pack_at_path(staging_repo, root_path, "organization")
                staging_repo.validate_semantics(root)
                _manifest_with_dependencies(
                    root_path / PACK_MANIFEST_FILENAME,
                    root,
                    publisher=self.target_publisher,
                    dependency_source="package",
                )
                root = _load_pack_at_path(staging_repo, root_path, "organization")

            _validate_official_closure(staged_dependencies, root)
            root_target = _package_path(self.target_package_root, root)
            root_key = _index_key(root)
            if root_target.exists() or root_key in pack_index:
                raise PromotionError(
                    f"refusing to overwrite existing official pack {root_key}; "
                    "choose a new target version"
                )

            index_updates: dict[str, str] = {}
            payloads: dict[tuple[PackType, str, str], LoadedPack] = {}
            for action, dependency in zip(dependency_actions, staged_dependencies, strict=True):
                if action == "create":
                    payloads[
                        (
                            dependency.manifest.type,
                            dependency.manifest.name,
                            dependency.manifest.version,
                        )
                    ] = dependency
                    index_updates[_index_key(dependency)] = dependency.digest
            payloads[(root.manifest.type, root.manifest.name, root.manifest.version)] = root
            index_updates[root_key] = root.digest
            updated_index = dict(index_document)
            updated_index["packs"] = dict(pack_index)
            updated_index["packs"].update(index_updates)

            plan = PromotionPlan(
                source=(
                    f"{source_pack.source}:{source_pack.manifest.publisher}:"
                    f"{source_pack.manifest.type}:{source_pack.manifest.name}@"
                    f"{source_pack.manifest.version}"
                ),
                target_publisher=self.target_publisher,
                target_publisher_display_name=self.target_publisher_display_name,
                target_repo_root=str(self.target_repo_root),
                target_package_root=str(self.target_package_root),
                root=_item("create", self.target_package_root, root),
                dependencies=dependency_items,
                namespace_rewrites=dependency_namespace_rewrites,
                index_updates=index_updates,
            )
            return PreparedPromotion(plan=plan, payloads=payloads, index_document=updated_index)

    def apply(self, prepared: PreparedPromotion) -> None:
        """Atomically publish the prepared pack directories and digest index."""

        targets = [Path(prepared.plan.root.package_path)] + [
            Path(item.package_path)
            for item in prepared.plan.dependencies
            if item.action == "create"
        ]
        for target in targets:
            if target.exists() or target.is_symlink():
                raise PromotionError(f"refusing to overwrite existing target {target}")

        self.target_package_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".eforge-pack-promotion-", dir=str(self.target_package_root.parent)
        ) as temporary_root:
            temporary_path = Path(temporary_root)
            staged_packs = temporary_path / "packs"
            for identity, pack in prepared.payloads.items():
                pack_type, name, version = identity
                destination = staged_packs / self.target_publisher / pack_type / name / version
                destination.mkdir(parents=True, exist_ok=True)
                for relative, content in (*pack.semantic_file_bytes, *pack.companion_file_bytes):
                    file_path = destination / relative
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    file_path.write_bytes(content)

            staged_index = temporary_path / "index.json"
            staged_index.write_text(
                json.dumps(prepared.index_document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            published: list[Path] = []
            old_index = self.index_path.read_bytes() if self.index_path.exists() else None
            try:
                for target in targets:
                    relative = target.relative_to(self.target_package_root)
                    staged = staged_packs / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(staged, target)
                    published.append(target)
                os.replace(staged_index, self.index_path)
            except OSError as exc:
                for target in reversed(published):
                    shutil.rmtree(target, ignore_errors=True)
                if old_index is not None:
                    self.index_path.write_bytes(old_index)
                else:
                    self.index_path.unlink(missing_ok=True)
                raise PromotionError(f"unable to apply pack promotion: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    """Create the developer-only command-line parser."""

    parser = argparse.ArgumentParser(
        description="Reissue a project pack under the official EvidenceForge publisher."
    )
    parser.add_argument("source", help="exact pack reference or path to pack.yaml")
    parser.add_argument("--source-project-root", type=Path, default=Path.cwd())
    parser.add_argument("--target-repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--target-package-root", type=Path)
    parser.add_argument("--target-name")
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--target-publisher", default=OFFICIAL_PUBLISHER)
    parser.add_argument("--target-publisher-display-name", default=DEFAULT_PUBLISHER_DISPLAY_NAME)
    parser.add_argument(
        "--no-promote-dependencies",
        action="store_true",
        help="fail instead of reissuing missing locked industry dependencies",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="publish the validated plan; omit to preview without changing files",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the developer-only promotion utility."""

    arguments = _parser().parse_args(argv)
    target_repo_root = arguments.target_repo_root.resolve()
    target_package_root = (
        arguments.target_package_root or target_repo_root / "src/evidenceforge/config/packs"
    ).resolve()
    try:
        promoter = PackPromoter(
            source_project_root=arguments.source_project_root,
            target_repo_root=target_repo_root,
            target_package_root=target_package_root,
            target_publisher=arguments.target_publisher,
            target_publisher_display_name=arguments.target_publisher_display_name,
            promote_dependencies=not arguments.no_promote_dependencies,
        )
        prepared = promoter.prepare(
            arguments.source,
            arguments.target_name,
            arguments.target_version,
        )
        if arguments.apply:
            promoter.apply(prepared)
            prepared.plan = prepared.plan.model_copy(update={"applied": True})
        print(prepared.plan.model_dump_json(indent=2))
        return 0
    except (PackError, OSError, ValueError, yaml.YAMLError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
