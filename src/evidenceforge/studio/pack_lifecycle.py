"""Read-only pack reviews and dependency-aware removal of workspace versions."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import (
    PackRepository,
    _bounded_pack_tree,
    _read_regular_file_no_follow,
    _write_new_file_no_follow,
    parse_pack_cli_reference,
)
from evidenceforge.config.context import select_context
from evidenceforge.desktop.library import discover_packs, discover_scenarios
from evidenceforge.models.exceptions import ConfigurationError, PackError
from evidenceforge.studio.contexts import context_path
from evidenceforge.studio.imports import _scenario_references
from evidenceforge.utils import load_scenario_source_graph

logger = logging.getLogger(__name__)


class PackReview(BaseModel):
    """Current canonical validation, identity, exports and locked dependencies."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    reference: str = ""
    digest: str = ""
    exports: dict[str, list[str]] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    model_contributions: dict[str, list[str]] = Field(default_factory=dict)
    error: str = ""


class PackDeleteReview(BaseModel):
    """Exact version and live consumers reviewed before a removal."""

    model_config = ConfigDict(extra="forbid")

    reference: str
    revision: str
    files: int
    bytes: int
    consumers: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    removable: bool


class PackDeleteRequest(BaseModel):
    """A confirmation tied to all reviewed files and consumers."""

    model_config = ConfigDict(extra="forbid")

    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class PackDeleted(BaseModel):
    """Recovery location outside the active pack repository."""

    model_config = ConfigDict(extra="forbid")

    recovery_path: Path


def review_pack(source: Path, workspace: Path) -> PackReview:
    """Validate a pack's complete locked closure through the canonical repository."""
    try:
        reference, kind = parse_pack_cli_reference(str(source))
        if kind is None:
            raise PackError("Choose an industry or organization pack")
        repository = PackRepository(workspace)
        pack = repository.resolve(reference, expected_type=kind)
        dependencies = repository.validate_semantics(pack)
        identity = pack.manifest
        return PackReview(
            valid=True,
            reference=f"{identity.publisher}:{kind}:{identity.name}@{identity.version}",
            digest=pack.digest,
            exports={category: sorted(entries) for category, entries in pack.catalogs.items()},
            dependencies=[
                f"{member.manifest.publisher}:industry:{member.manifest.name}@"
                f"{member.manifest.version}"
                for member in dependencies
            ],
            model_contributions={
                "environment": sorted(pack.environment),
                "baseline_activity": sorted(pack.baseline_activity),
            },
        )
    except (OSError, ValueError, ConfigurationError, PackError) as exc:
        return PackReview(valid=False, error=str(exc))


def _snapshot(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    metadata = root.stat()
    digest.update(f"{metadata.st_dev}:{metadata.st_ino}".encode())
    files = 0
    size = 0
    for entry in _bounded_pack_tree(root):
        digest.update(entry.relative_path.as_posix().encode())
        digest.update(b"/" if entry.is_directory else b"\0")
        if not entry.is_directory:
            content = _read_regular_file_no_follow(entry.path, max_bytes=entry.size)
            digest.update(hashlib.sha256(content).digest())
            files += 1
            size += len(content)
    return digest.hexdigest(), files, size


def _workspace_version(source: Path, workspace: Path) -> tuple[Path, str]:
    reference, kind = parse_pack_cli_reference(str(source))
    root = workspace.resolve() / ".eforge" / "packs"
    expected = root / reference.publisher / str(kind) / reference.name / reference.version
    if source.absolute() != expected / "pack.yaml":
        raise PackError(
            "Only exact workspace pack versions can be deleted; bundled packs are protected"
        )
    PackRepository(workspace)._assert_project_path_safe(expected)
    return expected, f"{reference.publisher}:{kind}:{reference.name}@{reference.version}"


def review_pack_deletion(
    source: Path,
    workspace: Path,
    scenario_paths: list[Path] | None = None,
    organization_paths: list[Path] | None = None,
) -> PackDeleteReview:
    """Inspect actual authored references, including includes and selected contexts."""
    target, identity = _workspace_version(source, workspace)
    revision, files, size = _snapshot(target)
    fingerprints: list[str] = [revision]
    consumers: list[str] = []
    problems: list[str] = []

    def check(reference: PackReference, kind: str, origin: Path, project: Path) -> bool:
        # Resolve locations independently of semantic validity: a broken catalog still owns
        # its consumers and must not make a referenced pack appear safe to remove.
        repository = PackRepository(project)
        if reference.source == "path":
            raw = Path(reference.path or "")
            location = raw if raw.is_absolute() else origin.parent / raw
        else:
            location = (
                repository.root_for(reference.source)
                / reference.publisher
                / kind
                / reference.name
                / reference.version
            )
        return location.resolve() == target

    discovered = {item.path: item.name for item in discover_scenarios(workspace, [])}
    for path in scenario_paths or []:
        discovered.setdefault(path, path.parent.name)
    for scenario_path, scenario_name in sorted(discovered.items()):
        try:
            graph = load_scenario_source_graph(scenario_path)
            fingerprints.extend(f"{member.path}:{member.sha256}" for member in graph.sources)
            selected_context = context_path(scenario_path, workspace)
            selection = select_context(None if selected_context else workspace, selected_context)
            fingerprints.append(str(selection.project_root))
            for reference, kind, origin in _scenario_references(graph):
                if check(reference, kind, origin, selection.project_root):
                    consumers.append(f"Scenario: {scenario_name} ({scenario_path})")
        except (OSError, ValueError, ConfigurationError, PackError) as exc:
            problems.append(f"Cannot check scenario {scenario_name}: {exc}")

    # Organizations are the only pack type allowed to depend on another pack. Inspect
    # declarations and lock independently; do not need a valid organization environment.
    organizations = {item.path for item in discover_packs(workspace, "organization")}
    repository = PackRepository(workspace)
    for root in (repository.root_for("package"), repository.root_for("project")):
        # Invalid manifests disappear from library discovery. Their standard repository
        # locations still need inspection so damaged consumers cannot authorize deletion.
        organizations.update(root.glob("*/organization/*/*/pack.yaml"))
    organizations.update(organization_paths or [])
    for path in sorted(organizations):
        if path.parent == target:
            continue
        try:
            reference, kind = parse_pack_cli_reference(str(path))
            if kind != "organization":
                raise PackError("Expected an organization pack manifest")
            pack = PackRepository(workspace).resolve(reference, expected_type=kind)
            fingerprints.append(f"{pack.root}:{_snapshot(pack.root)[0]}")
            for index, dependency in enumerate(pack.manifest.industry_dependencies):
                locked = next(
                    (
                        entry
                        for entry in pack.lock.dependencies
                        if (entry.publisher, entry.name) == (dependency.publisher, dependency.name)
                    ),
                    None,
                )
                if locked is None:
                    raise PackError("An industry dependency has no exact lock")
                selected = PackReference(
                    source=dependency.source,
                    publisher=dependency.publisher,
                    name=dependency.name,
                    version=locked.version,
                    path=dependency.path,
                )
                if check(
                    selected, "industry", pack.industry_dependency_declaring_files[index], workspace
                ):
                    consumers.append(
                        f"Organization pack: {pack.manifest.publisher}/{pack.manifest.name}"
                        f"@{pack.manifest.version}"
                    )
        except (OSError, ValueError, ConfigurationError, PackError) as exc:
            problems.append(f"Cannot check organization {path}: {exc}")
    fingerprints.extend(sorted(consumers))
    fingerprints.extend(sorted(problems))
    return PackDeleteReview(
        reference=identity,
        revision=hashlib.sha256(json.dumps(sorted(fingerprints)).encode()).hexdigest(),
        files=files,
        bytes=size,
        consumers=sorted(set(consumers)),
        problems=sorted(set(problems)),
        removable=not consumers and not problems,
    )


def remove_workspace_pack(
    source: Path,
    workspace: Path,
    revision: str,
    scenario_paths: list[Path] | None = None,
    organization_paths: list[Path] | None = None,
) -> PackDeleted:
    """Recheck reviewed input and atomically retire a version, retaining its files."""
    target, _identity = _workspace_version(source, workspace)
    original = target.stat()
    review = review_pack_deletion(source, workspace, scenario_paths, organization_paths)
    if review.revision != revision:
        raise FileExistsError("Pack files or consumers changed. Review deletion again")
    if not review.removable:
        raise PackError(
            "Update dependent scenarios/packs and resolve inspection errors before deletion"
        )
    _workspace_version(source, workspace)
    recovery = workspace.resolve() / ".eforge" / "deleted-packs"
    operation = uuid4().hex
    operation_root = recovery / operation
    destination = operation_root / "pack"
    receipt = json.dumps(
        {"recovery_version": 1, "source": str(source.relative_to(workspace.resolve()))}
    ).encode()
    if os.name == "nt":
        # Native Windows GUI acceptance is deferred. Keep the portable path guarded.
        if recovery.is_symlink():
            raise PackError("Pack recovery directory cannot be a symlink")
        recovery.mkdir(mode=0o700, exist_ok=True)
        operation_root.mkdir(mode=0o700)
        _write_new_file_no_follow(operation_root / "deletion.json", receipt)
        target.rename(destination)
    else:
        with _directory_beneath(workspace.resolve(), target.parent) as parent:
            with _directory_beneath(workspace.resolve(), recovery.parent) as eforge:
                try:
                    os.mkdir(recovery.name, mode=0o700, dir_fd=eforge)
                except FileExistsError:
                    pass
                descriptor = os.open(
                    recovery.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=eforge
                )
                try:
                    os.mkdir(operation, mode=0o700, dir_fd=descriptor)
                    operation_fd = os.open(
                        operation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                    )
                    try:
                        receipt_fd = os.open(
                            "deletion.json",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            mode=0o600,
                            dir_fd=operation_fd,
                        )
                        with os.fdopen(receipt_fd, "wb") as stream:
                            stream.write(receipt)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.fsync(operation_fd)
                        os.fsync(descriptor)
                        os.fsync(eforge)
                        current = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                            raise FileExistsError("Pack directory changed. Review deletion again")
                        os.rename(target.name, "pack", src_dir_fd=parent, dst_dir_fd=operation_fd)
                        try:
                            os.fsync(parent)
                            os.fsync(operation_fd)
                        except OSError:
                            os.rename(
                                "pack", target.name, src_dir_fd=operation_fd, dst_dir_fd=parent
                            )
                            raise
                    finally:
                        os.close(operation_fd)
                finally:
                    os.close(descriptor)
    logger.info("Removed workspace pack %s; recovery copy at %s", review.reference, destination)
    return PackDeleted(recovery_path=destination)


def retired_pack_sources(workspace: Path) -> set[Path]:
    """Recover completed retirements whose SQLite cleanup was interrupted."""
    recovery = workspace.resolve() / ".eforge" / "deleted-packs"
    if not recovery.is_dir() or any(path.is_symlink() for path in (recovery, *recovery.parents)):
        return set()
    sources: set[Path] = set()
    for operation in recovery.iterdir():
        if not re.fullmatch(r"[a-f0-9]{32}", operation.name) or operation.is_symlink():
            continue
        try:
            receipt = json.loads(
                _read_regular_file_no_follow(operation / "deletion.json", max_bytes=4096)
            )
            if receipt.get("recovery_version") != 1 or not isinstance(receipt.get("source"), str):
                continue
            reference, kind = parse_pack_cli_reference(str(operation / "pack" / "pack.yaml"))
            source = (
                workspace.resolve()
                / ".eforge"
                / "packs"
                / reference.publisher
                / str(kind)
                / reference.name
                / reference.version
                / "pack.yaml"
            )
            if (
                str(source.relative_to(workspace.resolve())) == receipt["source"]
                and not source.exists()
            ):
                sources.add(source)
        except (OSError, ValueError, PackError, AttributeError):
            continue
    return sources


@contextmanager
def _directory_beneath(workspace: Path, path: Path) -> Iterator[int]:
    """Open each workspace-relative directory without following substituted links."""
    descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.relative_to(workspace).parts:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)
