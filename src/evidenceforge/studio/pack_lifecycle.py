"""Read-only pack reviews and dependency-aware removal of workspace versions."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import (
    _publication_lock,
    _safe_path,
    artifact_root,
    safe_relative,
    storage_name,
)
from evidenceforge.artifacts.removal import (
    AffectedItem,
    delete_artifact_files,
    retired_artifact_sources,
)
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import (
    PackRepository,
    _bounded_pack_tree,
    _read_regular_file_no_follow,
    parse_pack_cli_reference,
)
from evidenceforge.config.context import select_context
from evidenceforge.desktop.library import discover_packs, discover_scenarios
from evidenceforge.models.exceptions import EvidenceForgeError, PackError
from evidenceforge.studio.contexts import context_path
from evidenceforge.studio.imports import _scenario_references
from evidenceforge.utils import load_scenario_source_graph
from evidenceforge.utils.files import LoadedSourceGraph

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
    affected: list[AffectedItem] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    removable: bool


class PackDeleteRequest(BaseModel):
    """A confirmation tied to all reviewed files and consumers."""

    model_config = ConfigDict(extra="forbid")

    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    accept_dependents: bool = False


class PackDeleted(BaseModel):
    """Confirmation of permanent exact-version deletion."""

    model_config = ConfigDict(extra="forbid")

    deleted_path: Path


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
            reference=f"draft:{kind}:{identity.name}@{identity.draft_id}"
            if identity.status == "draft"
            else f"{identity.publisher}:{kind}:{identity.name}@{identity.version}",
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
    except (OSError, ValueError, EvidenceForgeError) as exc:
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
    source = _safe_path(source)
    reference, kind = parse_pack_cli_reference(str(source))
    root = workspace.resolve() / ".eforge" / "packs"
    expected = root / str(reference.publisher) / str(kind) / reference.name / str(reference.version)
    if source == expected / "pack.yaml":
        PackRepository(workspace)._assert_project_path_safe(expected)
        return expected, f"{reference.publisher}:{kind}:{reference.name}@{reference.version}"
    artifacts = artifact_root(workspace)
    for parent in source.parents:
        if not parent.is_relative_to(artifacts):
            continue
        relative = parent.relative_to(artifacts).parts
        marker = None
        if len(relative) == 4 and relative[:2] == ("drafts", kind):
            marker = parent / "draft.json"
        elif len(relative) == 5 and relative[0] == "releases" and relative[2] == kind:
            marker = parent / "release.json"
        if marker and marker.is_file():
            data = json.loads(_read_regular_file_no_follow(marker, max_bytes=8 * 1024 * 1024))
            if not isinstance(data, dict) or parent / safe_relative(data["entrypoint"]) != source:
                raise PackError("Choose the pack entrypoint recorded in its receipt")
            label = (
                f"Draft {reference.name}"
                if reference.source == "draft"
                else (f"{reference.publisher}:{kind}:{reference.name}@{reference.version}")
            )
            return parent, label
    raise PackError("Only exact workspace packs can be deleted; bundled packs are protected")


def review_pack_deletion(
    source: Path,
    workspace: Path,
    scenario_paths: list[Path] | None = None,
    organization_paths: list[Path] | None = None,
) -> PackDeleteReview:
    """Inspect actual authored references, including includes and selected contexts."""
    target, identity = _workspace_version(source, workspace)
    return _review_pack_consumers(
        source, workspace, target, identity, scenario_paths, organization_paths
    )


def review_pack_identity(
    source: Path,
    workspace: Path,
    scenario_paths: list[Path] | None = None,
    organization_paths: list[Path] | None = None,
) -> PackDeleteReview:
    """Inspect consumers for a name edit, including protected bundled originals."""
    from evidenceforge.artifacts.lifecycle import inspect_artifact

    current = inspect_artifact(source)
    return _review_pack_consumers(
        source,
        workspace,
        source.parent.resolve(),
        current["name"],
        scenario_paths,
        organization_paths,
    )


def _review_pack_consumers(
    source: Path,
    workspace: Path,
    target: Path,
    identity: str,
    scenario_paths: list[Path] | None,
    organization_paths: list[Path] | None,
) -> PackDeleteReview:
    """Collect exact and indirect consumers without changing any source or reference."""
    revision, files, size = _snapshot(target)
    fingerprints: list[str] = [revision]
    consumers: list[str] = []
    affected: dict[Path, AffectedItem] = {}
    organization_roots: set[Path] = set()
    scenario_graphs: list[tuple[Path, LoadedSourceGraph, Path]] = []
    problems: list[str] = []

    def check(
        reference: PackReference, kind: str, origin: Path, project: Path, selected: Path = target
    ) -> bool:
        # Resolve locations independently of semantic validity: a broken catalog still owns
        # its consumers and must not make a referenced pack appear safe to remove.
        repository = PackRepository(project)
        if reference.source in {"path", "draft"}:
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
            if reference.source == "project" and not location.is_dir():
                location = (
                    artifact_root(project)
                    / "releases"
                    / str(reference.publisher)
                    / kind
                    / storage_name(reference.name)
                    / str(reference.version)
                    / "source"
                )
        resolved = location.resolve()
        return resolved == selected or resolved.is_relative_to(selected)

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
            scenario_graphs.append((scenario_path, graph, selection.project_root))
            for reference, kind, origin in _scenario_references(graph):
                if check(reference, kind, origin, selection.project_root):
                    consumers.append(f"Scenario: {scenario_name} ({scenario_path})")
                    from evidenceforge.schema import identify_document

                    contract = identify_document(graph.data)
                    lifecycle = contract.lifecycle
                    affected[scenario_path] = AffectedItem(
                        kind="scenario",
                        name=scenario_name,
                        version=lifecycle.version or "" if lifecycle else "",
                        publisher=lifecycle.publisher or "" if lifecycle else "",
                        path=scenario_path,
                        frozen=bool(lifecycle and lifecycle.status == "published"),
                    )
        except (OSError, ValueError, EvidenceForgeError) as exc:
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
        if path.is_relative_to(target):
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
                    publisher=dependency.publisher if dependency.source != "draft" else None,
                    name=dependency.name,
                    version=locked.version if dependency.source != "draft" else None,
                    path=dependency.path,
                    draft_id=dependency.draft_id,
                )
                if check(
                    selected, "industry", pack.industry_dependency_declaring_files[index], workspace
                ):
                    organization_roots.add(pack.root)
                    affected[path] = AffectedItem(
                        kind="organization_pack",
                        name=pack.manifest.name,
                        version=pack.manifest.version if pack.manifest.status != "draft" else "",
                        publisher=pack.manifest.publisher
                        if pack.manifest.status != "draft"
                        else "",
                        path=path,
                        frozen=pack.manifest.status == "published",
                    )
                    consumers.append(
                        f"Organization pack: {pack.manifest.publisher}/{pack.manifest.name}"
                        f"@{pack.manifest.version}"
                    )
        except (OSError, ValueError, EvidenceForgeError) as exc:
            problems.append(f"Cannot check organization {path}: {exc}")
    # Scenarios that select a dependent organization are affected indirectly as well.
    for path, graph, project in scenario_graphs:
        for reference, kind, origin in _scenario_references(graph):
            if kind == "organization" and any(
                check(reference, kind, origin, project, selected=root)
                for root in organization_roots
            ):
                from evidenceforge.schema import identify_document

                contract = identify_document(graph.data)
                lifecycle = contract.lifecycle
                affected[path] = AffectedItem(
                    kind="scenario",
                    name=str(graph.data["name"]),
                    version=lifecycle.version or "" if lifecycle else "",
                    publisher=lifecycle.publisher or "" if lifecycle else "",
                    path=path,
                    frozen=bool(lifecycle and lifecycle.status == "published"),
                )
                consumers.append(f"Scenario: {graph.data['name']} ({path})")
    fingerprints.extend(sorted(consumers))
    fingerprints.extend(sorted(problems))
    return PackDeleteReview(
        reference=identity,
        revision=hashlib.sha256(json.dumps(sorted(fingerprints)).encode()).hexdigest(),
        files=files,
        bytes=size,
        consumers=sorted(set(consumers)),
        affected=sorted(
            affected.values(),
            key=lambda entry: (
                {"industry_pack": 0, "organization_pack": 1, "scenario": 2}[entry.kind],
                entry.name.casefold(),
                tuple(-int(part) for part in entry.version.split(".")) if entry.version else (),
                entry.publisher,
                str(entry.path),
            ),
        ),
        problems=sorted(set(problems)),
        removable=not problems,
    )


def remove_workspace_pack(
    source: Path,
    workspace: Path,
    revision: str,
    scenario_paths: list[Path] | None = None,
    organization_paths: list[Path] | None = None,
    *,
    accept_dependents: bool = False,
) -> PackDeleted:
    """Permanently delete a reviewed version after explicit dependency warning acceptance."""
    with _publication_lock(workspace):
        target, _identity = _workspace_version(source, workspace)
        review = review_pack_deletion(source, workspace, scenario_paths, organization_paths)
        if review.revision != revision:
            raise FileExistsError("Pack files or consumers changed. Review deletion again")
        if not review.removable:
            raise PackError("Resolve inspection errors before deletion")
        if review.consumers and not accept_dependents:
            raise PackError("Confirm the dependent scenario/pack warning before permanent deletion")
        _, kind = parse_pack_cli_reference(str(source))
        return PackDeleted(deleted_path=delete_artifact_files(source, target, workspace, str(kind)))


def retired_pack_sources(workspace: Path) -> set[Path]:
    """Reconcile completed permanent pack deletions after interrupted index cleanup."""
    return retired_artifact_sources(workspace, "industry") | retired_artifact_sources(
        workspace, "organization"
    )
