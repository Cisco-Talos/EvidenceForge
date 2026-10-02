"""Reviewed, bounded imports of authored scenarios and portable pack closures."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Literal
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.composition.models import CompositionSpec, PackReference, PackType
from evidenceforge.composition.packs import LoadedPack, PackRepository, version_satisfies_constraint
from evidenceforge.composition.releases import (
    EFPACK_FORMAT_VERSION,
    EFPACK_MANIFEST,
    validate_efpack,
)
from evidenceforge.config.context import (
    ConfigurationContext,
    OverlayReference,
    SelectedContext,
    context_fingerprint,
    select_context,
)
from evidenceforge.models.exceptions import ConfigurationError, PackError, PathSafetyError
from evidenceforge.studio.contexts import capture_overlays, context_path, scenario_context_path
from evidenceforge.studio.environment import overlay_fingerprint
from evidenceforge.studio.lifecycle import rename_scenario
from evidenceforge.utils import LoadedSourceGraph, load_scenario_source_graph
from evidenceforge.utils.assets import EMAIL_CORPUS_MAX_SOURCE_BYTES
from evidenceforge.utils.paths import read_text_file_beneath
from evidenceforge.utils.yaml_loader import load_yaml_text

logger = logging.getLogger(__name__)
MAX_IMPORT_BYTES = 64 * 1024**2


class ScenarioImportRequest(BaseModel):
    """Explicit source locations and destination choices for one scenario."""

    model_config = ConfigDict(extra="forbid")
    path: Path
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    project_id: str | None = None
    source_workspaces: list[Path] = Field(default_factory=list, max_length=16)
    pack_locations: dict[str, Path] = Field(default_factory=dict, max_length=64)
    documents: list[str] | None = None
    configuration_context: Path | None = None


class PackImportRequest(BaseModel):
    """One received release archive; destination is the active workspace."""

    model_config = ConfigDict(extra="forbid")
    path: Path
    project_id: str | None = None
    source_workspaces: list[Path] = Field(default_factory=list, max_length=16)


class DependencyRow(BaseModel):
    """A dependency's identity, availability, and proposed action."""

    model_config = ConfigDict(extra="forbid")
    key: str
    kind: Literal["include", "asset", "pack", "document", "overlay"]
    label: str
    status: Literal["available", "copy", "missing", "conflict", "warning"]
    detail: str
    source: str | None = None
    destination: str | None = None
    source_digest: str | None = None
    digest: str | None = None
    dependencies: list[str] = Field(default_factory=list)


class DependencyHealth(BaseModel):
    """Live dependency readiness independent of optional scenario validation."""

    model_config = ConfigDict(extra="forbid")
    ready: bool
    fingerprint: str
    rows: list[DependencyRow]
    changed_at: float = 0


class ImportReview(BaseModel):
    """A prepared snapshot that can be inspected and optionally validated."""

    model_config = ConfigDict(extra="forbid")
    id: str
    kind: Literal["scenario", "pack"]
    name: str
    destination: Path
    rows: list[DependencyRow] = Field(default_factory=list)
    documents: list[str] = Field(default_factory=list)
    publishers: list[str] = Field(default_factory=list)
    can_import: bool = True


class ImportCommitRequest(BaseModel):
    """Publisher namespaces acknowledged by confirming the displayed review."""

    model_config = ConfigDict(extra="forbid")
    accepted_publishers: list[str] = Field(default_factory=list)
    selected_packs: list[str] | None = Field(default=None, max_length=256)


def pack_key(reference: PackReference, kind: PackType) -> str:
    """Return the exact identity used by review location overrides."""
    return f"{reference.publisher}:{kind}:{reference.name}@{reference.version}"


def _reference(pack: LoadedPack, source: Literal["project", "path"] = "project") -> PackReference:
    return PackReference(
        source=source,
        publisher=pack.manifest.publisher,
        name=pack.manifest.name,
        version=pack.manifest.version,
        path=str(pack.root) if source == "path" else None,
    )


def _digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(files.items()):
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def portable_pack_files(pack: LoadedPack) -> tuple[dict[str, bytes], str]:
    """Rebind external industry locations to project packs, retaining exact locks.

    Industry packs have no pack dependencies. Their bytes and locked digests are
    unchanged. Organization manifest fragments are rewritten only where a path
    dependency is declared; the review exposes the resulting organization digest.
    """
    semantic = dict(pack.semantic_file_bytes)
    by_file: dict[Path, list[int]] = {}
    for index, dependency in enumerate(pack.manifest.industry_dependencies):
        if dependency.source == "path":
            by_file.setdefault(pack.industry_dependency_declaring_files[index], []).append(index)
    for path in by_file:
        relative = path.relative_to(pack.root).as_posix()
        data = load_yaml_text(semantic[relative].decode("utf-8"))
        # A manifest fragment can own the entire list, never individual entries.
        for dependency in data.get("industry_dependencies", []):
            if dependency.get("source") == "path":
                dependency["source"] = "project"
                dependency.pop("path", None)
        semantic[relative] = yaml.safe_dump(data, sort_keys=False).encode()
    files = {**semantic, **dict(pack.companion_file_bytes)}
    digest = _digest(semantic)
    if digest != pack.digest:
        previous = files.get("COPY_PROVENANCE.md", b"")
        files["COPY_PROVENANCE.md"] = (
            previous
            + (
                f"\n# Studio import relocation\n\nOriginal digest: `{pack.digest}`.\n"
                f"Prepared digest: `{digest}`.\nExternal industry paths were rebound to "
                "workspace packs; catalogs, identities, versions, and locks were preserved.\n"
            ).encode()
        )
    return files, digest


def build_portable_archive(repository: PackRepository, pack: LoadedPack, target: Path) -> None:
    """Export one pack and its validated locked closure without external paths."""
    closure = [*repository.validate_semantics(pack), pack]
    payloads: dict[str, bytes] = {}
    members: list[dict[str, str]] = []
    root: dict[str, str] | None = None
    for member in closure:
        files, digest = portable_pack_files(member)
        identity = {
            "publisher": member.manifest.publisher,
            "type": member.manifest.type,
            "name": member.manifest.name,
            "version": member.manifest.version,
            "digest": digest,
        }
        members.append(identity)
        if member is pack:
            root = identity
        prefix = "packs/{publisher}/{type}/{name}/{version}".format(**identity)
        payloads.update({f"{prefix}/{path}": content for path, content in files.items()})
    document = {
        "efpack_format_version": EFPACK_FORMAT_VERSION,
        "root": root,
        "members": members,
        "files": {path: hashlib.sha256(content).hexdigest() for path, content in payloads.items()},
    }
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(
            {EFPACK_MANIFEST: yaml.safe_dump(document, sort_keys=True).encode(), **payloads}.items()
        ):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    validate_efpack(target)


def _scenario_references(graph: LoadedSourceGraph) -> list[tuple[PackReference, PackType, Path]]:
    spec = CompositionSpec.model_validate(graph.data.get("composition") or {})
    references: list[tuple[PackReference, PackType, Path]] = []
    for index, reference in enumerate(spec.industries):
        origin = graph.origins.get(("composition", "industries", str(index), "path"), graph.root)
        references.append((reference, "industry", origin))
    if spec.organization:
        origin = graph.origins.get(("composition", "organization", "path"), graph.root)
        references.append((spec.organization, "organization", origin))
    return references


def dependency_health(path: Path, workspace: Path) -> DependencyHealth:
    """Read actual scenario and pack files, including locked digest checks."""
    rows: list[DependencyRow] = []
    fingerprints: list[str] = []
    try:
        fingerprints.append(overlay_fingerprint(workspace))
        fingerprints.append(
            context_fingerprint(select_context(workspace, context_path(path, workspace)))
        )
    except (OSError, ValueError, ConfigurationError) as exc:
        fingerprints.append(f"overlay: {exc}")
        rows.append(
            DependencyRow(
                key="configuration",
                kind="overlay",
                label="Configuration context",
                status="missing",
                detail=str(exc),
            )
        )
    repository = PackRepository(workspace)
    try:
        graph = load_scenario_source_graph(path)
        fingerprints.extend(source.sha256 for source in graph.sources)
        for reference, kind, origin in _scenario_references(graph):
            key = pack_key(reference, kind)
            try:
                pack = repository.resolve(reference, expected_type=kind, declaring_file=origin)
                broken_dependency = False
                for index, dependency in enumerate(pack.manifest.industry_dependencies):
                    locked = next(
                        (
                            entry
                            for entry in pack.lock.dependencies
                            if (entry.publisher, entry.name)
                            == (dependency.publisher, dependency.name)
                        ),
                        None,
                    )
                    if locked is None:
                        raise PackError("Organization is missing an exact dependency lock")
                    dependency_ref = PackReference(
                        source=dependency.source,
                        publisher=dependency.publisher,
                        name=dependency.name,
                        version=locked.version,
                        path=dependency.path,
                    )
                    dependency_key = pack_key(dependency_ref, "industry")
                    try:
                        member = repository.resolve(
                            dependency_ref,
                            expected_type="industry",
                            declaring_file=pack.industry_dependency_declaring_files[index],
                        )
                        fingerprints.append(member.digest)
                        if member.digest != locked.digest:
                            rows.append(
                                DependencyRow(
                                    key=dependency_key,
                                    kind="pack",
                                    label=dependency_key,
                                    status="conflict",
                                    detail="Digest does not match the organization's locked dependency",
                                    digest=locked.digest,
                                    source_digest=member.digest,
                                )
                            )
                            broken_dependency = True
                    except PackError as exc:
                        rows.append(
                            DependencyRow(
                                key=dependency_key,
                                kind="pack",
                                label=dependency_key,
                                status="missing",
                                detail=str(exc),
                                digest=locked.digest,
                            )
                        )
                        broken_dependency = True
                if broken_dependency:
                    fingerprints.append(pack.digest)
                    fingerprints.extend(
                        row.model_dump_json()
                        for row in rows
                        if row.status in {"missing", "conflict"}
                    )
                    continue
                closure = [*repository.validate_semantics(pack), pack]
                for member in closure:
                    fingerprints.append(member.digest)
                    member_key = pack_key(_reference(member), member.manifest.type)
                    if not any(row.key == member_key for row in rows):
                        rows.append(
                            DependencyRow(
                                key=member_key,
                                kind="pack",
                                label=member_key,
                                status="available",
                                detail="Exact pack is available",
                                digest=member.digest,
                            )
                        )
            except (PackError, OSError) as exc:
                rows.append(
                    DependencyRow(
                        key=key, kind="pack", label=key, status="missing", detail=str(exc)
                    )
                )
                fingerprints.append(str(exc))
        environment = graph.data.get("environment")
        email = environment.get("email") if isinstance(environment, dict) else None
        if isinstance(email, dict) and email.get("corpus"):
            origin = graph.origins.get(("environment", "email", "corpus"), graph.root)
            content = read_text_file_beneath(
                origin.parent,
                str(email["corpus"]),
                max_bytes=EMAIL_CORPUS_MAX_SOURCE_BYTES,
                label="email corpus",
            )
            fingerprints.append(hashlib.sha256(content.encode()).hexdigest())
    except (
        ConfigurationError,
        PathSafetyError,
        OSError,
        ValueError,
        ValidationError,
        yaml.YAMLError,
    ) as exc:
        rows.append(
            DependencyRow(
                key="source",
                kind="include",
                label="Scenario inputs",
                status="missing",
                detail=str(exc),
            )
        )
        fingerprints.append(str(exc))
    return DependencyHealth(
        ready=not any(row.status in {"missing", "conflict"} for row in rows),
        fingerprint=hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest(),
        rows=rows,
    )


def _local_file(path: Path) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"Select a regular local file, not a link: {path}")
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("This file exceeds the 64 MiB import limit")
    return path


class PreparedImport:
    """A disposable snapshot, reserved for one workspace and one review."""

    def __init__(
        self, workspace: Path, cache: Path, kind: Literal["scenario", "pack"], name: str
    ) -> None:
        self.workspace = workspace.resolve()
        cache.mkdir(parents=True, exist_ok=True)
        self.stage = Path(tempfile.mkdtemp(prefix="studio-import-", dir=cache)).resolve()
        self.created_at = time.monotonic()
        self.review = ImportReview(id=uuid4().hex, kind=kind, name=name, destination=workspace)
        self.project_id: str | None = None
        self.target: Path | None = None
        self.sources: dict[Path, str] = {}
        self.reservations: dict[Path, str | None] = {}
        self.publish_roots: list[Path] = []
        self.pack_sources: dict[str, set[Path]] = {}
        self.configuration_source: SelectedContext | None = None
        self.configuration_fingerprint: str | None = None

    def close(self) -> None:
        """Remove only this generated temporary snapshot."""
        shutil.rmtree(self.stage, ignore_errors=True)

    def add_files(self, root: Path, files: dict[str, bytes]) -> None:
        """Capture bounded, relative files without replacing conflicting snapshots."""
        if (
            sum(path.stat().st_size for path in self.stage.rglob("*") if path.is_file())
            + sum(len(content) for content in files.values())
            > MAX_IMPORT_BYTES
        ):
            raise ValueError("Import exceeds the 64 MiB total limit")
        for relative, content in files.items():
            target = self.stage / root / relative
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("Import snapshot contains an unsafe file path")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != content:
                raise ValueError(f"Conflicting prepared inputs: {target.name}")
            target.write_bytes(content)

    def add_pack(self, pack: LoadedPack) -> None:
        """Reuse or prepare one exact pack without overwriting an existing version."""
        key = pack_key(_reference(pack), pack.manifest.type)
        dependencies = [
            f"{entry.publisher}:industry:{entry.name}@{entry.version}"
            for entry in pack.lock.dependencies
        ]
        if any(row.key == key for row in self.review.rows):
            existing = next(row for row in self.review.rows if row.key == key)
            if existing.source_digest and existing.source_digest != pack.digest:
                existing.status = "conflict"
                existing.detail = "Sources contain different contents for the same pack identity"
            return
        if pack.source == "package":
            self.review.rows.append(
                DependencyRow(
                    key=key,
                    kind="pack",
                    label=key,
                    status="available",
                    detail="Bundled exact version; reused",
                    digest=pack.digest,
                    dependencies=dependencies,
                )
            )
            return
        # Reuse packs owned by this workspace as authored. Only new copies need
        # relocation; exporting creates its own portable snapshot.
        if pack.source == "project" and pack.root.is_relative_to(self.workspace):
            files = {**dict(pack.semantic_file_bytes), **dict(pack.companion_file_bytes)}
            digest = pack.digest
        else:
            files, digest = portable_pack_files(pack)
        relative = (
            Path(".eforge/packs")
            / pack.manifest.publisher
            / pack.manifest.type
            / pack.manifest.name
            / pack.manifest.version
        )
        destination = self.workspace / relative
        status: Literal["copy", "available", "conflict"] = "copy"
        detail = "Copy into the workspace pack library"
        if digest != pack.digest:
            detail += "; external paths rebound and prepared digest updated (catalogs unchanged)"
        if destination.exists() or destination.is_symlink():
            try:
                existing = PackRepository(self.workspace).resolve(
                    _reference(pack), expected_type=pack.manifest.type
                )
                self.reservations[relative] = existing.digest
                if existing.digest != digest:
                    status, detail = (
                        "conflict",
                        "Same identity/version has different contents; existing pack will be preserved",
                    )
                else:
                    status, detail = "available", "Matching workspace pack; reused"
            except (PackError, OSError) as exc:
                status, detail = "conflict", str(exc)
        else:
            self.reservations[relative] = None
            self.publish_roots.append(relative)
        self.review.rows.append(
            DependencyRow(
                key=key,
                kind="pack",
                label=key,
                status=status,
                detail=detail,
                source=str(pack.root),
                destination=str(destination),
                source_digest=pack.digest,
                digest=digest,
                dependencies=dependencies,
            )
        )
        if status != "conflict":
            self.add_files(relative, files)
        self.review.publishers = sorted(set(self.review.publishers) | {pack.manifest.publisher})
        for filename, content in (*pack.semantic_file_bytes, *pack.companion_file_bytes):
            self.sources[pack.root / filename] = hashlib.sha256(content).hexdigest()
        self.pack_sources[key] = {
            pack.root / filename
            for filename, _content in (*pack.semantic_file_bytes, *pack.companion_file_bytes)
        }

    def selected_pack_keys(self, selection: list[str] | None = None) -> set[str]:
        """Expand explicitly selected packs to their reviewed, exact locked closure."""
        rows = {row.key: row for row in self.review.rows if row.kind == "pack"}
        selected = set(rows) if selection is None else set(selection)
        if not selected:
            raise ValueError("Select at least one pack to import")
        if selected - rows.keys():
            raise ValueError("A selected pack is not part of this review. Review again")
        pending = list(selected)
        while pending:
            row = rows[pending.pop()]
            for dependency in row.dependencies:
                if dependency not in rows:
                    raise ValueError(f"The reviewed dependency {dependency} is missing")
                if dependency not in selected:
                    selected.add(dependency)
                    pending.append(dependency)
        return selected

    def commit(
        self,
        workspace: Path,
        accepted_publishers: list[str],
        selected_packs: list[str] | None = None,
    ) -> Path | None:
        """Publish only displayed new directories; reject stale or changed reviews."""
        if workspace.resolve() != self.workspace or time.monotonic() - self.created_at > 1800:
            raise FileExistsError(
                "This import review expired or its workspace changed. Review again"
            )
        if self.review.kind != "pack" and selected_packs is not None:
            raise ValueError("Pack selection is only available for pack imports")
        selection = self.selected_pack_keys(selected_packs) if self.review.kind == "pack" else None
        rows = [row for row in self.review.rows if selection is None or row.key in selection]
        if (
            self.review.kind == "pack"
            and any(row.status in {"conflict", "missing"} for row in rows)
        ) or (self.review.kind != "pack" and not self.review.can_import):
            raise ValueError("Resolve pack conflicts before importing this release")
        publishers = (
            {row.key.split(":", 1)[0] for row in rows} & set(self.review.publishers)
            if selection is not None
            else set(self.review.publishers)
        )
        if publishers - set(accepted_publishers):
            raise ValueError("Confirm all publisher namespaces shown in the import review")
        selected_destinations = {row.destination for row in rows}
        all_pack_sources = set().union(*self.pack_sources.values())
        selected_sources = set().union(
            *(
                paths
                for key, paths in self.pack_sources.items()
                if selection is None or key in selection
            )
        )
        for path, digest in self.sources.items():
            if path in all_pack_sources and path not in selected_sources:
                continue
            if hashlib.sha256(_local_file(path).read_bytes()).hexdigest() != digest:
                raise FileExistsError("Source files changed after review. Review the import again")
        for relative, expected in self.reservations.items():
            target = workspace / relative
            if selection is not None and str(target) not in selected_destinations:
                continue
            if expected is None:
                if target.exists() or target.is_symlink():
                    raise FileExistsError(f"Destination appeared after review: {target}")
            else:
                identity = relative.parts[-4:]
                pack = PackRepository(workspace).resolve(
                    PackReference(
                        source="project",
                        publisher=identity[0],
                        name=identity[2],
                        version=identity[3],
                    ),
                    expected_type=identity[1],
                )
                if pack.digest != expected:
                    raise FileExistsError("A destination pack changed after review. Review again")
        if (
            self.configuration_source is not None
            and self.configuration_fingerprint
            != context_fingerprint(self.configuration_source)
            + overlay_fingerprint(self.configuration_source.project_root)
        ):
            raise FileExistsError("Source configuration changed after review. Review again")
        published: list[Path] = []
        try:
            for relative in self.publish_roots:
                target = workspace / relative
                if selection is not None and str(target) not in selected_destinations:
                    continue
                if any(
                    row.status == "conflict" and row.destination == str(target)
                    for row in self.review.rows
                ):
                    continue
                current = workspace
                for part in relative.parts[:-1]:
                    current /= part
                    if current.is_symlink():
                        raise ValueError("Import destination must not contain links")
                    current.mkdir(exist_ok=True)
                # Reserve without overwriting even an empty directory created concurrently.
                if (self.stage / relative).is_file():
                    target.touch(exist_ok=False)
                else:
                    target.mkdir()
                published.append(target)
                os.replace(self.stage / relative, target)
        except (OSError, ValueError):
            for target in reversed(published):
                if target.is_file():
                    target.unlink()
                else:
                    shutil.rmtree(target)
            raise
        return workspace / self.target if self.target else None


def _find_pack(
    reference: PackReference,
    kind: PackType,
    origin: Path,
    request: ScenarioImportRequest,
    workspace: Path,
) -> tuple[LoadedPack | None, PackRepository]:
    repository = PackRepository(workspace)
    # Available destination identities take precedence; path references are rebound explicitly.
    candidate = (
        reference.model_copy(update={"source": "project", "path": None})
        if reference.source == "path"
        else reference
    )
    try:
        return repository.resolve(candidate, expected_type=kind, declaring_file=origin), repository
    except PackError:
        pass
    locations: list[tuple[PackRepository, PackReference]] = []
    override = request.pack_locations.get(pack_key(reference, kind))
    if override:
        locations.append(
            (
                repository,
                reference.model_copy(update={"source": "path", "path": str(override.expanduser())}),
            )
        )
    if reference.source == "path":
        locations.append((repository, reference))
    for root in request.source_workspaces:
        locations.append(
            (
                PackRepository(root.expanduser()),
                reference.model_copy(update={"source": "project", "path": None}),
            )
        )
    for source_repository, source_reference in locations:
        try:
            return source_repository.resolve(
                source_reference, expected_type=kind, declaring_file=origin
            ), source_repository
        except PackError:
            continue
    return None, repository


def prepare_scenario(
    request: ScenarioImportRequest, workspace: Path, cache: Path
) -> PreparedImport:
    """Capture a scenario, nested includes, assets, and selected pack closure."""
    source = _local_file(request.path)
    if source.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError("Choose a .yaml or .yml scenario file")
    selection = (
        select_context(context=request.configuration_context)
        if request.configuration_context is not None
        else None
    )
    if selection is not None and selection.project_root not in request.source_workspaces:
        request = request.model_copy(
            update={"source_workspaces": [*request.source_workspaces, selection.project_root]}
        )
    graph = load_scenario_source_graph(source)
    if graph.data.get("kind") == "evidenceforge.resolved-scenario" or not (
        "name" in graph.data
        and ("version" in graph.data or "scenario_version" in graph.data)
        and any(key in graph.data for key in ("environment", "composition"))
    ):
        raise ValueError(
            "Choose an authored scenario YAML, not a fragment or generated resolved scenario"
        )
    plan = PreparedImport(workspace, cache, "scenario", request.name)
    try:
        destination = Path("scenarios") / request.name
        if (workspace / destination).exists() or (workspace / destination).is_symlink():
            raise FileExistsError("A scenario folder with this name already exists")
        plan.review.destination = workspace / destination
        plan.project_id = request.project_id
        plan.target = destination / "scenario.yaml"
        plan.publish_roots.append(destination)
        plan.reservations[destination] = None
        locations = {
            entry.path: (
                Path("scenario.yaml")
                if entry.path == graph.root
                else Path(".sources")
                / f"{hashlib.sha256(str(entry.path).encode()).hexdigest()[:12]}-{entry.path.name}"
            )
            for entry in graph.sources
        }
        for entry in graph.sources:
            data = load_yaml_text(entry.content.decode("utf-8"))
            for key in ("includes", "include"):
                if key not in data:
                    continue
                entries = [data[key]] if isinstance(data[key], str) else data[key]
                relocated = []
                for original in entries:
                    child = Path(os.path.abspath(entry.path.parent / original))
                    relocated.append(
                        Path(
                            os.path.relpath(locations[child], locations[entry.path].parent)
                        ).as_posix()
                    )
                data[key] = relocated[0] if isinstance(data[key], str) else relocated
            composition = data.get("composition")
            composition = composition if isinstance(composition, dict) else {}
            industries = composition.get("industries")
            for ref in [
                *(industries if isinstance(industries, list) else []),
                *([composition["organization"]] if composition.get("organization") else []),
            ]:
                if isinstance(ref, dict) and ref.get("source") == "path":
                    ref["source"] = "project"
                    ref.pop("path", None)
            environment = data.get("environment") or {}
            email = environment.get("email") if isinstance(environment, dict) else None
            if isinstance(email, dict) and email.get("corpus"):
                content = read_text_file_beneath(
                    entry.path.parent,
                    str(email["corpus"]),
                    max_bytes=EMAIL_CORPUS_MAX_SOURCE_BYTES,
                    label="email corpus",
                ).encode()
                asset = _local_file(entry.path.parent / str(email["corpus"]))
                asset_relative = (
                    locations[entry.path].parent
                    / "assets"
                    / f"{hashlib.sha256(str(asset).encode()).hexdigest()[:12]}-{asset.name}"
                )
                plan.add_files(destination, {str(asset_relative): content})
                plan.sources[asset] = hashlib.sha256(content).hexdigest()
                email["corpus"] = Path(
                    os.path.relpath(asset_relative, locations[entry.path].parent)
                ).as_posix()
                plan.review.rows.append(
                    DependencyRow(
                        key=str(asset),
                        kind="asset",
                        label=asset.name,
                        status="copy",
                        detail="Referenced email corpus",
                        source=str(asset),
                        destination=str(workspace / destination / asset_relative),
                    )
                )
            plan.add_files(
                destination,
                {str(locations[entry.path]): yaml.safe_dump(data, sort_keys=False).encode()},
            )
            plan.sources[entry.path] = entry.sha256
            plan.review.rows.append(
                DependencyRow(
                    key=str(entry.path),
                    kind="include",
                    label=entry.path.name,
                    status="copy",
                    detail="Scenario YAML"
                    if entry.path == graph.root
                    else "Nested include; path rebound",
                    source=str(entry.path),
                    destination=str(workspace / destination / locations[entry.path]),
                )
            )
        name_origin = graph.origins.get(("name",), graph.root)
        name_file = plan.stage / destination / locations[name_origin]
        if name_origin != graph.root:
            # Keep the editable identity in the root document so workspace rename
            # remains a direct, atomic edit even when the source used metadata includes.
            metadata = load_yaml_text(name_file.read_text())
            metadata.pop("name")
            name_file.write_text(yaml.safe_dump(metadata, sort_keys=False), encoding="utf-8")
            root_file = plan.stage / plan.target
            root_data = load_yaml_text(root_file.read_text())
            root_data["name"] = request.name
            root_file.write_text(yaml.safe_dump(root_data, sort_keys=False), encoding="utf-8")
        else:
            rename_scenario(
                name_file, request.name, hashlib.sha256(name_file.read_bytes()).hexdigest()
            )
        # Includes were already parsed with the CLI's bounded, duplicate-key-aware loader.
        try:
            references = _scenario_references(graph)
        except ValidationError as exc:
            references = []
            plan.review.rows.append(
                DependencyRow(
                    key="composition",
                    kind="pack",
                    label="Pack references",
                    status="missing",
                    detail=f"Repair these references in the imported scenario: {exc}",
                )
            )
        for reference, kind, origin in references:
            pack, repository = _find_pack(reference, kind, origin, request, workspace)
            if pack is None:
                key = pack_key(reference, kind)
                plan.review.rows.append(
                    DependencyRow(
                        key=key,
                        kind="pack",
                        label=key,
                        status="missing",
                        detail="Import this exact pack version to resolve the scenario dependency",
                    )
                )
                continue
            # Industry dependencies can themselves come from separately selected workspaces.
            for index, dependency in enumerate(pack.manifest.industry_dependencies):
                locked = next(
                    (
                        lock
                        for lock in pack.lock.dependencies
                        if (lock.publisher, lock.name) == (dependency.publisher, dependency.name)
                    ),
                    None,
                )
                if locked is None or not version_satisfies_constraint(
                    locked.version, dependency.version_constraint
                ):
                    raise PackError(
                        "Organization pack has an invalid or incomplete dependency lock"
                    )
                dependency_ref = PackReference(
                    source=dependency.source,
                    publisher=dependency.publisher,
                    name=dependency.name,
                    version=locked.version,
                    path=dependency.path,
                )
                member, _ = _find_pack(
                    dependency_ref,
                    "industry",
                    pack.industry_dependency_declaring_files[index],
                    request,
                    workspace,
                )
                key = pack_key(dependency_ref, "industry")
                if member is None or member.digest != locked.digest:
                    plan.review.rows.append(
                        DependencyRow(
                            key=key,
                            kind="pack",
                            label=key,
                            status="missing" if member is None else "conflict",
                            detail="Locked industry pack is missing"
                            if member is None
                            else "Digest does not match the organization's locked dependency",
                            digest=locked.digest,
                        )
                    )
                else:
                    plan.add_pack(member)
            plan.add_pack(pack)
        available_documents = [
            path.name
            for path in sorted(source.parent.glob("*.md"))
            if path.is_file() and not path.is_symlink()
        ][:64]
        plan.review.documents = available_documents
        selected = available_documents if request.documents is None else request.documents
        if any(name not in available_documents for name in selected):
            raise ValueError("Select only Markdown documents listed alongside the source scenario")
        for name in selected:
            document = _local_file(source.parent / name)
            content = document.read_bytes()
            plan.sources[document] = hashlib.sha256(content).hexdigest()
            plan.add_files(destination, {name: content})
            plan.review.rows.append(
                DependencyRow(
                    key=name,
                    kind="document",
                    label=name,
                    status="copy",
                    detail="Selected supporting document",
                )
            )
        plan.review.rows.append(
            DependencyRow(
                key="overlays",
                kind="overlay",
                label="Workspace configuration",
                status="warning",
                detail="Destination workspace configuration applies first. Explicitly selected source configuration is copied into private layers."
                if selection
                else "Use destination workspace overlays. Source-workspace overlays are not copied; select a configuration context to include them.",
            )
        )
        for root in request.source_workspaces:
            if (root / ".eforge/config").is_dir():
                plan.review.rows.append(
                    DependencyRow(
                        key=str(root),
                        kind="overlay",
                        label=str(root),
                        status="warning",
                        detail="Source has project overlays; review destination configuration before generating",
                    )
                )
        plan.publish_roots.remove(destination)
        plan.publish_roots.append(destination)
        if selection is not None:
            plan.configuration_source = selection
            plan.configuration_fingerprint = context_fingerprint(selection) + overlay_fingerprint(
                selection.project_root
            )
            layers: list[OverlayReference] = []
            for index, captured in enumerate(capture_overlays(selection)):
                relative = destination / "configuration" / str(index)
                (plan.stage / relative).mkdir(parents=True, exist_ok=True)
                plan.add_files(relative, captured.files)
                layers.append(
                    OverlayReference(
                        name=f"Imported {index + 1}: {captured.name}"[:80], path=relative
                    )
                )
                for filename, content in captured.files.items():
                    plan.sources[captured.root / filename] = hashlib.sha256(content).hexdigest()
                plan.review.rows.append(
                    DependencyRow(
                        key=f"configuration-{index}",
                        kind="overlay",
                        label=captured.name,
                        status="copy",
                        detail=f"Copy {len(captured.files)} files as a private layer after destination workspace and project configuration",
                        source=str(captured.root),
                        destination=str(workspace / relative),
                    )
                )
            context_file = scenario_context_path(workspace / plan.target, workspace).relative_to(
                workspace
            )
            document = ConfigurationContext(
                project_root=Path(os.path.relpath(Path("."), context_file.parent)),
                overlays=[
                    layer.model_copy(
                        update={"path": Path(os.path.relpath(layer.path, context_file.parent))}
                    )
                    for layer in layers
                ],
            )
            plan.add_files(
                context_file.parent,
                {
                    context_file.name: yaml.safe_dump(
                        document.model_dump(mode="json"), sort_keys=False
                    ).encode()
                },
            )
            plan.reservations[context_file] = None
            plan.publish_roots.append(context_file)
            plan.sources[selection.path] = hashlib.sha256(selection.path.read_bytes()).hexdigest()
        return plan
    except (
        OSError,
        ValueError,
        ConfigurationError,
        PathSafetyError,
        PackError,
        ValidationError,
        yaml.YAMLError,
    ):
        plan.close()
        raise


def prepare_archive(request: PackImportRequest, workspace: Path, cache: Path) -> PreparedImport:
    """Prepare validated .efpack members for explicit workspace-local import."""
    candidate = request.path.expanduser()
    if candidate.is_dir():
        if candidate.is_symlink():
            raise ValueError("Select a regular source workspace, not a link")
        repository = PackRepository(candidate)
        plan = PreparedImport(workspace, cache, "pack", candidate.name)
        plan.project_id = request.project_id
        try:
            packs = [pack for pack in repository.list() if pack.source == "project"]
            if not packs:
                raise ValueError("This workspace has no editable packs in .eforge/packs")
            source_request = ScenarioImportRequest(
                path=candidate,
                name="pack-import",
                source_workspaces=[candidate, *request.source_workspaces],
            )
            for pack in packs:
                for index, dependency in enumerate(pack.manifest.industry_dependencies):
                    locked = next(
                        (
                            entry
                            for entry in pack.lock.dependencies
                            if (entry.publisher, entry.name)
                            == (dependency.publisher, dependency.name)
                        ),
                        None,
                    )
                    if locked is None:
                        raise PackError("Organization is missing an exact dependency lock")
                    reference = PackReference(
                        source=dependency.source,
                        publisher=dependency.publisher,
                        name=dependency.name,
                        version=locked.version,
                        path=dependency.path,
                    )
                    member, _ = _find_pack(
                        reference,
                        "industry",
                        pack.industry_dependency_declaring_files[index],
                        source_request,
                        workspace,
                    )
                    if member is None or member.digest != locked.digest:
                        raise PackError(
                            f"Locate the locked dependency {pack_key(reference, 'industry')} before importing this pack"
                        )
                    plan.add_pack(member)
                plan.add_pack(pack)
            plan.review.destination = workspace / ".eforge/packs"
            plan.review.can_import = not any(row.status == "conflict" for row in plan.review.rows)
            return plan
        except (OSError, ValueError, PackError):
            plan.close()
            raise
    source = _local_file(request.path)
    archive = validate_efpack(source)
    plan = PreparedImport(workspace, cache, "pack", archive.root["name"])
    plan.project_id = request.project_id
    try:
        plan.sources[source] = hashlib.sha256(source.read_bytes()).hexdigest()
        extracted = plan.stage / "received"
        for path, content in archive.files.items():
            target = extracted / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        repository = PackRepository(workspace)
        for member in sorted(archive.members, key=lambda item: item["type"]):
            root = (
                extracted
                / "packs"
                / member["publisher"]
                / member["type"]
                / member["name"]
                / member["version"]
            )
            pack = repository.resolve(
                PackReference(
                    source="path",
                    path=str(root),
                    publisher=member["publisher"],
                    name=member["name"],
                    version=member["version"],
                ),
                expected_type=member["type"],
            )
            plan.add_pack(pack)
        # Received source files live in our own disposable stage, not user locations.
        plan.sources = {source: plan.sources[source]}
        plan.review.can_import = not any(row.status == "conflict" for row in plan.review.rows)
        plan.review.destination = workspace / ".eforge/packs"
        shutil.rmtree(extracted)
        return plan
    except (OSError, ValueError, PackError, yaml.YAMLError):
        plan.close()
        raise
