"""File-based artifact properties, edits, history and exact validation provenance."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge import __version__
from evidenceforge.artifacts.comparison import ParentComparison, compare_parent
from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    _capture_sources,
    _edit_envelope,
    _publication_lock,
    _receipt_root,
    artifact_root,
    assert_mutable,
    canonical_bytes,
    inspect_artifact,
    list_drafts,
    list_versions,
    resolve_reference,
    sha256,
    validation_findings,
)
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.naming import DisplayName
from evidenceforge.schema import LifecycleMetadata, identify_document
from evidenceforge.utils import load_scenario_source_graph

logger = logging.getLogger(__name__)


class MetadataEdit(BaseModel):
    """Only human-authored properties; identity and schema have separate operations."""

    display_name: DisplayName | None = None
    description: str = Field(default="", max_length=65536)
    release_notes: str = Field(default="", max_length=65536)
    model_config = ConfigDict(extra="forbid")


class ValidationProvenance(BaseModel):
    """Successful canonical validation of exact inputs, not a compatibility promise."""

    evidenceforge_version: str
    completed_at: str
    input_digest: str
    warnings: int = 0
    model_config = ConfigDict(extra="forbid", frozen=True)


class NoteHistoryEntry(BaseModel):
    """Notes from one available exact release or draft, or an unavailable ancestor."""

    name: str
    publisher: str | None = None
    version: str | None = None
    draft_id: str | None = None
    source_schema_version: str | None = None
    digest: str
    status: str
    notes: str = ""
    available: bool = True
    path: Path | None = None
    model_config = ConfigDict(extra="forbid")


class ArtifactProperties(BaseModel):
    """Computed properties. Files, rather than an application index, are authoritative."""

    kind: str
    name: str
    display_name: str | None = None
    description: str = ""
    path: Path
    schema_version: str | None = None
    lifecycle: LifecycleMetadata | None = None
    digest: str
    semantic_digest: str | None = None
    upgrade_available: bool = False
    requires_evidenceforge: str | None = None
    validated_with: ValidationProvenance | None = None
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    history: list[NoteHistoryEntry] = Field(default_factory=list)
    comparisons: list[ParentComparison] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid")


def validation_signature(
    source: Path, project_root: Path, context: Path | None = None, *, compiled: Any = None
) -> str:
    """Capture source, dependencies and effective configuration for a validation record."""
    from evidenceforge.composition.compiler import (
        build_management_effective_config,
        compile_scenario,
    )
    from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference

    info = inspect_artifact(source)
    if info["kind"] == "scenario":
        compiled = compiled or compile_scenario(source, project_root=project_root, context=context)
        payload = {"source": info["digest"], "compiled": compiled.digests}
    else:
        reference, kind = parse_pack_cli_reference(str(source))
        repository = PackRepository(project_root)
        pack = repository.resolve(reference, expected_type=kind)
        dependencies = repository.validate_semantics(pack)
        payload = {
            "source": info["digest"],
            "pack": pack.selected().model_dump(mode="json"),
            "dependencies": [
                dependency.selected().model_dump(mode="json") for dependency in dependencies
            ],
            "configuration": build_management_effective_config(
                project_root, context=context
            ).model_dump(mode="json"),
        }
    return sha256(canonical_bytes(payload))


def validation_record(input_digest: str, warnings: int = 0) -> ValidationProvenance:
    """Describe a completed check performed by this installed engine."""
    return ValidationProvenance(
        evidenceforge_version=__version__,
        completed_at=datetime.now(UTC).isoformat(),
        input_digest=input_digest,
        warnings=warnings,
    )


def check_artifact(
    source: Path, *, project_root: Path, context: Path | None = None
) -> dict[str, Any]:
    """Validate and record success in portable project files without touching the source."""
    before = validation_signature(source, project_root, context)
    findings = validation_findings(source, project_root=project_root, context=context)
    if before != validation_signature(source, project_root, context):
        raise ArtifactError("inputs changed during validation; validate again")
    valid = not any(issue["severity"] == "error" for issue in findings)
    record = None
    if valid:
        record = remember_validation(
            source,
            project_root,
            before,
            sum(issue["severity"] == "warning" for issue in findings),
            context=context,
        )
    return {
        "valid": valid,
        "findings": findings,
        "validated_with": record.model_dump(mode="json") if record else None,
    }


def remember_validation(
    source: Path, project_root: Path, before: str, warnings: int = 0, *, context: Path | None = None
) -> ValidationProvenance:
    """Retain a completed successful check only while all captured inputs still match."""
    if before != validation_signature(source, project_root, context):
        raise ArtifactError("inputs changed during validation; validate again")
    record = validation_record(before, warnings)
    root = artifact_root(project_root) / "validations"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"{inspect_artifact(source)['digest']}.json"
    temporary = root / f".{uuid4().hex}.json"
    try:
        temporary.write_bytes(canonical_bytes(record.model_dump(mode="json")))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return record


def edit_metadata(
    source: Path, edit: MetadataEdit, *, project_root: Path, expected_digest: str
) -> None:
    """Save a reviewed draft's metadata together, preserving comments and include ownership."""
    with _publication_lock(project_root):
        assert_mutable(source)
        current = inspect_artifact(source)
        if not expected_digest or current["digest"] != expected_digest:
            raise ArtifactError("source changed after review; inspect it again")
        if (current.get("lifecycle") or {}).get("status") != "draft":
            raise ArtifactError("create a Schema 3 draft before editing properties")
        graph = load_scenario_source_graph(source)
        files, entry, base = _capture_sources(
            source, "scenario" if current["kind"] == "scenario" else "pack"
        )
        edited = _edit_envelope(files, entry, graph, base, edit.model_dump(exclude_unset=True))
        staged: dict[Path, Path] = {}
        backups: dict[Path, Path] = {}
        replaced: list[Path] = []
        try:
            for member, content in edited.items():
                if content == files[member]:
                    continue
                owner = base / member
                staged[owner] = owner.with_name(f".{owner.name}.{uuid4().hex}.properties")
                backups[owner] = owner.with_name(f".{owner.name}.{uuid4().hex}.backup")
                for path, payload in ((staged[owner], content), (backups[owner], files[member])):
                    with path.open("xb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    path.chmod(owner.stat().st_mode & 0o777)
            if any((base / member).read_bytes() != content for member, content in files.items()):
                raise ArtifactError("source changed while saving properties; inspect it again")
            for owner, temporary in staged.items():
                os.replace(temporary, owner)
                replaced.append(owner)
        except OSError:
            for owner in reversed(replaced):
                os.replace(backups[owner], owner)
            raise
        finally:
            for path in (*staged.values(), *backups.values()):
                path.unlink(missing_ok=True)


def inspect_properties(
    source: Path,
    *,
    project_root: Path,
    candidates: list[Path] | None = None,
    context: Path | None = None,
) -> ArtifactProperties:
    """Inspect repairable sources, available notes and verified validation receipts."""
    from evidenceforge.composition.compiler import compile_scenario

    current = inspect_artifact(source)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    metadata = contract.lifecycle
    result = ArtifactProperties(
        **{key: current[key] for key in ("kind", "name", "display_name", "digest")},
        path=source,
        description=graph.data.get("description", ""),
        schema_version=contract.schema_version,
        lifecycle=metadata,
        semantic_digest=current.get("semantic_digest"),
        upgrade_available=contract.upgrade_available,
        requires_evidenceforge=graph.data.get("requires_evidenceforge"),
        source_files=[str(member.path) for member in graph.sources],
    )
    try:
        if result.kind == "scenario":
            compiled = compile_scenario(source, project_root=project_root, context=context)
            result.dependencies = [pack.model_dump(mode="json") for pack in compiled.selected_packs]
        else:
            result.dependencies = list(graph.data.get("industry_dependencies", []))
    except (EvidenceForgeError, OSError, ValueError) as exc:
        result.findings.append(str(exc))
    root = _receipt_root(source)
    record_path = (
        (root / "validated-with.json")
        if root
        else artifact_root(project_root) / "validations" / f"{result.digest}.json"
    )
    if record_path.is_file():
        try:
            record = ValidationProvenance.model_validate_json(record_path.read_bytes())
            if root or record.input_digest == validation_signature(source, project_root, context):
                result.validated_with = record
        except (EvidenceForgeError, OSError, ValueError):
            result.findings.append("The previous validation does not match the current inputs.")
    paths = list(candidates or [])
    paths.extend(Path(draft["path"]) for draft in list_drafts(project_root))
    if metadata and metadata.publisher:
        versions = list_versions(
            project_root, kind=result.kind, name=result.name, publisher=metadata.publisher
        )
        paths.extend(Path(version["path"]) for version in versions)
    if metadata:
        for parent in metadata.parents:
            if parent.publisher and parent.version:
                try:
                    paths.append(
                        resolve_reference(
                            f"{parent.publisher}:{parent.kind}:{quote(parent.name, safe='')}@{parent.version}",
                            project_root,
                        )
                    )
                except (EvidenceForgeError, OSError, ValueError):
                    pass
    paths.insert(0, source)
    for path in dict.fromkeys(paths):
        try:
            info = inspect_artifact(path)
            life = info.get("lifecycle") or {}
            # Include only the same logical family or an exact recorded ancestor.
            same = (
                info["kind"] == result.kind
                and info["name"] == result.name
                and life.get("publisher") == (metadata.publisher if metadata else None)
            )
            parent = metadata and any(
                info["digest"] == reference.digest for reference in metadata.parents
            )
            if not same and not parent:
                continue
            data = load_scenario_source_graph(path).data
            result.history.append(
                NoteHistoryEntry(
                    name=info["name"],
                    publisher=life.get("publisher"),
                    version=life.get("version"),
                    draft_id=life.get("draft_id"),
                    digest=info["digest"],
                    status=life.get("status", "legacy"),
                    notes=data.get("release_notes", ""),
                    path=path,
                )
            )
        except (EvidenceForgeError, OSError, ValueError):
            continue
    if metadata:
        for parent in metadata.parents:
            result.comparisons.append(compare_parent(source, parent, project_root, paths))
            if not any(entry.digest == parent.digest for entry in result.history):
                result.history.append(
                    NoteHistoryEntry(
                        **parent.model_dump(mode="json", exclude={"kind"}),
                        status="ancestor",
                        available=False,
                    )
                )
    result.history.sort(
        key=lambda entry: (
            entry.status == "draft",
            tuple(int(part) for part in (entry.version or "0.0.0").split(".")),
            str(entry.draft_id or ""),
        ),
        reverse=True,
    )
    return result
