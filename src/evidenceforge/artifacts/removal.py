"""Reviewed permanent artifact removal usable without Studio."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import (
    MAX_BYTES,
    ArtifactError,
    ReleaseReceipt,
    _publication_lock,
    _safe_path,
    canonical_bytes,
    safe_relative,
)
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.utils import load_scenario_source_graph

logger = logging.getLogger(__name__)


class ScenarioDeleteReview(BaseModel):
    """The exact files and inclusion consumers of one selected scenario."""

    model_config = ConfigDict(extra="forbid")

    source: Path
    target: Path
    revision: str
    files: int
    bytes: int
    whole_artifact: bool
    include_files: bool = False
    run_count: int = 0
    run_paths: list[Path] = Field(default_factory=list)
    consumers: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    removable: bool


class ScenarioDeleteRequest(BaseModel):
    """Explicit acceptance of a current removal review."""

    model_config = ConfigDict(extra="forbid")

    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    include_files: bool = False


class ScenarioDeleted(BaseModel):
    """Confirmation of permanent removal with no retained source content."""

    model_config = ConfigDict(extra="forbid")

    deleted_path: Path


def _target(source: Path, workspace: Path) -> Path:
    source = _safe_path(source)
    workspace = _safe_path(workspace.resolve())
    if not source.is_relative_to(workspace) or not source.is_file():
        raise ArtifactError("Only local workspace scenarios can be deleted")
    # A managed draft/release is one unit, including its frozen inputs and receipt.
    artifacts = workspace / ".eforge" / "artifacts"
    for parent in source.parents:
        if parent == artifacts or not parent.is_relative_to(artifacts):
            continue
        relative = parent.relative_to(artifacts).parts
        marker = None
        if len(relative) == 4 and relative[:2] == ("drafts", "scenario"):
            marker = parent / "draft.json"
        elif len(relative) == 5 and relative[0] == "releases" and relative[2] == "scenario":
            marker = parent / "release.json"
        if marker is not None:
            _safe_path(marker)
            if marker.stat().st_size > MAX_BYTES:
                raise ArtifactError("The scenario receipt is too large")
            data = json.loads(marker.read_bytes())
            if not isinstance(data, dict) or parent / safe_relative(data["entrypoint"]) != source:
                raise ArtifactError("Choose the scenario entrypoint recorded in its receipt")
            return parent
    if not source.is_relative_to(workspace / "scenarios"):
        raise ArtifactError("Choose a scenario under this workspace's scenarios directory")
    # Legacy folders may contain other scenarios, shared assets, or generated runs.
    # Retire only the selected YAML; preserve every other file in those folders.
    return source


def review_scenario_deletion(
    source: Path,
    workspace: Path,
    scenario_paths: list[Path] | None = None,
    *,
    include_files: bool = False,
) -> ScenarioDeleteReview:
    """Capture current files and refuse removal of live included source material."""
    source = source.absolute()
    workspace = workspace.resolve()
    target = _target(source, workspace)
    paths = {item.path for item in discover_scenarios(workspace, [])}
    paths.update(scenario_paths or [])
    if source not in paths:
        raise ArtifactError("Choose a discovered authored scenario, not a fragment or bundle")
    if include_files and target == source:
        folder = source.parent
        if folder == workspace / "scenarios" or any(
            path != source and path.is_relative_to(folder) for path in paths
        ):
            raise ArtifactError("This folder is shared by scenarios; delete only the selected YAML")
        target = folder
    signature, files, size = deletion_snapshot(target)
    fingerprints = [signature, str(include_files)]
    consumers: list[str] = []
    problems: list[str] = []
    for path in sorted(paths):
        if path == source or path.is_relative_to(target):
            continue
        try:
            graph = load_scenario_source_graph(path)
            fingerprints.extend(f"{member.path}:{member.sha256}" for member in graph.sources)
            if any(
                member.path == target or member.path.is_relative_to(target)
                for member in graph.sources
            ):
                consumers.append(str(path))
            environment = graph.data.get("environment")
            email = environment.get("email") if isinstance(environment, dict) else None
            corpus = email.get("corpus") if isinstance(email, dict) else None
            if isinstance(corpus, str):
                origin = graph.origins.get(("environment", "email", "corpus"), path)
                asset = (origin.parent / corpus).resolve()
                if asset == target or asset.is_relative_to(target):
                    consumers.append(str(path))
        except (OSError, ValueError, EvidenceForgeError) as exc:
            problems.append(f"Cannot check scenario {path}: {exc}")
    fingerprints.extend(consumers)
    fingerprints.extend(problems)
    return ScenarioDeleteReview(
        source=source,
        target=target,
        revision=hashlib.sha256(canonical_bytes(sorted(fingerprints))).hexdigest(),
        files=files,
        bytes=size,
        include_files=include_files,
        whole_artifact=target.is_dir(),
        consumers=sorted(set(consumers)),
        problems=problems,
        removable=not consumers and not problems,
    )


@contextmanager
def _directory_beneath(workspace: Path, path: Path) -> Iterator[int]:
    """Open each local directory without following substituted links."""
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


class AffectedItem(BaseModel):
    """One exact authored consumer shown in a deletion warning."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["industry_pack", "organization_pack", "scenario"]
    name: str
    version: str = ""
    publisher: str = ""
    path: Path
    frozen: bool = False


def deletion_snapshot(target: Path) -> tuple[str, int, int]:
    """Fingerprint paths and file metadata without reading large generated datasets."""
    _safe_path(target)
    digest = hashlib.sha256()
    files = 0
    size = 0
    paths = [target]
    if target.is_dir():
        paths.extend(sorted(target.rglob("*")))
    for path in paths:
        _safe_path(path)
        metadata = path.stat()
        digest.update(
            canonical_bytes(
                [
                    str(path),
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_mode,
                ]
            )
        )
        if path.is_file():
            files += 1
            size += metadata.st_size
        elif not path.is_dir():
            raise ArtifactError(f"Cannot delete a non-regular artifact member: {path}")
    return digest.hexdigest(), files, size


def _delete_tree_last_source(target: Path, source: Path) -> None:
    """Remove companions first, keeping the entrypoint available after partial failures."""
    import shutil

    if target == source:
        if os.name == "nt":
            target.unlink()
            return
        with _directory_beneath(target.parent, target.parent) as descriptor:
            os.unlink(target.name, dir_fd=descriptor)
            os.fsync(descriptor)
        return
    protected = {source, target / "release.json", target / "draft.json"}
    for path in sorted(target.iterdir()):
        _safe_path(path)
        if path in protected or source.is_relative_to(path):
            if path.is_dir():
                _delete_tree_last_source(path, source)
            continue
        if os.name == "nt":
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            continue
        with _directory_beneath(target, path.parent) as descriptor:
            if path.is_dir():
                shutil.rmtree(path.name, dir_fd=descriptor)
            else:
                os.unlink(path.name, dir_fd=descriptor)
    # Recursive descent keeps the source; the outer call performs the final unlink.


def delete_artifact_files(source: Path, target: Path, workspace: Path, kind: str) -> Path:
    """Permanently delete one reviewed local artifact; retain only release identity metadata."""
    source = _safe_path(source)
    target = _safe_path(target)
    workspace = _safe_path(workspace.resolve())
    if not source.is_relative_to(workspace) or not source.is_relative_to(target):
        raise ArtifactError("Only the selected workspace artifact can be deleted")
    record_root = _safe_path(workspace / ".eforge" / "deletions")
    record_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity = None
    if target.is_dir() and (target / "release.json").is_file():
        receipt = ReleaseReceipt.model_validate_json((target / "release.json").read_bytes())
        identity = {
            "kind": receipt.kind,
            "name": receipt.name,
            "publisher": receipt.lifecycle.publisher,
            "version": receipt.lifecycle.version,
            "digest": receipt.digest,
        }
    elif kind in {"industry", "organization"}:
        from evidenceforge.composition.packs import parse_pack_cli_reference

        reference, pack_kind = parse_pack_cli_reference(str(source))
        if reference.source != "draft":
            identity = {
                "kind": pack_kind,
                "name": reference.name,
                "publisher": reference.publisher,
                "version": reference.version,
            }
    record = record_root / f"{uuid4().hex}.json"
    with record.open("xb") as stream:
        stream.write(
            canonical_bytes(
                {
                    "deletion_version": 1,
                    "source": source.relative_to(workspace).as_posix(),
                    "kind": kind,
                    "release": identity,
                }
            )
        )
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if target == source:
            _delete_tree_last_source(target, source)
        else:
            _delete_tree_last_source(target, source)
            _safe_path(source)
            if os.name == "nt":
                source.unlink()
            else:
                with _directory_beneath(workspace, source.parent) as descriptor:
                    os.unlink(source.name, dir_fd=descriptor)
            for marker in (target / "release.json", target / "draft.json"):
                _safe_path(marker)
                if os.name == "nt":
                    marker.unlink(missing_ok=True)
                elif marker.exists():
                    with _directory_beneath(workspace, marker.parent) as descriptor:
                        os.unlink(marker.name, dir_fd=descriptor)
            # All files are gone; remove the now-empty entrypoint directories and root.
            for directory in sorted(
                target.rglob("*"), key=lambda path: len(path.parts), reverse=True
            ):
                if directory.is_dir():
                    _safe_path(directory)
                    if os.name == "nt":
                        directory.rmdir()
                    else:
                        with _directory_beneath(workspace, directory.parent) as descriptor:
                            os.rmdir(directory.name, dir_fd=descriptor)
            if os.name == "nt":
                target.rmdir()
            else:
                with _directory_beneath(workspace, target.parent) as descriptor:
                    os.rmdir(target.name, dir_fd=descriptor)
    except OSError as exc:
        raise ArtifactError(
            f"Deletion was interrupted; some files may already be permanently removed. "
            f"Files remain at {target}. Refresh the deletion review and retry: {exc}"
        ) from exc
    logger.info("Permanently removed %s at %s", kind, target)
    return target


def remove_scenario(
    source: Path,
    workspace: Path,
    revision: str,
    scenario_paths: list[Path] | None = None,
    *,
    include_files: bool = False,
) -> ScenarioDeleted:
    """Recheck explicit acceptance and permanently delete the selected scenario."""
    with _publication_lock(workspace):
        review = review_scenario_deletion(
            source, workspace, scenario_paths, include_files=include_files
        )
        if revision != review.revision:
            raise FileExistsError("Scenario files or references changed. Review deletion again")
        if not review.removable:
            raise ArtifactError("Resolve scenario inclusion references and inspection errors first")
        return ScenarioDeleted(
            deleted_path=delete_artifact_files(review.source, review.target, workspace, "scenario")
        )


def retired_artifact_sources(workspace: Path, kind: str) -> set[Path]:
    """Reconcile index cleanup after irreversible deletion, without retained content."""
    sources: set[Path] = set()
    for data in _deletion_records(workspace):
        if data.get("kind") != kind:
            continue
        source = workspace.resolve() / safe_relative(data["source"])
        if not source.exists():
            sources.add(source)
    return sources


def _deletion_records(workspace: Path) -> Iterator[dict]:
    root = workspace.resolve() / ".eforge" / "deletions"
    try:
        _safe_path(root)
    except ArtifactError:
        return
    if not root.is_dir():
        return
    for path in root.iterdir():
        if not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
            continue
        try:
            _safe_path(path)
            if path.stat().st_size > 4096:
                continue
            data = json.loads(path.read_bytes())
            if isinstance(data, dict) and data.get("deletion_version") == 1:
                safe_relative(data["source"])
                yield data
        except (OSError, ValueError, KeyError, ArtifactError):
            continue


def retired_scenario_sources(workspace: Path) -> set[Path]:
    """Find permanently deleted scenarios whose local index still needs cleanup."""
    return retired_artifact_sources(workspace, "scenario")


def retired_versions(workspace: Path, *, kind: str, name: str, publisher: str) -> set[str]:
    """Keep retired release labels reserved without retaining authored files or notes."""
    versions: set[str] = set()
    for data in _deletion_records(workspace):
        release = data.get("release")
        if (
            isinstance(release, dict)
            and (release.get("kind"), release.get("name"), release.get("publisher"))
            == (kind, name, publisher)
            and isinstance(release.get("version"), str)
            and re.fullmatch(r"\d+\.\d+\.\d+", release["version"])
        ):
            versions.add(release["version"])
    return versions
