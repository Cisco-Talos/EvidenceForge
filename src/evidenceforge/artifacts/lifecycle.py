"""File-backed drafts, publication and integrity for scenarios and packs."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.naming import storage_name, validate_display_name, validate_name
from evidenceforge.schema import (
    LifecycleMetadata,
    ParentReference,
    identify_document,
    update_top_level,
    upgrade_sources,
)
from evidenceforge.schema.contracts import VERSION_PATTERN
from evidenceforge.utils import load_scenario_source_graph

logger = logging.getLogger(__name__)
RECEIPT = "release.json"
MAX_FILES = 1024
MAX_BYTES = 64 * 1024 * 1024
ArtifactKind = Literal["scenario", "industry", "organization"]


class ArtifactError(EvidenceForgeError):
    """An authored lifecycle operation failed without changing its original input."""


class ReleaseReceipt(BaseModel):
    """Portable authority for a completely captured immutable local release."""

    artifact_format_version: Literal["1.0"] = "1.0"
    kind: ArtifactKind
    name: str = Field(min_length=1)
    lifecycle: LifecycleMetadata
    entrypoint: str
    files: dict[str, str]
    semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_config = ConfigDict(extra="forbid", frozen=True)


def sha256(content: bytes) -> str:
    """Hash exact portable bytes."""
    return hashlib.sha256(content).hexdigest()


def canonical_bytes(data: Any) -> bytes:
    """Encode receipt data without timestamps or machine paths."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def safe_relative(name: str) -> PurePosixPath:
    """Reject platform-independent path escapes and aliases before filesystem access."""
    path = PurePosixPath(name)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or path.as_posix() != name
        or "." in path.parts
    ):
        raise ArtifactError(f"unsafe portable artifact path: {name!r}")
    return path


def _safe_path(path: Path) -> Path:
    path = path.absolute()
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ArtifactError(f"artifact paths cannot contain symbolic links: {path}")
    return path


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Capture a bounded regular-file tree without following links."""
    _safe_path(root)
    if not root.is_dir():
        raise ArtifactError(f"artifact directory was not found: {root}")
    files: dict[str, bytes] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        _safe_path(path)
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ArtifactError(f"artifact member must be an unlinked regular file: {path}")
        name = path.relative_to(root).as_posix()
        safe_relative(name)
        size = path.stat().st_size
        total += size
        if len(files) >= MAX_FILES or total > MAX_BYTES:
            raise ArtifactError("artifact exceeds portable file-count or byte limits")
        content = path.read_bytes()
        if len(content) != size:
            raise ArtifactError(f"input changed while capturing {path}")
        files[name] = content
    return files


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    for name, content in sorted(files.items()):
        destination = root / safe_relative(name)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())


def artifact_root(project_root: Path) -> Path:
    """Return the shared repository, with no dependency on Studio's private state."""
    return _safe_path(project_root / ".eforge" / "artifacts")


def assert_mutable(source: Path) -> None:
    """Keep every supported authoring operation from rewriting an immutable release."""
    root = _receipt_root(source)
    if root is not None:
        verify_release(root)
        raise ArtifactError("this release is immutable; create a separate draft to edit it")
    data = load_scenario_source_graph(source).data
    contract = identify_document(data)
    if contract.lifecycle and contract.lifecycle.status == "published":
        raise ArtifactError(
            "published sources are immutable; import the release and create a draft"
        )


def set_release_notes(source: Path, notes: str, *, expected_digest: str | None = None) -> None:
    """Save a reviewed note in a draft; assistance and publication are separate operations."""
    if len(notes) > 65536:
        raise ArtifactError("release notes exceed 65536 characters")
    _set_draft_metadata(source, "release_notes", notes, expected_digest=expected_digest)


def set_display_name(
    source: Path, display_name: str | None, *, expected_digest: str | None = None
) -> None:
    """Set or clear the optional friendly title without renaming the artifact identity."""
    value = validate_display_name(display_name) if display_name is not None else None
    _set_draft_metadata(source, "display_name", value, expected_digest=expected_digest)


def _set_draft_metadata(
    source: Path, field: str, value: str | None, *, expected_digest: str | None
) -> None:
    assert_mutable(source)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    if contract.lifecycle is None or contract.lifecycle.status != "draft":
        raise ArtifactError(f"{field} requires a Schema 3 draft; create an upgraded draft")
    if expected_digest is not None and inspect_artifact(source)["digest"] != expected_digest:
        raise ArtifactError("draft changed while editing notes; review it again")
    owner = graph.origins.get((field,), source)
    content = owner.read_bytes()
    temporary = owner.with_name(f".{owner.name}.{uuid4().hex}.notes")
    try:
        with temporary.open("xb") as stream:
            stream.write(update_top_level(content, {field: value}))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(owner.stat().st_mode & 0o777)
        if owner.read_bytes() != content:
            raise ArtifactError("draft changed while saving notes; review it again")
        os.replace(temporary, owner)
    finally:
        temporary.unlink(missing_ok=True)


def set_artifact_names(
    source: Path,
    name: str,
    display_name: str | None,
    *,
    project_root: Path,
    expected_digest: str,
) -> Path:
    """Edit draft names or branch an immutable source, preserving ancestry and namespaces."""
    with _publication_lock(project_root):
        current = inspect_artifact(source)
        validate_name(name, "scenario" if current["kind"] == "scenario" else "pack")
        title = validate_display_name(display_name) if display_name is not None else None
        if not expected_digest or current["digest"] != expected_digest:
            raise ArtifactError("source changed after review; inspect it again")
        branch = (current.get("lifecycle") or {}).get("status") != "draft"
        if not branch:
            assert_mutable(source)
            graph = load_scenario_source_graph(source)
            files, entry, base = _capture_sources(
                source, "scenario" if current["kind"] == "scenario" else "pack"
            )
            edited = _edit_envelope(
                files, entry, graph, base, {"name": name, "display_name": title}
            )
            if current["kind"] != "scenario" and name != current["name"]:
                namespace = f"draft-{current['lifecycle']['draft_id']}"
                edited = _remap_namespace(
                    edited, f"{namespace}/{current['name']}", f"{namespace}/{name}"
                )
            staged: dict[Path, Path] = {}
            backups: dict[Path, Path] = {}
            replaced: list[Path] = []
            try:
                for member, content in edited.items():
                    if content == files[member]:
                        continue
                    owner = base / member
                    staged[owner] = owner.with_name(f".{owner.name}.{uuid4().hex}.names")
                    backups[owner] = owner.with_name(f".{owner.name}.{uuid4().hex}.names-backup")
                    for temporary, payload in (
                        (staged[owner], content),
                        (backups[owner], files[member]),
                    ):
                        with temporary.open("xb") as stream:
                            stream.write(payload)
                            stream.flush()
                            os.fsync(stream.fileno())
                        temporary.chmod(owner.stat().st_mode & 0o777)
                if any((base / member).read_bytes() != data for member, data in files.items()):
                    raise ArtifactError("source changed while saving names; inspect it again")
                for owner, temporary in staged.items():
                    os.replace(temporary, owner)
                    replaced.append(owner)
            except OSError:
                for owner in reversed(replaced):
                    os.replace(backups[owner], owner)
                raise
            finally:
                for temporary in (*staged.values(), *backups.values()):
                    temporary.unlink(missing_ok=True)
    if branch:
        result = create_draft(
            source,
            project_root=project_root,
            name=name,
            display_name=title,
            expected_digest=expected_digest,
        )
        if title is None:
            set_display_name(result, None)
        return result
    return source


@contextmanager
def _publication_lock(project_root: Path) -> Iterator[None]:
    """Hold a process-owned lock; termination releases ownership without stale lock recovery."""
    root = artifact_root(project_root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = _safe_path(root / "publication.lock")
    with lock_path.open("a+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                if stream.read(1) == b"":
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ArtifactError(
                "another artifact operation is in progress; retry after it completes"
            ) from exc
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _publish_directory(staging: Path, destination: Path) -> None:
    _safe_path(destination)
    if destination.exists():
        raise ArtifactError(f"destination already exists: {destination}")
    # Sync captured directories before a single exclusive rename. A killed writer leaves
    # only an unreferenced staging directory, never an empty visible release reservation.
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import publish_new_directory

        publish_new_directory(staging, destination)
    else:
        import ctypes
        import sys

        for directory in [
            *sorted((p for p in staging.rglob("*") if p.is_dir()), reverse=True),
            staging,
        ]:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            rename = library.renamex_np
            rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            result = rename(os.fsencode(staging), os.fsencode(destination), 4)  # RENAME_EXCL
        else:
            rename = library.renameat2
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            result = rename(-100, os.fsencode(staging), -100, os.fsencode(destination), 1)
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))
        descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _receipt_root(path: Path) -> Path | None:
    """Find an artifact receipt by its source layout, avoiding unrelated release metadata."""
    path = _safe_path(path)
    for parent in (path if path.is_dir() else path.parent, *path.parents):
        # Python standalone runtimes also have a release.json. Artifact releases always
        # retain their authored source tree; a receipt alone does not identify this family.
        if (parent / RECEIPT).is_file() and (parent / "source").is_dir():
            return parent
    return None


def verify_release(root: Path) -> ReleaseReceipt:
    """Check the complete inventory, receipt seal and every captured file."""
    files = snapshot_tree(root)
    try:
        receipt = ReleaseReceipt.model_validate_json(files.pop(RECEIPT))
    except (KeyError, ValidationError) as exc:
        raise ArtifactError(f"invalid or missing release receipt at {root}") from exc
    payload = receipt.model_dump(mode="json", exclude={"digest"})
    if (
        receipt.lifecycle.status != "published"
        or sha256(canonical_bytes(payload)) != receipt.digest
    ):
        raise ArtifactError("release receipt was modified; recover it into a draft")
    if set(files) != set(receipt.files):
        raise ArtifactError("published file inventory changed; recover it into a draft")
    for name, digest in receipt.files.items():
        safe_relative(name)
        if sha256(files[name]) != digest:
            raise ArtifactError(f"published file was modified: {name}; recover it into a draft")
    safe_relative(receipt.entrypoint)
    if receipt.entrypoint not in files:
        raise ArtifactError("release entrypoint is missing from the integrity receipt")
    return receipt


def frozen_scenario_input(path: Path) -> dict[str, Any] | None:
    """Resolve immutable inputs for the compiler without consulting live configuration."""
    if path.suffix == ".efscenario":
        from .portable import read_archive

        receipt, files = read_archive(path)
        if receipt.kind != "scenario":
            raise ArtifactError("expected a scenario release archive")
        return json.loads(files["frozen.json"])
    root = _receipt_root(path)
    if root is None:
        return None
    receipt = verify_release(root)
    if receipt.kind != "scenario":
        raise ArtifactError("expected a scenario release")
    if path.is_file() and path != root / receipt.entrypoint and path != root / "frozen.json":
        raise ArtifactError("select the published scenario entrypoint")
    return json.loads((root / "frozen.json").read_bytes())


def resolve_reference(value: str | Path, project_root: Path) -> Path:
    """Accept paths or publisher-qualified portable local release references."""
    raw = str(value)
    match = re.fullmatch(
        r"(?:project:)?([a-z0-9][a-z0-9-]*):(scenario|industry|organization):([^:@]+)@(\d+\.\d+\.\d+)",
        raw,
    )
    if match:
        publisher, kind, name, version = match.groups()
        from urllib.parse import unquote

        name = unquote(name)
        root = (
            artifact_root(project_root)
            / "releases"
            / publisher
            / kind
            / storage_name(name)
            / version
        )
        receipt = verify_release(root)
        if (
            receipt.name != name
            or receipt.kind != kind
            or receipt.lifecycle.publisher != publisher
            or receipt.lifecycle.version != version
        ):
            raise ArtifactError("portable reference does not match the captured release identity")
        return root / receipt.entrypoint
    path = _safe_path(Path(value))
    if path.is_dir():
        if (path / RECEIPT).is_file():
            receipt = verify_release(path)
            return path / receipt.entrypoint
        path /= "pack.yaml"
    return path


def inspect_artifact(path: Path) -> dict[str, Any]:
    """Inspect repairable drafts, unclassified legacy files, and verified releases."""
    if path.suffix in {".efscenario", ".efpack"}:
        import zipfile

        if path.suffix == ".efpack":
            with zipfile.ZipFile(path) as archive:
                legacy = RECEIPT not in archive.namelist()
            if legacy:
                from evidenceforge.composition.releases import validate_efpack

                validated = validate_efpack(path)
                root = validated.root
                return {
                    "kind": root["type"],
                    "name": root["name"],
                    "path": str(path),
                    "schema_version": "2.0",
                    "lifecycle": LifecycleMetadata(
                        status="published", publisher=root["publisher"], version=root["version"]
                    ).model_dump(mode="json"),
                    "digest": sha256(path.read_bytes()),
                    "members": list(validated.members),
                    "valid": True,
                    "root": root,
                }
        from .portable import read_archive

        receipt, files = read_archive(path)
        with tempfile.TemporaryDirectory(prefix="eforge-inspect-") as temporary:
            root = Path(temporary).resolve()
            _write_files(
                root,
                {name: content for name, content in files.items() if name.startswith("source/")},
            )
            display_name = load_scenario_source_graph(root / receipt.entrypoint).data.get(
                "display_name"
            )
        return {**receipt.model_dump(mode="json"), "display_name": display_name, "path": str(path)}
    root = _receipt_root(path)
    if root is not None:
        receipt = verify_release(root)
        return {
            **receipt.model_dump(mode="json"),
            "path": str(root / receipt.entrypoint),
            "display_name": load_scenario_source_graph(root / receipt.entrypoint).data.get(
                "display_name"
            ),
        }
    graph = load_scenario_source_graph(path)
    contract = identify_document(graph.data)
    kind = graph.data.get("type", "scenario") if contract.family == "pack" else contract.family
    source_files, _entry, _base = _capture_sources(path, contract.family)
    identity_files = {f"source/{name}": sha256(content) for name, content in source_files.items()}
    container = next((parent for parent in path.parents if (parent / "draft.json").is_file()), None)
    if container:
        for companion in ("configuration", "dependencies"):
            if (container / companion).is_dir():
                identity_files.update(
                    {
                        f"{companion}/{name}": sha256(content)
                        for name, content in snapshot_tree(container / companion).items()
                    }
                )
    return {
        "kind": kind,
        "name": graph.data.get("name"),
        "display_name": graph.data.get("display_name"),
        "path": str(path),
        "schema_version": contract.schema_version,
        "upgrade_available": contract.upgrade_available,
        "lifecycle": contract.lifecycle.model_dump(mode="json", exclude_none=True)
        if contract.lifecycle
        else None,
        "digest": sha256(canonical_bytes(identity_files)),
    }


def _capture_sources(path: Path, family: str) -> tuple[dict[str, bytes], str, Path]:
    if family == "pack":
        return snapshot_tree(path.parent), path.name, path.parent
    graph = load_scenario_source_graph(path)
    captured = {source.path: source.content for source in graph.sources}
    email = graph.data.get("environment", {}).get("email", {})
    corpus = email.get("corpus") if isinstance(email, dict) else None
    if corpus:
        declaring = graph.origins.get(("environment", "email", "corpus"), path)
        asset = _safe_path(declaring.parent / corpus)
        if not asset.is_relative_to(declaring.parent):
            raise ArtifactError("email corpus must remain beneath its declaring directory")
        captured[asset] = asset.read_bytes()
    for companion in path.parent.glob("*.md"):
        if companion.name == "GROUND_TRUTH.md":
            continue
        _safe_path(companion)
        if companion.stat().st_nlink != 1:
            raise ArtifactError(f"scenario companion must be a regular unlinked file: {companion}")
        captured[companion] = companion.read_bytes()
    # Preserve relative includes, even when the authored root sits below its includes.
    base = Path(os.path.commonpath([str(source.parent) for source in captured]))
    files = {source.relative_to(base).as_posix(): content for source, content in captured.items()}
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
        raise ArtifactError("scenario sources exceed portable limits")
    return files, path.relative_to(base).as_posix(), base


def _remap_namespace(files: dict[str, bytes], old: str, new: str) -> dict[str, bytes]:
    """Rewrite qualified catalog references while retaining all other authored bytes."""
    result = dict(files)
    protected = {"description", "display_name", "release_notes", "parents", "provenance"}
    pattern = re.compile(rf"{re.escape(old)}:[a-z0-9][a-z0-9_-]*")

    def collect(node: yaml.Node | None, seen: set[int], edits: list[tuple[int, int]]) -> None:
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, yaml.ScalarNode) and pattern.fullmatch(node.value):
            edits.append((node.start_mark.index, node.end_mark.index))
        elif isinstance(node, yaml.SequenceNode):
            for child in node.value:
                collect(child, seen, edits)
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode) and key.value not in protected:
                    collect(value, seen, edits)

    for name, content in files.items():
        if not name.endswith((".yaml", ".yml")):
            continue
        text = content.decode()
        edits: list[tuple[int, int]] = []
        seen: set[int] = set()

        collect(yaml.compose(text), seen, edits)
        for start, end in sorted(edits, reverse=True):
            text = text[:start] + text[start:end].replace(f"{old}:", f"{new}:") + text[end:]
        result[name] = text.encode()
    return result


def _edit_envelope(
    files: dict[str, bytes],
    entry: str,
    graph: Any,
    base: Path,
    changes: dict[str, Any],
    remove: set[str] | None = None,
) -> dict[str, bytes]:
    """Edit fields in their declaring include, preserving single field ownership."""
    result = dict(files)
    updates: dict[str, dict[str, Any]] = {}
    removals: dict[str, set[str]] = {}
    for key, value in changes.items():
        owner = graph.origins.get((key,), graph.root)
        name = owner.relative_to(base).as_posix()
        updates.setdefault(name, {})[key] = value
    for key in remove or set():
        owner = graph.origins.get((key,), graph.root)
        name = owner.relative_to(base).as_posix()
        removals.setdefault(name, set()).add(key)
    for name in set(updates) | set(removals):
        result[name] = update_top_level(
            result[name], updates.get(name, {}), removals.get(name, set())
        )
    return result


def _configuration_files(
    source: Path, project_root: Path, context: Path | None
) -> dict[str, bytes]:
    from evidenceforge.config.context import select_context

    graph = load_scenario_source_graph(source)
    bound = graph.data.get("configuration_context")
    if context is None and bound:
        declaring = graph.origins.get(("configuration_context",), source)
        context = declaring.parent / bound
        selection = select_context(None, context)
    else:
        selection = select_context(None if context else project_root, context)
    files: dict[str, bytes] = {"configuration/project/context-root.json": b"{}"}
    base = selection.project_root / ".eforge" / "config"
    if base.exists():
        files.update(
            {
                f"configuration/project/.eforge/config/{name}": content
                for name, content in snapshot_tree(base).items()
            }
        )
    layers: list[dict[str, str]] = []
    for index, layer in enumerate(selection.overlays):
        prefix = f"configuration/layers/{index}"
        files[f"{prefix}/overlay.json"] = b"{}"
        files.update(
            {f"{prefix}/{name}": content for name, content in snapshot_tree(layer.path).items()}
        )
        layers.append({"name": layer.name, "path": f"layers/{index}"})
    files["configuration/context.yaml"] = yaml.safe_dump(
        {"context_version": "1.0", "project_root": "project", "overlays": layers}, sort_keys=False
    ).encode()
    return files


def _remap_captured_dependencies(staging: Path, entry: str, kind: str) -> None:
    """Bind copied source references to the portable closure, retaining exact namespaces."""
    source = staging / "source" / entry
    graph = load_scenario_source_graph(source)
    raw = graph.data
    dependency_root = staging / "dependencies"
    if not dependency_root.is_dir():
        return
    targets: dict[tuple[str, str, str], Path] = {}
    for manifest in dependency_root.rglob("pack.yaml"):
        data = load_scenario_source_graph(manifest).data
        targets[(data["publisher"], data["name"], data["version"])] = manifest.parent
    # Copied organization manifests have their own relative dependency origins. Bind
    # every member, not only the top-level consumer, to the same captured closure.
    for manifest in dependency_root.rglob("pack.yaml"):
        member_graph = load_scenario_source_graph(manifest)
        dependencies = json.loads(json.dumps(member_graph.data.get("industry_dependencies", [])))
        if not dependencies:
            continue
        lock = load_scenario_source_graph(manifest.parent / "pack.lock.yaml").data
        owner = member_graph.origins.get(("industry_dependencies",), manifest)
        for dependency in dependencies:
            selected = next(
                item
                for item in lock["dependencies"]
                if item["publisher"] == dependency["publisher"]
                and item["name"] == dependency["name"]
            )
            target = targets[(selected["publisher"], selected["name"], selected["version"])]
            dependency.update({"source": "path", "path": os.path.relpath(target, owner.parent)})
        owner.write_bytes(
            update_top_level(owner.read_bytes(), {"industry_dependencies": dependencies})
        )
    changes: dict[str, Any] = {}
    declaring_parent = graph.origins.get(
        ("composition" if kind == "scenario" else "industry_dependencies",), source
    ).parent
    if kind == "scenario":
        composition = raw.get("composition")
        if not isinstance(composition, dict):
            return
        composition = json.loads(json.dumps(composition))
        references = [
            *composition.get("industries", []),
            *([composition["organization"]] if composition.get("organization") else []),
        ]
        for reference in references:
            target = targets.get(
                (reference.get("publisher"), reference["name"], reference.get("version"))
            )
            if target is None:
                raise ArtifactError(
                    "release is missing an authored dependency from its portable closure"
                )
            reference.update({"source": "path", "path": os.path.relpath(target, declaring_parent)})
        changes["composition"] = composition
    else:
        dependencies = json.loads(json.dumps(raw.get("industry_dependencies", [])))
        lock = load_scenario_source_graph(source.parent / "pack.lock.yaml").data
        for dependency in dependencies:
            selected = next(
                (
                    item
                    for item in lock.get("dependencies", [])
                    if item["publisher"] == dependency["publisher"]
                    and item["name"] == dependency["name"]
                ),
                None,
            )
            if selected is None:
                raise ArtifactError("pack closure is missing an exact locked dependency")
            target = targets[(selected["publisher"], selected["name"], selected["version"])]
            dependency.update({"source": "path", "path": os.path.relpath(target, declaring_parent)})
        if dependencies:
            changes["industry_dependencies"] = dependencies
    if changes:
        files, root_entry, base = _capture_sources(
            source, "scenario" if kind == "scenario" else "pack"
        )
        edited = _edit_envelope(files, root_entry, graph, base, changes)
        for name in edited:
            if edited[name] != files[name]:
                (base / name).write_bytes(edited[name])


def _bind_configuration(staging: Path, entry: str) -> None:
    source = staging / "source" / entry
    graph = load_scenario_source_graph(source)
    owner = graph.origins.get(("configuration_context",), source)
    owner.write_bytes(
        update_top_level(
            owner.read_bytes(),
            {
                "configuration_context": os.path.relpath(
                    staging / "configuration/context.yaml", owner.parent
                )
            },
        )
    )


def _parent(path: Path, *, recover: bool = False) -> ParentReference | None:
    root = _receipt_root(path)
    if root is not None:
        try:
            receipt = verify_release(root)
        except ArtifactError:
            if not recover:
                raise
            receipt = ReleaseReceipt.model_validate_json((root / RECEIPT).read_bytes())
        return ParentReference(
            kind=receipt.kind,
            name=receipt.name,
            publisher=receipt.lifecycle.publisher,
            version=receipt.lifecycle.version,
            digest=receipt.digest,
        )
    info = inspect_artifact(path)
    metadata = info["lifecycle"]
    if metadata is None:
        return ParentReference(
            kind=info["kind"],
            name=info["name"],
            digest=info["digest"],
            source_schema_version=info["schema_version"],
        )  # No invented historical release label.
    return ParentReference(
        kind=info["kind"],
        name=info["name"],
        publisher=metadata.get("publisher"),
        version=metadata.get("version"),
        draft_id=metadata.get("draft_id"),
        digest=info["digest"],
    )


def create_draft(
    source: Path,
    *,
    project_root: Path,
    destination: Path | None = None,
    name: str | None = None,
    display_name: str | None = None,
    publisher: str | None = None,
    upgrade: bool = False,
    recover: bool = False,
    additional_parents: list[ParentReference] | None = None,
    expected_digest: str | None = None,
) -> Path:
    """Fork, adopt or upgrade into an independent draft; never modify the original."""
    if source.suffix in {".efscenario", ".efpack"}:
        from .portable import import_release

        source = import_release(source, project_root=project_root)
    source = resolve_reference(source, project_root) if not recover else _safe_path(source)
    if expected_digest is not None and inspect_artifact(source)["digest"] != expected_digest:
        raise ArtifactError("source changed after review; inspect it again")
    draft_container = next(
        (parent for parent in source.parents if (parent / "draft.json").is_file()), None
    )
    root = _receipt_root(source)
    receipt = None
    if root is not None:
        if not recover:
            receipt = verify_release(root)
        else:
            receipt = ReleaseReceipt.model_validate_json((root / RECEIPT).read_bytes())
        source = root / safe_relative(receipt.entrypoint)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    if contract.family not in {"scenario", "pack"}:
        raise ArtifactError(f"cannot draft a {contract.family} document")
    if upgrade and not contract.upgrade_available:
        raise ArtifactError("this document has no supported upgrade to a newer schema")
    if contract.lifecycle and contract.lifecycle.status == "published" and root is None:
        raise ArtifactError(
            "published source has no integrity receipt; import its portable release"
        )
    files, entry, base = _capture_sources(source, contract.family)
    if contract.upgrade_available:
        files = upgrade_sources(
            files,
            entry,
            contract.family,
            {item.path.relative_to(base).as_posix() for item in graph.sources},
        )
    parent = _parent(source, recover=recover)
    parents = ([parent] if parent else []) + (additional_parents or [])
    draft_id = str(uuid4())
    logical_name = graph.data["name"] if name is None else name
    kind = graph.data["type"] if contract.family == "pack" else "scenario"
    if name is not None:
        validate_name(logical_name, "scenario" if kind == "scenario" else "pack")
    storage_key = storage_name(logical_name)
    draft_publisher, publisher_title = _draft_publisher(
        project_root, publisher, graph.data.get("publisher")
    )
    metadata = LifecycleMetadata(
        status="draft",
        draft_id=draft_id,
        publisher=draft_publisher,
        parents=parents,
    )
    changes = metadata.model_dump(mode="json", exclude_none=True)
    if kind != "scenario" and publisher_title is not None:
        changes["publisher_display_name"] = publisher_title
    if display_name is not None:
        changes["display_name"] = validate_display_name(display_name)
    changes.update(
        {
            "name": logical_name,
            "schema_version" if kind == "scenario" else "pack_schema_version": "3.0",
        }
    )
    files = _edit_envelope(
        files,
        entry,
        graph,
        base,
        changes,
        remove={"scenario_version" if kind == "scenario" else "version", "publisher"}
        - set(changes),
    )
    if kind != "scenario":
        old_namespace = f"{graph.data.get('publisher')}/{graph.data['name']}"
        if contract.lifecycle and contract.lifecycle.draft_id:
            old_namespace = f"draft-{contract.lifecycle.draft_id}/{graph.data['name']}"
        files = _remap_namespace(files, old_namespace, f"draft-{draft_id}/{logical_name}")
    target = destination or artifact_root(project_root) / "drafts" / kind / storage_key / draft_id
    _safe_path(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=".draft-", dir=target.parent))
    try:
        _write_files(staging / "source", files)
        # Published source closure and effective configuration are preserved for later editing.
        captured_container = root if receipt is not None else draft_container
        if captured_container is not None:
            for companion in ("dependencies", "configuration"):
                if (captured_container / companion).is_dir():
                    snapshot_tree(captured_container / companion)
                    shutil.copytree(captured_container / companion, staging / companion)
            if (staging / "configuration/context.yaml").is_file():
                _bind_configuration(staging, entry)
            _remap_captured_dependencies(staging, entry, kind)
        _write_files(
            staging,
            {
                "draft.json": canonical_bytes(
                    {"draft_id": draft_id, "entrypoint": f"source/{entry}"}
                )
            },
        )
        with _publication_lock(project_root):
            if (
                expected_digest is not None
                and inspect_artifact(source)["digest"] != expected_digest
            ):
                raise ArtifactError("source changed while creating a draft; inspect it again")
            _publish_directory(staging, target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target / "source" / entry


def _draft_publisher(
    project_root: Path, explicit: str | None, inherited: str | None = None
) -> tuple[str | None, str | None]:
    """Preserve selected namespaces; use configured identity for an unassigned draft."""
    from evidenceforge.composition.publisher import effective_publisher

    if explicit is not None or inherited is not None:
        return explicit if explicit is not None else inherited, None
    configured, _scope = effective_publisher(project_root, required=False)
    if configured is None:
        return None, None
    return configured.publisher, configured.publisher_display_name


def create_new_draft(
    kind: ArtifactKind,
    name: str,
    *,
    description: str,
    project_root: Path,
    publisher: str | None = None,
    publisher_display_name: str | None = None,
    display_name: str | None = None,
) -> Path:
    """Create a draft scaffold through files, with no release label allocation."""
    if not name:
        raise ArtifactError("artifact name cannot be empty")
    if kind != "scenario":
        validate_name(name, "pack")
    draft_id = str(uuid4())
    publisher, configured_title = _draft_publisher(project_root, publisher)
    if publisher_display_name is None:
        publisher_display_name = configured_title
    metadata = LifecycleMetadata(status="draft", draft_id=draft_id, publisher=publisher)
    data: dict[str, Any] = {
        "name": name,
        "description": description,
        **metadata.model_dump(mode="json", exclude_none=True),
    }
    if display_name is not None:
        data["display_name"] = validate_display_name(display_name)
    files: dict[str, bytes] = {}
    if kind == "scenario":
        data.update(
            {
                "schema_version": "3.0",
                "composition": {},
                "environment": {"description": description, "users": [], "systems": []},
                "time_window": {"start": "2026-01-01T00:00:00Z", "duration": "1h"},
                "baseline_activity": {"intensity": "medium", "variation": "low"},
                "output": {
                    "logs": [{"format": "windows"}, {"format": "zeek"}],
                    "destination": "./output",
                },
            }
        )
        entry = "scenario.yaml"
    else:
        from evidenceforge.composition.packs import CATALOG_FILES

        data.update(
            {
                "pack_schema_version": "3.0",
                "type": kind,
                "requires_evidenceforge": ">=2.0.0,<3.0.0",
                "industry_dependencies": [],
            }
        )
        if publisher_display_name is not None:
            data["publisher_display_name"] = publisher_display_name
        entry = "pack.yaml"
        files["pack.lock.yaml"] = b"lock_schema_version: '1.0'\ndependencies: []\n"
        files.update(
            {
                relative: yaml.safe_dump({catalog: {}}).encode()
                for catalog, relative, _model in CATALOG_FILES
            }
        )
        if kind == "organization":
            files["model/environment.yaml"] = b"environment: {}\n"
            files["model/baseline_activity.yaml"] = b"baseline_activity: {}\n"
    files[entry] = yaml.safe_dump(data, sort_keys=False).encode()
    target = artifact_root(project_root) / "drafts" / kind / storage_name(name) / draft_id
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=".draft-", dir=target.parent))
    try:
        _write_files(staging / "source", files)
        _write_files(
            staging,
            {
                "draft.json": canonical_bytes(
                    {"draft_id": draft_id, "entrypoint": f"source/{entry}"}
                )
            },
        )
        with _publication_lock(project_root):
            _publish_directory(staging, target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target / "source" / entry


def list_versions(
    project_root: Path, *, kind: ArtifactKind, name: str, publisher: str
) -> list[dict[str, Any]]:
    """Inspect every exact published version of one identity, oldest first."""
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", publisher) is None or not name:
        raise ArtifactError("invalid release identity")
    root = artifact_root(project_root) / "releases" / publisher / kind / storage_name(name)
    if not root.exists():
        return []
    versions: list[dict[str, Any]] = []
    for path in sorted(
        (path for path in root.iterdir() if re.fullmatch(VERSION_PATTERN, path.name)),
        key=lambda path: tuple(int(part) for part in path.name.split(".")),
    ):
        if not path.is_dir():
            continue
        receipt = verify_release(path)
        if (receipt.name, receipt.kind, receipt.lifecycle.publisher, receipt.lifecycle.version) != (
            name,
            kind,
            publisher,
            path.name,
        ):
            raise ArtifactError("stored release does not match its repository identity")
        versions.append({**receipt.model_dump(mode="json"), "path": str(path / receipt.entrypoint)})
    return versions


def list_drafts(project_root: Path, *, kind: ArtifactKind | None = None) -> list[dict[str, Any]]:
    """Discover portable drafts, including sources that still need semantic repair."""
    drafts: list[dict[str, Any]] = []
    root = artifact_root(project_root) / "drafts"
    for marker in sorted(root.glob(f"{kind or '*'}/*/*/draft.json")):
        entry = json.loads(marker.read_bytes())["entrypoint"]
        source = marker.parent / safe_relative(entry)
        try:
            info = inspect_artifact(source)
        except (EvidenceForgeError, OSError, ValueError) as exc:
            info = {"error": str(exc)}
        drafts.append({**info, "path": str(source)})
    return drafts


def suggest_version(
    project_root: Path,
    *,
    kind: ArtifactKind,
    name: str,
    publisher: str,
    bump: Literal["patch", "minor", "major"] = "patch",
) -> str:
    """Choose the next unused release label without reserving it for a draft."""
    versions = _used_versions(project_root, kind=kind, name=name, publisher=publisher)
    if not versions:
        return "1.0.0"
    major, minor, patch = map(
        int, max(versions, key=lambda value: tuple(map(int, value.split(".")))).split(".")
    )
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _used_versions(
    project_root: Path, *, kind: ArtifactKind, name: str, publisher: str
) -> set[str]:
    """Reserve existing pack labels across legacy and immutable repositories as well."""
    versions = {
        item["lifecycle"]["version"]
        for item in list_versions(project_root, kind=kind, name=name, publisher=publisher)
    }
    from evidenceforge.artifacts.removal import retired_versions

    versions.update(retired_versions(project_root, kind=kind, name=name, publisher=publisher))
    if kind == "scenario":
        return versions
    from evidenceforge.composition.packs import PackRepository

    repository = PackRepository(project_root)
    for root in (
        repository.package_root,
        repository.project_pack_root,
        project_root / ".eforge/releases",
        Path.home() / ".eforge/releases",
    ):
        identity = root / publisher / kind / name
        if identity.is_dir():
            versions.update(
                path.name
                for path in identity.iterdir()
                if path.is_dir() and re.fullmatch(VERSION_PATTERN, path.name)
            )
    return versions


def _validate_scenario(
    compiled: Any, source: Path, oob_hosts: tuple[str, ...]
) -> list[dict[str, str | None]]:
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.validation import ScenarioValidator

    with effective_config_scope(compiled.effective_config):
        issues = ScenarioValidator(
            compiled.scenario, scenario_root=source.parent, oob_hosts=oob_hosts
        ).validate()
    findings = [
        {
            "severity": issue.severity,
            "field_path": issue.field_path,
            "message": issue.message,
            "suggestion": issue.suggestion,
        }
        for issue in issues
    ]
    errors = [issue["message"] for issue in findings if issue["severity"] == "error"]
    if errors:
        raise ArtifactError(
            "canonical validation failed: " + "; ".join(str(error) for error in errors)
        )
    return findings


def validation_findings(
    source: Path, *, project_root: Path, context: Path | None = None
) -> list[dict[str, Any]]:
    """Report repairable draft findings without making upgrade a publication gate."""
    from evidenceforge.composition.compiler import compile_scenario
    from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.validation import ScenarioValidator

    try:
        graph = load_scenario_source_graph(source)
        contract = identify_document(graph.data)
        if contract.family == "pack":
            reference, kind = parse_pack_cli_reference(str(source))
            repository = PackRepository(project_root)
            repository.validate_semantics(repository.resolve(reference, expected_type=kind))
            return []
        compiled = compile_scenario(source, project_root=project_root, context=context)
        with effective_config_scope(compiled.effective_config):
            return [
                {
                    "severity": issue.severity,
                    "field_path": issue.field_path,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                }
                for issue in ScenarioValidator(
                    compiled.scenario, scenario_root=source.parent
                ).validate()
            ]
    except (EvidenceForgeError, OSError, ValueError) as exc:
        return [{"severity": "error", "message": str(exc)}]


def publish(
    source: Path,
    *,
    project_root: Path,
    version: str | None = None,
    bump: Literal["patch", "minor", "major"] = "patch",
    context: Path | None = None,
    accept_warnings: bool = False,
    oob_hosts: tuple[str, ...] = (),
) -> Path:
    """Validate, capture, recheck and atomically finalize a local release."""
    from evidenceforge.composition.artifacts import build_resolved_document
    from evidenceforge.composition.compiler import compile_scenario
    from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
    from evidenceforge.composition.publisher import effective_publisher

    source = resolve_reference(source, project_root)
    graph = load_scenario_source_graph(source)
    contract = identify_document(graph.data)
    if contract.lifecycle is None or contract.lifecycle.status != "draft":
        raise ArtifactError(
            "publication requires a Schema 3 draft; create a draft or upgrade first"
        )
    configured, _scope = effective_publisher(project_root, required=True)
    assert configured is not None
    publisher = contract.lifecycle.publisher or configured.publisher
    kind = graph.data.get("type", "scenario") if contract.family == "pack" else "scenario"
    if kind not in ("scenario", "industry", "organization"):
        raise ArtifactError("unsupported artifact family")
    label = version or suggest_version(
        project_root, kind=kind, name=graph.data["name"], publisher=publisher, bump=bump
    )
    if re.fullmatch(VERSION_PATTERN, label) is None:
        raise ArtifactError("release version must be exact X.Y.Z")
    draft_parent = _parent(source)
    assert draft_parent is not None
    metadata = contract.lifecycle.model_copy(
        update={
            "status": "published",
            "draft_id": None,
            "publisher": publisher,
            "version": label,
            "parents": [*contract.lifecycle.parents, draft_parent],
        }
    )
    from evidenceforge.config.context import select_context

    bound = graph.data.get("configuration_context")
    if context is None and bound:
        context = graph.origins.get(("configuration_context",), source).parent / bound
    configuration_root = select_context(None if context else project_root, context).project_root
    files, entry, base = _capture_sources(source, contract.family)
    captured = dict(files)
    changes = metadata.model_dump(mode="json", exclude_none=True, exclude={"version"})
    changes["scenario_version" if kind == "scenario" else "version"] = label
    if kind != "scenario":
        changes["publisher_display_name"] = (
            graph.data.get("publisher_display_name") or configured.publisher_display_name
        )
    files = _edit_envelope(files, entry, graph, base, changes, remove={"draft_id"})
    if kind != "scenario":
        files = _remap_namespace(
            files,
            f"draft-{contract.lifecycle.draft_id}/{graph.data['name']}",
            f"{publisher}/{graph.data['name']}",
        )
    with _publication_lock(project_root):
        if label in _used_versions(
            project_root, kind=kind, name=graph.data["name"], publisher=publisher
        ):
            raise ArtifactError(
                "release identity/version is already published or reserved by an existing pack"
            )
        destination = (
            artifact_root(project_root)
            / "releases"
            / publisher
            / kind
            / storage_name(graph.data["name"])
            / label
        )
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists():
            raise ArtifactError(f"release identity/version is already published: {destination}")
        staging = Path(tempfile.mkdtemp(prefix=".publish-", dir=destination.parent))
        try:
            _write_files(staging / "source", files)
            if kind == "scenario":
                compiled = compile_scenario(
                    source, project_root=configuration_root, context=context
                )
                if any(pack.source == "draft" for pack in compiled.selected_packs):
                    raise ArtifactError(
                        "scenario publication requires published dependencies; promote draft references first"
                    )
                findings = _validate_scenario(compiled, source, oob_hosts)
                if (
                    any(issue["severity"] == "warning" for issue in findings)
                    and not accept_warnings
                ):
                    raise ArtifactError(
                        "review publication warnings and retry with --accept-warnings: "
                        + "; ".join(
                            str(issue["message"])
                            for issue in findings
                            if issue["severity"] == "warning"
                        )
                    )
                # Retain full dependency source/companions alongside the self-contained runtime.
                captured_dependencies = _capture_dependencies(
                    compiled, graph, staging, configuration_root
                )
                compiled = compiled.model_copy(
                    update={
                        "provenance": {
                            **compiled.provenance,
                            "artifact": {
                                "kind": kind,
                                "name": graph.data["name"],
                                **metadata.model_dump(mode="json", exclude_none=True),
                            },
                        }
                    }
                )
                frozen = build_resolved_document(compiled)
                _write_files(
                    staging,
                    {
                        "frozen.json": canonical_bytes(frozen.model_dump(mode="json")),
                        "validation.json": canonical_bytes(findings),
                    },
                )
                from evidenceforge.composition.identity import semantic_resolved_sha256

                semantic_digest = semantic_resolved_sha256(compiled)
                second = compile_scenario(source, project_root=configuration_root, context=context)
                if second.digests != compiled.digests:
                    raise ArtifactError(
                        "scenario, dependencies or configuration changed during publication; retry"
                    )
            else:
                reference, pack_type = parse_pack_cli_reference(str(source))
                repository = PackRepository(configuration_root)
                pack = repository.resolve(reference, expected_type=pack_type)
                dependencies = repository.validate_semantics(pack)
                captured_dependencies = dependencies
                if any(dependency.source == "draft" for dependency in dependencies):
                    raise ArtifactError("pack publication requires published dependencies")
                for dependency in dependencies:
                    _require_published_dependency(dependency, repository)
                    prefix = f"dependencies/{dependency.manifest.publisher}/{dependency.manifest.type}/{dependency.manifest.name}/{dependency.manifest.version}"
                    _write_files(
                        staging,
                        {
                            f"{prefix}/{name}": content
                            for name, content in (
                                *dependency.semantic_file_bytes,
                                *dependency.companion_file_bytes,
                            )
                        },
                    )
                _remap_captured_dependencies(staging, entry, kind)
                published_reference, _ = parse_pack_cli_reference(str(staging / "source"))
                published_pack = repository.resolve(published_reference, expected_type=pack_type)
                repository.validate_semantics(published_pack)
                semantic_digest = sha256(
                    canonical_bytes(
                        {
                            "catalogs": published_pack.catalogs,
                            "environment": published_pack.environment,
                            "baseline_activity": published_pack.baseline_activity,
                        }
                    )
                )
                from evidenceforge.composition.compiler import build_management_effective_config

                _write_files(
                    staging,
                    {
                        "frozen-config.json": canonical_bytes(
                            build_management_effective_config(
                                configuration_root, context=context
                            ).model_dump(mode="json")
                        )
                    },
                )
                for dependency in dependencies:
                    _recheck_dependency(dependency)
            configuration = _configuration_files(source, project_root, context)
            _write_files(staging, configuration)
            if kind == "scenario":
                _remap_captured_dependencies(staging, entry, kind)
            _bind_configuration(staging, entry)
            current, _current_entry, _ = _capture_sources(source, contract.family)
            if current != captured or inspect_artifact(source)["digest"] != draft_parent.digest:
                raise ArtifactError("authored files changed during publication; retry")
            if _configuration_files(source, project_root, context) != configuration:
                raise ArtifactError("configuration changed during publication; retry")
            for dependency in captured_dependencies:
                _recheck_dependency(dependency)
            from .properties import validation_record

            _write_files(
                staging,
                {
                    "validated-with.json": canonical_bytes(
                        validation_record(
                            semantic_digest,
                            sum(issue["severity"] == "warning" for issue in findings)
                            if kind == "scenario"
                            else 0,
                        ).model_dump(mode="json")
                    )
                },
            )
            payload = {
                "artifact_format_version": "1.0",
                "kind": kind,
                "name": graph.data["name"],
                "lifecycle": metadata.model_dump(mode="json"),
                "entrypoint": f"source/{entry}",
                "files": {
                    name: sha256(content) for name, content in snapshot_tree(staging).items()
                },
                "semantic_digest": semantic_digest,
            }
            receipt = ReleaseReceipt.model_validate(
                {**payload, "digest": sha256(canonical_bytes(payload))}
            )
            _write_files(staging, {RECEIPT: canonical_bytes(receipt.model_dump(mode="json"))})
            verify_release(staging)
            _publish_directory(staging, destination)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return destination / receipt.entrypoint


def _capture_dependencies(
    compiled: Any, graph: Any, staging: Path, project_root: Path
) -> list[Any]:
    from evidenceforge.composition.compiler import _resolve_composition
    from evidenceforge.composition.models import CompositionSpec

    packs, _ = _resolve_composition(
        CompositionSpec.model_validate(graph.data.get("composition") or {}), graph, project_root
    )
    for pack in packs:
        from evidenceforge.composition.packs import PackRepository

        _require_published_dependency(pack, PackRepository(project_root))
        selected = pack.selected()
        if not any(
            item.digest == selected.digest and item.name == selected.name
            for item in compiled.selected_packs
        ):
            raise ArtifactError("dependency changed while capturing publication inputs")
        prefix = (
            f"dependencies/{selected.publisher}/{selected.type}/{selected.name}/{selected.version}"
        )
        _write_files(
            staging,
            {
                f"{prefix}/{name}": content
                for name, content in (*pack.semantic_file_bytes, *pack.companion_file_bytes)
            },
        )
        _recheck_dependency(pack)
    return list(packs)


def _require_published_dependency(pack: Any, repository: Any) -> None:
    if pack.source == "package" or _receipt_root(pack.root) is not None:
        return
    # Existing immutable Schema 2 imported/hydrated releases remain supported.
    identity = (
        pack.manifest.publisher,
        pack.manifest.type,
        pack.manifest.name,
        pack.manifest.version,
    )
    for library in (repository.project_root / ".eforge/releases", Path.home() / ".eforge/releases"):
        manifest = library.joinpath(*identity, "pack.yaml")
        if manifest.is_file():
            from evidenceforge.composition.packs import parse_pack_cli_reference

            reference, kind = parse_pack_cli_reference(str(manifest))
            immutable = repository.resolve(reference, expected_type=kind)
            if immutable.digest == pack.digest:
                return
    raise ArtifactError(
        "publication requires published dependencies; adopt and publish this workspace pack first"
    )


def _recheck_dependency(pack: Any) -> None:
    for name, content in (*pack.semantic_file_bytes, *pack.companion_file_bytes):
        if (pack.root / safe_relative(name)).read_bytes() != content:
            raise ArtifactError("dependency changed during publication; retry")
