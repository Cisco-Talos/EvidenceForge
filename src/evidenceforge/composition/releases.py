# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Safe build, validation, and import support for portable ``.efpack`` releases."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml

from evidenceforge.models.exceptions import PackError

from .models import PackReference
from .packs import LoadedPack, PackRepository

EFPACK_FORMAT_VERSION = "1.0"
EFPACK_MANIFEST = "efpack.yaml"
EFPACK_MAX_FILES = 1024
EFPACK_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ValidatedEFPack:
    """Validated immutable archive payload ready for inspection or import."""

    root: dict[str, str]
    members: tuple[dict[str, str], ...]
    files: dict[str, bytes]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _member(pack: LoadedPack) -> dict[str, str]:
    return {
        "publisher": pack.manifest.publisher,
        "type": pack.manifest.type,
        "name": pack.manifest.name,
        "version": pack.manifest.version,
        "digest": pack.digest,
    }


def _prefix(member: dict[str, str]) -> str:
    return "packs/{publisher}/{type}/{name}/{version}".format(**member)


def build_efpack(repository: PackRepository, root: LoadedPack, destination: Path) -> dict[str, Any]:
    """Build one deterministic root-plus-closure archive without overwriting its destination."""

    dependencies = repository.validate_semantics(root)
    members = [*dependencies, root]
    payloads: dict[str, bytes] = {}
    manifest_members: list[dict[str, str]] = []
    for pack in sorted(members, key=lambda value: (_member(value)["type"], _member(value)["name"])):
        member = _member(pack)
        manifest_members.append(member)
        for relative, content in (*pack.semantic_file_bytes, *pack.companion_file_bytes):
            payloads[f"{_prefix(member)}/{relative}"] = content
    files = {path: _sha256(content) for path, content in sorted(payloads.items())}
    document = {
        "efpack_format_version": EFPACK_FORMAT_VERSION,
        "root": _member(root),
        "members": manifest_members,
        "files": files,
    }
    manifest = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    destination = destination.resolve()
    if destination.exists():
        raise PackError(f"refusing to overwrite release artifact: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, content in [(EFPACK_MANIFEST, manifest), *sorted(payloads.items())]:
                info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, content)
    except (OSError, zipfile.BadZipFile) as exc:
        destination.unlink(missing_ok=True)
        raise PackError(f"unable to build .efpack: {exc}") from exc
    return {"path": str(destination), "root": document["root"], "members": manifest_members}


def validate_efpack(path: Path) -> ValidatedEFPack:
    """Read and validate every archive member before an import can write state."""

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > EFPACK_MAX_FILES:
                raise PackError(f".efpack has too many entries (limit {EFPACK_MAX_FILES})")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise PackError(".efpack contains duplicate archive paths")
            if sum(info.file_size for info in infos) > EFPACK_MAX_BYTES:
                raise PackError(f".efpack exceeds extracted byte limit {EFPACK_MAX_BYTES}")
            for info in infos:
                pure = PurePosixPath(info.filename)
                if not pure.parts or pure.is_absolute() or ".." in pure.parts or info.is_dir():
                    raise PackError(f".efpack contains unsafe archive entry: {info.filename!r}")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise PackError(f".efpack cannot contain symbolic links: {info.filename!r}")
            if EFPACK_MANIFEST not in names:
                raise PackError(f".efpack is missing {EFPACK_MANIFEST}")
            try:
                document = yaml.safe_load(archive.read(EFPACK_MANIFEST))
            except (yaml.YAMLError, UnicodeError) as exc:
                raise PackError(f".efpack manifest is not valid YAML: {exc}") from exc
            if (
                not isinstance(document, dict)
                or document.get("efpack_format_version") != EFPACK_FORMAT_VERSION
            ):
                raise PackError("unsupported or invalid .efpack format manifest")
            raw_members = document.get("members")
            raw_files = document.get("files")
            root = document.get("root")
            if (
                not isinstance(root, dict)
                or not isinstance(raw_members, list)
                or not isinstance(raw_files, dict)
            ):
                raise PackError(".efpack manifest must define root, members, and files")
            members: list[dict[str, str]] = []
            for member in raw_members:
                if not isinstance(member, dict) or set(member) != {
                    "publisher",
                    "type",
                    "name",
                    "version",
                    "digest",
                }:
                    raise PackError(".efpack member has invalid release identity")
                members.append({key: str(value) for key, value in member.items()})
            if root not in members:
                raise PackError(".efpack root is not one of its members")
            expected = {str(key): str(value) for key, value in raw_files.items()}
            actual_names = set(names) - {EFPACK_MANIFEST}
            if actual_names != set(expected):
                raise PackError(".efpack file manifest does not exactly describe archive contents")
            files = {name: archive.read(name) for name in sorted(actual_names)}
    except zipfile.BadZipFile as exc:
        raise PackError(f"invalid .efpack ZIP archive: {exc}") from exc
    for name, content in files.items():
        if _sha256(content) != expected[name]:
            raise PackError(f".efpack hash mismatch for {name}")
    for member in members:
        prefix = f"{_prefix(member)}/"
        manifest_name = f"{prefix}pack.yaml"
        if manifest_name not in files or f"{prefix}pack.lock.yaml" not in files:
            raise PackError(f".efpack member is missing manifest or lock: {_prefix(member)}")
    return ValidatedEFPack(
        root={key: str(value) for key, value in root.items()}, members=tuple(members), files=files
    )


def import_efpack(
    path: Path, *, scope: Literal["project", "user"], project_root: Path
) -> dict[str, Any]:
    """Validate then atomically materialize a release archive into an immutable library."""

    validated = validate_efpack(path)
    library = (
        (project_root / ".eforge" / "releases")
        if scope == "project"
        else Path.home() / ".eforge" / "releases"
    )
    library.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".efpack-", dir=library.parent))
    try:
        for name, content in validated.files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        repository = PackRepository(project_root)
        loaded_packs: list[LoadedPack] = []
        loaded_by_identity: dict[tuple[str, str, str, str], LoadedPack] = {}
        for member in validated.members:
            source = (staging / _prefix(member)).resolve()
            loaded = repository._load(
                source,
                source="path",
                reference=PackReference(
                    source="path",
                    path=str(source),
                    publisher=member["publisher"],
                    name=member["name"],
                    version=member["version"],
                ),
                expected_type=member["type"],  # type: ignore[arg-type]
            )
            if loaded.digest != member["digest"]:
                raise PackError(f".efpack canonical digest mismatch for {_prefix(member)}")
            loaded_packs.append(loaded)
            loaded_by_identity[
                (member["publisher"], member["type"], member["name"], member["version"])
            ] = loaded
        closure = {
            (
                pack.manifest.publisher,
                pack.manifest.type,
                pack.manifest.name,
                pack.manifest.version,
            ): pack
            for pack in loaded_packs
        }
        for pack in loaded_packs:
            for dependency in pack.lock.dependencies:
                key = (dependency.publisher, dependency.type, dependency.name, dependency.version)
                resolved = closure.get(key)
                if resolved is None or resolved.digest != dependency.digest:
                    raise PackError(
                        f".efpack lock closure is incomplete or mismatched for {dependency.publisher}/"
                        f"{dependency.name}@{dependency.version}"
                    )
        for member in validated.members:
            source = staging / _prefix(member)
            destination = (
                library / member["publisher"] / member["type"] / member["name"] / member["version"]
            )
            identity = (member["publisher"], member["type"], member["name"], member["version"])
            if destination.exists():
                existing = repository._load(
                    destination,
                    source="path",
                    reference=PackReference(
                        source="path",
                        path=str(destination),
                        publisher=member["publisher"],
                        name=member["name"],
                        version=member["version"],
                    ),
                    expected_type=member["type"],  # type: ignore[arg-type]
                )
                if existing.digest != loaded_by_identity[identity].digest:
                    raise PackError(
                        "library already contains a different release with the same publisher, type, "
                        f"name, and version: {destination}"
                    )
                continue
        destinations = [
            (
                staging / _prefix(member),
                library / member["publisher"] / member["type"] / member["name"] / member["version"],
            )
            for member in validated.members
            if not (
                library / member["publisher"] / member["type"] / member["name"] / member["version"]
            ).exists()
        ]
        published: list[Path] = []
        try:
            for source, destination in destinations:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                published.append(destination)
        except OSError as exc:
            for destination in reversed(published):
                shutil.rmtree(destination, ignore_errors=True)
            raise PackError(f"unable to publish .efpack release closure: {exc}") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {"scope": scope, "root": validated.root, "members": list(validated.members)}


def hydrate_release(reference: str, project_root: Path) -> dict[str, str]:
    """Copy one explicitly selected immutable user release into a project pack repository."""

    try:
        publisher, pack_type, versioned = reference.split(":", 2)
        name, version = versioned.split("@", 1)
    except ValueError as exc:
        raise PackError("release must be publisher:type:name@version") from exc
    source = Path.home() / ".eforge" / "releases" / publisher / pack_type / name / version
    destination = project_root / ".eforge" / "packs" / pack_type / name / version
    if not (source / "pack.yaml").is_file():
        raise PackError(f"user-library release was not found: {reference}")
    if destination.exists():
        if (destination / "pack.yaml").read_bytes() != (source / "pack.yaml").read_bytes():
            raise PackError(f"project contains a conflicting pack release: {destination}")
        return {"reference": reference, "destination": str(destination), "hydrated": "false"}
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    return {"reference": reference, "destination": str(destination), "hydrated": "true"}
