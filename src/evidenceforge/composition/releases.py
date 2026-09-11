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
from .packs import LoadedPack, PackRepository, version_satisfies_constraint

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
    for pack in sorted(
        members,
        key=lambda value: (
            value.manifest.publisher,
            value.manifest.type,
            value.manifest.name,
            value.manifest.version,
        ),
    ):
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
            member_identities = {
                (member["publisher"], member["type"], member["name"], member["version"])
                for member in members
            }
            if len(member_identities) != len(members):
                raise PackError(".efpack contains duplicate release identities")
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
    validated = ValidatedEFPack(
        root={key: str(value) for key, value in root.items()}, members=tuple(members), files=files
    )
    _validate_archive_pack_graph(validated)
    return validated


def _validate_archive_pack_graph(validated: ValidatedEFPack) -> None:
    """Validate every contained pack and its exact locked closure before consent."""

    staging = Path(tempfile.mkdtemp(prefix=".efpack-validate-")).resolve()
    try:
        for name, content in validated.files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        repository = PackRepository(Path.cwd())
        closure: dict[tuple[str, str, str, str], LoadedPack] = {}
        for member in validated.members:
            source = staging / _prefix(member)
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
            closure[(member["publisher"], member["type"], member["name"], member["version"])] = (
                loaded
            )
        _validate_locked_closure(closure, context=".efpack")
        root_identity = (
            validated.root["publisher"],
            validated.root["type"],
            validated.root["name"],
            validated.root["version"],
        )
        reachable: set[tuple[str, str, str, str]] = set()
        pending = [root_identity]
        while pending:
            identity = pending.pop()
            if identity in reachable:
                continue
            selected = closure.get(identity)
            if selected is None:
                raise PackError(".efpack root or dependency is absent from its member closure")
            reachable.add(identity)
            pending.extend(
                (
                    dependency.publisher,
                    dependency.type,
                    dependency.name,
                    dependency.version,
                )
                for dependency in selected.lock.dependencies
            )
        if reachable != set(closure):
            extras = sorted(set(closure) - reachable)
            raise PackError(
                f".efpack contains unrelated releases outside the root closure: {extras}"
            )
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _validate_locked_closure(
    closure: dict[tuple[str, str, str, str], LoadedPack],
    *,
    context: str,
) -> None:
    """Validate manifest constraints and exact locks against a materialized closure."""

    for loaded in closure.values():
        declared = {
            (dependency.publisher, dependency.type, dependency.name): dependency
            for dependency in loaded.manifest.industry_dependencies
        }
        locked = {
            (dependency.publisher, dependency.type, dependency.name): dependency
            for dependency in loaded.lock.dependencies
        }
        if declared.keys() != locked.keys():
            missing = sorted(declared.keys() - locked.keys())
            extra = sorted(locked.keys() - declared.keys())
            raise PackError(
                f"{context} manifest/lock dependency mismatch for "
                f"{loaded.manifest.publisher}/{loaded.manifest.name}: "
                f"missing={missing}, extra={extra}"
            )
        for identity, dependency in locked.items():
            declaration = declared[identity]
            selected_identity = (*identity, dependency.version)
            selected = closure.get(selected_identity)
            if selected is None or selected.digest != dependency.digest:
                raise PackError(
                    f"{context} lock closure is incomplete or mismatched for "
                    f"{dependency.publisher}/{dependency.name}@{dependency.version}"
                )
            if not version_satisfies_constraint(dependency.version, declaration.version_constraint):
                raise PackError(
                    f"{context} locked version {dependency.version} is outside constraint "
                    f"{declaration.version_constraint} for "
                    f"{dependency.publisher}/{dependency.name}"
                )


def import_efpack(
    path: Path,
    *,
    scope: Literal["project", "user"],
    project_root: Path,
    accepted_publishers: set[str],
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
        required_publishers = {member["publisher"] for member in validated.members}
        missing_consent = sorted(required_publishers - accepted_publishers)
        if missing_consent:
            flags = " ".join(f"--accept-publisher {publisher}" for publisher in missing_consent)
            raise PackError("publisher consent is required for every import; repeat with " + flags)
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


def _release_library(project_root: Path, scope: Literal["project", "user"]) -> Path:
    """Return one immutable release-library root."""

    if scope == "project":
        return project_root / ".eforge" / "releases"
    return Path.home() / ".eforge" / "releases"


def hydrate_release(
    reference: str,
    project_root: Path,
    *,
    scope: Literal["project", "user"],
) -> dict[str, Any]:
    """Atomically copy one immutable release and its locked closure into project packs."""

    try:
        publisher, pack_type, versioned = reference.split(":", 2)
        name, version = versioned.split("@", 1)
    except ValueError as exc:
        raise PackError("release must be publisher:type:name@version") from exc
    library = _release_library(project_root, scope)
    source = library / publisher / pack_type / name / version
    if not (source / "pack.yaml").is_file():
        raise PackError(f"{scope}-library release was not found: {reference}")
    repository = PackRepository(project_root)
    pending = [(publisher, pack_type, name, version)]
    closure: dict[tuple[str, str, str, str], LoadedPack] = {}
    while pending:
        identity = pending.pop()
        if identity in closure:
            continue
        member_source = library.joinpath(*identity)
        loaded = repository._load(
            member_source,
            source="path",
            reference=PackReference(
                source="path",
                path=str(member_source),
                publisher=identity[0],
                name=identity[2],
                version=identity[3],
            ),
            expected_type=identity[1],  # type: ignore[arg-type]
        )
        closure[identity] = loaded
        for dependency in loaded.lock.dependencies:
            dependency_identity = (
                dependency.publisher,
                dependency.type,
                dependency.name,
                dependency.version,
            )
            dependency_source = library.joinpath(*dependency_identity)
            if not dependency_source.is_dir():
                raise PackError(
                    f"immutable release closure is missing {dependency.publisher}/"
                    f"{dependency.name}@{dependency.version}"
                )
            pending.append(dependency_identity)

    _validate_locked_closure(closure, context="immutable release")

    destination_root = project_root / ".eforge" / "packs"
    staged_parent = project_root / ".eforge"
    staged_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".hydrate-", dir=staged_parent))
    destinations: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for identity, loaded in sorted(closure.items()):
            destination = destination_root.joinpath(*identity)
            if destination.exists():
                existing = repository._load(
                    destination,
                    source="path",
                    reference=PackReference(
                        source="path",
                        path=str(destination),
                        publisher=identity[0],
                        name=identity[2],
                        version=identity[3],
                    ),
                    expected_type=identity[1],  # type: ignore[arg-type]
                )
                if existing.digest != loaded.digest:
                    raise PackError(f"project contains a conflicting pack release: {destination}")
                continue
            staged = staging.joinpath(*identity)
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(loaded.root, staged, copy_function=shutil.copy2)
            destinations.append((staged, destination))
        for staged, destination in destinations:
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged, destination)
            published.append(destination)
    except (OSError, PackError) as exc:
        for destination in reversed(published):
            shutil.rmtree(destination, ignore_errors=True)
        if isinstance(exc, PackError):
            raise
        raise PackError(f"unable to hydrate release closure: {exc}") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {
        "reference": reference,
        "scope": scope,
        "hydrated": bool(destinations),
        "members": [
            _member(pack)
            for pack in sorted(
                closure.values(),
                key=lambda item: (
                    item.manifest.publisher,
                    item.manifest.type,
                    item.manifest.name,
                    item.manifest.version,
                ),
            )
        ],
    }


def list_release_library(
    project_root: Path,
    *,
    scope: Literal["project", "user"],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return valid immutable releases and isolated validation issues."""

    library = _release_library(project_root, scope)
    records: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    if not library.is_dir():
        return records, issues
    repository = PackRepository(project_root)
    for root in sorted(path for path in library.glob("*/*/*/*") if path.is_dir()):
        relative = root.relative_to(library)
        if len(relative.parts) != 4:
            continue
        publisher, pack_type, name, version = relative.parts
        try:
            loaded = repository._load(
                root,
                source="path",
                reference=PackReference(
                    source="path",
                    path=str(root),
                    publisher=publisher,
                    name=name,
                    version=version,
                ),
                expected_type=pack_type,  # type: ignore[arg-type]
            )
            hydrated_path = (
                project_root / ".eforge" / "packs" / publisher / pack_type / name / version
            )
            records.append(
                {
                    **_member(loaded),
                    "scope": f"{scope}-release",
                    "location": str(root),
                    "mutable": False,
                    "resolvable": False,
                    "hydration_state": "hydrated" if hydrated_path.is_dir() else "dehydrated",
                }
            )
        except PackError as exc:
            issues.append(
                {
                    "scope": f"{scope}-release",
                    "location": str(root),
                    "error": str(exc),
                }
            )
    return records, issues
