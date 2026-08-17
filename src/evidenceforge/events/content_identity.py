# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Immutable deployment and content identity value objects.

These types deliberately separate content identity from placement. A binary
release is keyed by product/version/build/architecture and artifact identity,
never by the host, user, or installation path that happens to contain it.
Local artifacts make the opposite choice: their object identity includes the
host, user profile, application profile, and source object that own the local
cache or filesystem entry.

Only compact metadata and deterministic digests are retained. No file payloads
are materialized or stored by this module.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
import re
from dataclasses import dataclass, field
from typing import Literal, TypeAlias, cast

Platform: TypeAlias = Literal["windows", "linux", "macos"]
Architecture: TypeAlias = Literal["x86", "x64", "arm64", "neutral"]
InstallationScope: TypeAlias = Literal["machine", "user"]

BinaryReleaseCanonicalKey: TypeAlias = tuple[str, str, str, str, str, str, str]
InstalledSoftwareReleaseCanonicalKey: TypeAlias = tuple[str, str, str, str, str, str]
FileVersionCanonicalKey: TypeAlias = tuple[str, int]
UserProfileCanonicalKey: TypeAlias = tuple[str, str, str, str]
InstallationCanonicalKey: TypeAlias = tuple[str, str, str, str, str, str, str]
ApplicationProfileCanonicalKey: TypeAlias = tuple[str, str, str, str, str, str, str]
CompiledServiceDeploymentCanonicalKey: TypeAlias = tuple[str, str]
CompiledTaskDeploymentCanonicalKey: TypeAlias = tuple[str, str]
RuntimeServiceDeploymentCanonicalKey: TypeAlias = tuple[str, str, str]
LocalArtifactObjectKey: TypeAlias = tuple[str, str, str, str, str, str, str, str]
LocalArtifactCanonicalKey: TypeAlias = tuple[str, str, str, str, str, str, str, str, int]
LocalArtifactBinaryCanonicalKey: TypeAlias = tuple[str, str, str, str, str]

_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}
_PLATFORMS = {"windows", "linux", "macos"}
_ARCHITECTURES = {"x86", "x64", "arm64", "neutral"}
_INSTALLATION_SCOPES = {"machine", "user"}


def _text(value: str, field_name: str, *, casefold: bool = False) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized.casefold() if casefold else normalized


def _optional_text(value: str, *, casefold: bool = False) -> str:
    normalized = value.strip()
    return normalized.casefold() if casefold else normalized


def _platform(value: str) -> Platform:
    normalized = _text(value, "platform", casefold=True)
    if normalized not in _PLATFORMS:
        raise ValueError(f"platform must be one of {sorted(_PLATFORMS)}")
    return cast(Platform, normalized)


def _principal(value: str, platform: Platform) -> str:
    return _optional_text(value, casefold=platform == "windows")


def canonical_native_path(path: str, platform: Platform) -> str:
    """Return an exact platform-native lookup key for a path.

    Windows paths are slash- and case-insensitive. POSIX paths retain case.
    This helper canonicalizes path spelling only; it never accesses the host
    filesystem and therefore cannot resolve symlinks or materialize content.
    """

    normalized = _text(path, "path")
    if platform == "windows":
        return ntpath.normpath(normalized.replace("/", "\\")).casefold()
    return posixpath.normpath(normalized.replace("\\", "/"))


def _semantic_material(namespace: str, key: tuple[object, ...]) -> bytes:
    payload = json.dumps(
        [namespace, *key],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return payload.encode("utf-8")


def _semantic_sha256(namespace: str, key: tuple[object, ...]) -> str:
    return hashlib.sha256(_semantic_material(namespace, key)).hexdigest()


def _semantic_id(prefix: str, namespace: str, key: tuple[object, ...]) -> str:
    return f"{prefix}-{_semantic_sha256(namespace, key)[:32]}"


def _validate_digest(value: str, algorithm: str, *, optional: bool = False) -> str:
    normalized = value.strip().upper()
    if optional and not normalized:
        return ""
    expected_length = _HEX_LENGTHS[algorithm]
    if len(normalized) != expected_length or re.fullmatch(r"[0-9A-F]+", normalized) is None:
        raise ValueError(f"{algorithm} must be exactly {expected_length} hexadecimal characters")
    return normalized


@dataclass(frozen=True, slots=True)
class ContentDigests:
    """Deterministic digest projections for one canonical content identity."""

    md5: str
    sha1: str
    sha256: str
    imphash: str = ""

    def __post_init__(self) -> None:
        """Normalize and validate all configured digest values."""

        object.__setattr__(self, "md5", _validate_digest(self.md5, "md5"))
        object.__setattr__(self, "sha1", _validate_digest(self.sha1, "sha1"))
        object.__setattr__(self, "sha256", _validate_digest(self.sha256, "sha256"))
        object.__setattr__(
            self,
            "imphash",
            _validate_digest(self.imphash, "imphash", optional=True),
        )

    @classmethod
    def derive(
        cls,
        namespace: str,
        canonical_key: tuple[object, ...],
        *,
        include_imphash: bool = False,
    ) -> ContentDigests:
        """Derive digest-shaped values from one semantic content key.

        Every algorithm digests the same canonical material. ``imphash`` uses
        a distinct import-table namespace because it is not a whole-file hash.
        """

        material = _semantic_material(namespace, canonical_key)
        return cls(
            md5=hashlib.md5(material, usedforsecurity=False).hexdigest(),
            sha1=hashlib.sha1(material, usedforsecurity=False).hexdigest(),
            sha256=hashlib.sha256(material).hexdigest(),
            imphash=(
                hashlib.md5(b"imports:" + material, usedforsecurity=False).hexdigest()
                if include_imphash
                else ""
            ),
        )


@dataclass(frozen=True, slots=True)
class PeVersionInfo:
    """Source-native Windows PE version-resource identity."""

    file_version: str
    description: str
    product: str
    company: str
    original_filename: str

    def __post_init__(self) -> None:
        """Reject incomplete or path-derived PE version resources."""

        for field_name in ("file_version", "description", "product", "company"):
            object.__setattr__(self, field_name, _text(getattr(self, field_name), field_name))
        original_filename = _text(self.original_filename, "original_filename")
        if "/" in original_filename or "\\" in original_filename:
            raise ValueError("original_filename must be a filename, not an installation path")
        object.__setattr__(self, "original_filename", original_filename)


@dataclass(frozen=True, slots=True)
class BinaryReleaseKey:
    """Path-independent semantic key for one executable or module artifact."""

    product_id: str
    version: str
    build: str
    architecture: Architecture
    platform: Platform
    artifact_name: str
    variant: str = "default"

    def __post_init__(self) -> None:
        """Canonicalize release fields and reject accidental path keys."""

        platform = _platform(self.platform)
        architecture = _text(self.architecture, "architecture", casefold=True)
        if architecture not in _ARCHITECTURES:
            raise ValueError(f"architecture must be one of {sorted(_ARCHITECTURES)}")
        artifact_name = _text(
            self.artifact_name,
            "artifact_name",
            casefold=platform == "windows",
        )
        if "/" in artifact_name or "\\" in artifact_name:
            raise ValueError("artifact_name must not contain an installation path")

        object.__setattr__(self, "product_id", _text(self.product_id, "product_id", casefold=True))
        object.__setattr__(self, "version", _text(self.version, "version"))
        object.__setattr__(self, "build", _text(self.build, "build"))
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "artifact_name", artifact_name)
        object.__setattr__(self, "variant", _text(self.variant, "variant", casefold=True))

    @property
    def canonical_key(self) -> BinaryReleaseCanonicalKey:
        """Return the collision-safe, path-independent artifact key."""

        return (
            self.product_id,
            self.version,
            self.build,
            self.architecture,
            self.platform,
            self.artifact_name,
            self.variant,
        )

    @property
    def product_release_key(self) -> tuple[str, str, str, str, str, str]:
        """Return the shared release key for sibling executable/module artifacts."""

        return (
            self.product_id,
            self.version,
            self.build,
            self.architecture,
            self.platform,
            self.variant,
        )


@dataclass(frozen=True, slots=True)
class BinaryReleaseIdentity:
    """Canonical identity and deterministic hashes for one binary release artifact."""

    key: BinaryReleaseKey
    pe_version_info: PeVersionInfo | None = None
    release_id: str = field(init=False)
    content_id: str = field(init=False)
    digests: ContentDigests = field(init=False)
    identity_kind: Literal["installed_release"] = field(
        init=False,
        default="installed_release",
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Derive immutable release and content identifiers exactly once."""

        object.__setattr__(
            self,
            "release_id",
            _semantic_id("release", "binary-product-release", self.key.product_release_key),
        )
        object.__setattr__(
            self,
            "content_id",
            _semantic_id("binary", "binary-content", self.key.canonical_key),
        )
        object.__setattr__(
            self,
            "digests",
            ContentDigests.derive(
                "binary-content",
                self.key.canonical_key,
                include_imphash=self.key.platform == "windows",
            ),
        )

    def __deepcopy__(self, memo: dict[int, object]) -> BinaryReleaseIdentity:
        """Share this immutable interned identity across sealed occurrences."""

        memo[id(self)] = self
        return self

    @property
    def canonical_key(self) -> BinaryReleaseCanonicalKey:
        """Return the exact registry key for this binary artifact."""

        return self.key.canonical_key


@dataclass(frozen=True, slots=True)
class InstalledSoftwareReleaseIdentity:
    """Path-free release identity used by installed-software inventory evidence."""

    product_id: str
    name: str
    publisher: str
    version: str
    build: str
    architecture: Architecture
    platform: Platform
    scope: InstallationScope
    release_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Normalize release dimensions without inventing an executable artifact."""

        platform = _platform(self.platform)
        architecture = _text(self.architecture, "architecture", casefold=True)
        if architecture not in _ARCHITECTURES:
            raise ValueError(f"architecture must be one of {sorted(_ARCHITECTURES)}")
        scope = _text(self.scope, "scope", casefold=True)
        if scope not in _INSTALLATION_SCOPES:
            raise ValueError(f"scope must be one of {sorted(_INSTALLATION_SCOPES)}")
        object.__setattr__(self, "product_id", _text(self.product_id, "product_id", casefold=True))
        object.__setattr__(self, "name", _text(self.name, "name"))
        object.__setattr__(self, "publisher", _text(self.publisher, "publisher"))
        object.__setattr__(self, "version", _text(self.version, "version"))
        object.__setattr__(self, "build", _text(self.build, "build"))
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(
            self,
            "release_id",
            _semantic_id("software-release", "installed-software-release", self.canonical_key),
        )

    @property
    def canonical_key(self) -> InstalledSoftwareReleaseCanonicalKey:
        """Return the path- and host-independent installed release key."""

        return (
            self.product_id,
            self.version,
            self.build,
            self.architecture,
            self.platform,
            self.scope,
        )

    def __deepcopy__(self, memo: dict[int, object]) -> InstalledSoftwareReleaseIdentity:
        """Share this immutable release descriptor across exact consumers."""

        memo[id(self)] = self
        return self


@dataclass(frozen=True, slots=True)
class FileContentIdentity:
    """Metadata-only identity for one version of a canonical file object."""

    file_object_id: str
    version: int
    size_bytes: int
    mime_type: str
    seed_ref: str = ""
    file_version_id: str = field(init=False)
    content_id: str = field(init=False)
    digests: ContentDigests = field(init=False)

    def __post_init__(self) -> None:
        """Derive versioned content identity without retaining a payload."""

        file_object_id = _text(self.file_object_id, "file_object_id")
        if self.version < 1:
            raise ValueError("version must be at least 1")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        mime_type = _text(self.mime_type, "mime_type", casefold=True)
        seed_ref = _optional_text(self.seed_ref) or file_object_id

        object.__setattr__(self, "file_object_id", file_object_id)
        object.__setattr__(self, "mime_type", mime_type)
        object.__setattr__(self, "seed_ref", seed_ref)
        object.__setattr__(
            self,
            "file_version_id",
            _semantic_id("file-version", "file-version", self.canonical_key),
        )
        content_key = (seed_ref, self.version)
        object.__setattr__(
            self,
            "content_id",
            _semantic_id("content", "file-content", content_key),
        )
        object.__setattr__(
            self,
            "digests",
            ContentDigests.derive("file-content", content_key),
        )

    @property
    def canonical_key(self) -> FileVersionCanonicalKey:
        """Return the stable file-object/version key; paths never participate."""

        return (self.file_object_id, self.version)


@dataclass(frozen=True, slots=True)
class UserProfileIdentity:
    """One host-local OS profile owned by a modeled principal."""

    hostname: str
    principal: str
    platform: Platform
    profile_name: str = "default"
    profile_root: str = ""
    profile_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Canonicalize the profile owner and derive a path-independent ID."""

        platform = _platform(self.platform)
        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(
            self, "principal", _text(_principal(self.principal, platform), "principal")
        )
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "profile_name",
            _text(self.profile_name, "profile_name", casefold=platform == "windows"),
        )
        object.__setattr__(self, "profile_root", _optional_text(self.profile_root))
        object.__setattr__(
            self,
            "profile_id",
            _semantic_id("user-profile", "user-profile", self.canonical_key),
        )

    @property
    def canonical_key(self) -> UserProfileCanonicalKey:
        """Return the host/principal/platform/profile lookup key."""

        return (self.hostname, self.principal, self.platform, self.profile_name)


@dataclass(frozen=True, slots=True)
class SoftwareInstallationIdentity:
    """One host-local installation of a path-independent software release."""

    hostname: str
    application_id: str
    release_id: str
    platform: Platform
    scope: InstallationScope
    principal: str = ""
    user_profile_id: str = ""
    installation_slot: str = "default"
    install_root: str = ""
    image_paths: tuple[str, ...] = ()
    installation_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Validate installation scope and derive its semantic identity."""

        platform = _platform(self.platform)
        scope = _text(self.scope, "scope", casefold=True)
        if scope not in _INSTALLATION_SCOPES:
            raise ValueError(f"scope must be one of {sorted(_INSTALLATION_SCOPES)}")
        principal = _principal(self.principal, platform)
        user_profile_id = _optional_text(self.user_profile_id)
        if scope == "user" and (not principal or not user_profile_id):
            raise ValueError("user-scoped installations require principal and user_profile_id")
        if scope == "machine" and (principal or user_profile_id):
            raise ValueError("machine-scoped installations cannot name a principal or user profile")
        if not self.image_paths:
            raise ValueError("image_paths must contain at least one exact executable path")

        normalized_paths = [canonical_native_path(path, platform) for path in self.image_paths]
        if len(normalized_paths) != len(set(normalized_paths)):
            raise ValueError("image_paths contains duplicate platform-equivalent paths")

        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(
            self,
            "application_id",
            _text(self.application_id, "application_id", casefold=True),
        )
        object.__setattr__(self, "release_id", _text(self.release_id, "release_id"))
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "user_profile_id", user_profile_id)
        object.__setattr__(
            self,
            "installation_slot",
            _text(self.installation_slot, "installation_slot", casefold=True),
        )
        object.__setattr__(self, "install_root", _optional_text(self.install_root))
        object.__setattr__(
            self, "image_paths", tuple(_text(path, "image_path") for path in self.image_paths)
        )
        object.__setattr__(
            self,
            "installation_id",
            _semantic_id("installation", "software-installation", self.canonical_key),
        )

    @property
    def canonical_key(self) -> InstallationCanonicalKey:
        """Return the deployment key; installation paths are intentionally absent."""

        return (
            self.hostname,
            self.application_id,
            self.release_id,
            self.scope,
            self.principal,
            self.user_profile_id,
            self.installation_slot,
        )

    @property
    def normalized_image_paths(self) -> tuple[str, ...]:
        """Return exact platform-normalized paths used only for placement lookup."""

        return tuple(canonical_native_path(path, self.platform) for path in self.image_paths)


@dataclass(frozen=True, slots=True)
class ApplicationProfileIdentity:
    """One application-owned profile inside a user's host-local OS profile."""

    hostname: str
    principal: str
    platform: Platform
    user_profile_id: str
    installation_id: str
    application_id: str
    profile_name: str = "default"
    profile_root: str = ""
    application_profile_id: str = field(init=False)
    native_profile_token: str = field(init=False)

    def __post_init__(self) -> None:
        """Derive a stable application-profile ID and native token seed."""

        platform = _platform(self.platform)
        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(
            self,
            "principal",
            _text(_principal(self.principal, platform), "principal"),
        )
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "user_profile_id",
            _text(self.user_profile_id, "user_profile_id"),
        )
        object.__setattr__(
            self,
            "installation_id",
            _text(self.installation_id, "installation_id"),
        )
        object.__setattr__(
            self,
            "application_id",
            _text(self.application_id, "application_id", casefold=True),
        )
        object.__setattr__(
            self,
            "profile_name",
            _text(self.profile_name, "profile_name", casefold=platform == "windows"),
        )
        object.__setattr__(self, "profile_root", _optional_text(self.profile_root))
        digest = _semantic_sha256("application-profile", self.canonical_key)
        object.__setattr__(self, "application_profile_id", f"application-profile-{digest[:32]}")
        object.__setattr__(self, "native_profile_token", digest[32:48])

    @property
    def canonical_key(self) -> ApplicationProfileCanonicalKey:
        """Return the host/user/installation/application profile key."""

        return (
            self.hostname,
            self.principal,
            self.platform,
            self.user_profile_id,
            self.installation_id,
            self.application_id,
            self.profile_name,
        )


@dataclass(frozen=True, slots=True)
class CompiledServiceDeploymentIdentity:
    """Exact host-local identity for one compiler-admitted service.

    ``canonical_id`` deliberately preserves the repository catalog identifier
    byte-for-byte. The discriminator keeps this identity separate from a
    runtime-created service even when an external compatibility surface still
    consumes only the canonical string projection.
    """

    hostname: str
    service_id: str
    identity_kind: Literal["compiled_service"] = field(
        init=False,
        default="compiled_service",
    )

    def __post_init__(self) -> None:
        """Normalize the host while preserving the exact compiled service ID."""

        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(self, "service_id", _text(self.service_id, "service_id"))

    @property
    def canonical_id(self) -> str:
        """Return the exact compiler-owned service identifier."""

        return self.service_id

    @property
    def deployment_service_id(self) -> str:
        """Return the source-compatible string projection for lifecycle adapters."""

        return self.canonical_id

    @property
    def canonical_key(self) -> CompiledServiceDeploymentCanonicalKey:
        """Return the exact host/compiler-service lookup key."""

        return (self.hostname, self.service_id)

    @property
    def primitive(self) -> tuple[str, str, str]:
        """Return a stable discriminator/host/ID serialization primitive."""

        return (self.identity_kind, self.hostname, self.canonical_id)


@dataclass(frozen=True, slots=True)
class CompiledTaskDeploymentIdentity:
    """Exact host-local identity for one compiler-admitted scheduled task."""

    hostname: str
    task_id: str
    identity_kind: Literal["compiled_task"] = field(init=False, default="compiled_task")

    def __post_init__(self) -> None:
        """Normalize the host while preserving the exact compiled task ID."""

        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(self, "task_id", _text(self.task_id, "task_id"))

    @property
    def canonical_id(self) -> str:
        """Return the exact compiler-owned task identifier."""

        return self.task_id

    @property
    def deployment_task_id(self) -> str:
        """Return the source-compatible string projection for task consumers."""

        return self.canonical_id

    @property
    def canonical_key(self) -> CompiledTaskDeploymentCanonicalKey:
        """Return the exact host/compiler-task lookup key."""

        return (self.hostname, self.task_id)

    @property
    def primitive(self) -> tuple[str, str, str]:
        """Return a stable discriminator/host/ID serialization primitive."""

        return (self.identity_kind, self.hostname, self.canonical_id)


@dataclass(frozen=True, slots=True)
class RuntimeServiceDeploymentIdentity:
    """Typed deployment identity for one dynamically created service.

    The canonical ID is derived in a runtime-only namespace from the exact
    host, canonical service name, and root action. It is never the request's
    action ID and must be collision-checked against compiler-owned IDs before
    lifecycle publication.
    """

    hostname: str
    canonical_name: str
    action_id: str
    identity_kind: Literal["runtime_created_service"] = field(
        init=False,
        default="runtime_created_service",
    )
    canonical_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Normalize semantic inputs and derive the runtime-only canonical ID."""

        hostname = _text(self.hostname, "hostname", casefold=True)
        canonical_name = _text(self.canonical_name, "canonical_name", casefold=True)
        action_id = _text(self.action_id, "action_id")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "canonical_name", canonical_name)
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(
            self,
            "canonical_id",
            _semantic_id(
                "runtime-service-deployment",
                "runtime-created-service-deployment",
                self.canonical_key,
            ),
        )

    @property
    def deployment_service_id(self) -> str:
        """Return the source-compatible string projection for lifecycle adapters."""

        return self.canonical_id

    @property
    def canonical_key(self) -> RuntimeServiceDeploymentCanonicalKey:
        """Return the host/name/root-action semantic identity key."""

        return (self.hostname, self.canonical_name, self.action_id)

    @property
    def primitive(self) -> tuple[str, str, str]:
        """Return a stable discriminator/host/ID serialization primitive."""

        return (self.identity_kind, self.hostname, self.canonical_id)


ServiceDeploymentIdentity: TypeAlias = (
    CompiledServiceDeploymentIdentity | RuntimeServiceDeploymentIdentity
)


@dataclass(frozen=True, slots=True)
class LocalArtifactIdentity:
    """One version of an application-owned local cache or file artifact."""

    hostname: str
    principal: str
    platform: Platform
    user_profile_id: str
    application_profile_id: str
    application_id: str
    family: str
    source_object_id: str
    native_path: str
    content_id: str = ""
    slot: str = "default"
    version: int = 1
    artifact_id: str = field(init=False)
    artifact_version_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Derive object and version IDs from local ownership, never just a token."""

        platform = _platform(self.platform)
        if self.version < 1:
            raise ValueError("version must be at least 1")
        object.__setattr__(self, "hostname", _text(self.hostname, "hostname", casefold=True))
        object.__setattr__(
            self, "principal", _text(_principal(self.principal, platform), "principal")
        )
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "user_profile_id",
            _text(self.user_profile_id, "user_profile_id"),
        )
        object.__setattr__(
            self,
            "application_profile_id",
            _text(self.application_profile_id, "application_profile_id"),
        )
        object.__setattr__(
            self,
            "application_id",
            _text(self.application_id, "application_id", casefold=True),
        )
        object.__setattr__(self, "family", _text(self.family, "family", casefold=True))
        object.__setattr__(
            self,
            "source_object_id",
            _text(self.source_object_id, "source_object_id"),
        )
        object.__setattr__(self, "native_path", _text(self.native_path, "native_path"))
        object.__setattr__(self, "content_id", _optional_text(self.content_id))
        object.__setattr__(self, "slot", _text(self.slot, "slot", casefold=True))
        object.__setattr__(
            self,
            "artifact_id",
            _semantic_id("artifact", "local-artifact-object", self.object_key),
        )
        object.__setattr__(
            self,
            "artifact_version_id",
            _semantic_id(
                "artifact-version",
                "local-artifact-version",
                (self.artifact_id, self.version),
            ),
        )

    @property
    def object_key(self) -> LocalArtifactObjectKey:
        """Return the stable local object key, excluding content version and path."""

        return (
            self.hostname,
            self.principal,
            self.user_profile_id,
            self.application_profile_id,
            self.application_id,
            self.family,
            self.source_object_id,
            self.slot,
        )

    @property
    def canonical_key(self) -> LocalArtifactCanonicalKey:
        """Return the exact local artifact-version key."""

        return (*self.object_key, self.version)

    @property
    def normalized_native_path(self) -> str:
        """Return the platform-normalized placement key for this artifact."""

        return canonical_native_path(self.native_path, self.platform)


@dataclass(frozen=True, slots=True)
class LocalArtifactBinaryIdentity:
    """Executable identity backed by one exact retained local artifact version.

    Unlike :class:`BinaryReleaseIdentity`, this type does not claim that an
    ad-hoc or transferred executable belongs to an installed product release.
    Its hashes are the hashes of the linked canonical file content, while its
    placement and local lifecycle remain owned by ``artifact_version_id``.
    """

    artifact_version_id: str
    content_id: str
    digests: ContentDigests
    platform: Platform
    architecture: Architecture
    artifact_name: str
    pe_version_info: PeVersionInfo | None = None
    identity_kind: Literal["local_artifact"] = field(init=False, default="local_artifact")

    def __post_init__(self) -> None:
        """Validate the local artifact/content link without deriving new hashes."""

        platform = _platform(self.platform)
        architecture = _text(self.architecture, "architecture", casefold=True)
        if architecture not in _ARCHITECTURES:
            raise ValueError(f"architecture must be one of {sorted(_ARCHITECTURES)}")
        artifact_name = _text(
            self.artifact_name,
            "artifact_name",
            casefold=platform == "windows",
        )
        if "/" in artifact_name or "\\" in artifact_name:
            raise ValueError("artifact_name must not contain an installation path")
        object.__setattr__(
            self,
            "artifact_version_id",
            _text(self.artifact_version_id, "artifact_version_id"),
        )
        object.__setattr__(self, "content_id", _text(self.content_id, "content_id"))
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "artifact_name", artifact_name)

    @property
    def canonical_key(self) -> LocalArtifactBinaryCanonicalKey:
        """Return the exact local executable identity key."""

        return (
            self.artifact_version_id,
            self.content_id,
            self.platform,
            self.architecture,
            self.artifact_name,
        )

    def __deepcopy__(self, memo: dict[int, object]) -> LocalArtifactBinaryIdentity:
        """Share this immutable identity across sealed occurrences."""

        memo[id(self)] = self
        return self


@dataclass(frozen=True, slots=True)
class VirtualKernelBinaryIdentity:
    """Explicit non-file process image supplied by the operating-system kernel."""

    platform: Platform
    artifact_name: str
    reason: Literal["virtual_kernel"] = "virtual_kernel"
    identity_kind: Literal["virtual_kernel"] = field(init=False, default="virtual_kernel")

    def __post_init__(self) -> None:
        """Normalize the virtual image name without fabricating file content."""

        platform = _platform(self.platform)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "artifact_name",
            _text(self.artifact_name, "artifact_name", casefold=platform == "windows"),
        )

    @property
    def canonical_key(self) -> tuple[str, Platform, str]:
        """Return the exact typed virtual-kernel identity key."""

        return (self.identity_kind, self.platform, self.artifact_name)

    def __deepcopy__(self, memo: dict[int, object]) -> VirtualKernelBinaryIdentity:
        """Share this immutable identity across sealed occurrences."""

        memo[id(self)] = self
        return self


@dataclass(frozen=True, slots=True)
class UnresolvedBinaryIdentity:
    """Explicit compatibility-only classification for an unresolved file image.

    Production generation audits treat every instance of this type as a
    defect. It exists so legacy/direct fixtures can remain explicit without
    allowing renderers to synthesize hashes or VERSIONINFO.
    """

    platform: Platform
    native_path: str
    reason: str
    identity_kind: Literal["unresolved"] = field(init=False, default="unresolved")

    def __post_init__(self) -> None:
        """Normalize the lookup path and require an actionable reason."""

        platform = _platform(self.platform)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "native_path",
            canonical_native_path(self.native_path, platform),
        )
        object.__setattr__(self, "reason", _text(self.reason, "reason"))

    @property
    def canonical_key(self) -> tuple[str, Platform, str, str]:
        """Return the exact typed unresolved identity key."""

        return (self.identity_kind, self.platform, self.native_path, self.reason)

    def __deepcopy__(self, memo: dict[int, object]) -> UnresolvedBinaryIdentity:
        """Share this immutable identity across sealed occurrences."""

        memo[id(self)] = self
        return self


ProcessBinaryIdentity: TypeAlias = (
    BinaryReleaseIdentity
    | LocalArtifactBinaryIdentity
    | VirtualKernelBinaryIdentity
    | UnresolvedBinaryIdentity
)


@dataclass(frozen=True, slots=True)
class LocalArtifactVersionRecord:
    """Canonical content and optional executable truth for one local version."""

    artifact: LocalArtifactIdentity
    content: FileContentIdentity
    binary: LocalArtifactBinaryIdentity | None = None

    def __post_init__(self) -> None:
        """Reject contradictory artifact, content, or executable descriptors."""

        if self.artifact.content_id != self.content.content_id:
            raise ValueError("local artifact content_id must match its file content identity")
        if self.binary is None:
            return
        if (
            self.binary.artifact_version_id != self.artifact.artifact_version_id
            or self.binary.content_id != self.content.content_id
            or self.binary.digests != self.content.digests
            or self.binary.platform != self.artifact.platform
        ):
            raise ValueError(
                "local executable identity must match its artifact version, content, and platform"
            )

    def __deepcopy__(self, memo: dict[int, object]) -> LocalArtifactVersionRecord:
        """Share this immutable record across prepared publication boundaries."""

        memo[id(self)] = self
        return self


__all__ = [
    "ApplicationProfileCanonicalKey",
    "ApplicationProfileIdentity",
    "Architecture",
    "BinaryReleaseCanonicalKey",
    "BinaryReleaseIdentity",
    "BinaryReleaseKey",
    "ContentDigests",
    "FileContentIdentity",
    "FileVersionCanonicalKey",
    "InstallationCanonicalKey",
    "InstallationScope",
    "LocalArtifactCanonicalKey",
    "LocalArtifactBinaryCanonicalKey",
    "LocalArtifactBinaryIdentity",
    "LocalArtifactIdentity",
    "LocalArtifactObjectKey",
    "LocalArtifactVersionRecord",
    "PeVersionInfo",
    "Platform",
    "ProcessBinaryIdentity",
    "SoftwareInstallationIdentity",
    "UnresolvedBinaryIdentity",
    "UserProfileCanonicalKey",
    "UserProfileIdentity",
    "VirtualKernelBinaryIdentity",
    "canonical_native_path",
]
