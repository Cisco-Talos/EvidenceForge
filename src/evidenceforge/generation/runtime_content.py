# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Engine-owned canonical identity preparation for runtime file artifacts.

This module owns metadata-only identity construction. It never reads or stores
payload bytes, samples time, or mutates lifecycle state. Callers prepare a
publication before their external StateManager/lifecycle transaction and commit
the returned token last through :class:`LocalArtifactVersionRegistry`.
"""

from __future__ import annotations

import ntpath
import posixpath
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal

from evidenceforge.events.content_identity import (
    Architecture,
    FileContentIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
    MachOCodeSignature,
    MachOImageIdentity,
    PeVersionInfo,
    Platform,
    UserProfileIdentity,
    canonical_native_path,
)
from evidenceforge.events.macos_file import MacosFileMetadata, detach_file_metadata
from evidenceforge.events.macos_file_operation import MacosFileRenameObservation
from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactPreparedGroupCommit,
    LocalArtifactPublicationGroupReceipt,
    LocalArtifactPublishToken,
    LocalArtifactRegistryCensus,
    LocalArtifactVersionRegistry,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc

RuntimeArtifactOwnerKind = Literal["user", "system"]
RuntimeFileEffectAction = Literal["create", "modify", "read", "delete"]


class RuntimeContentOwnerError(ValueError):
    """A runtime artifact cannot bind to an exact compiled owner profile."""


@dataclass(frozen=True, slots=True)
class RuntimeArtifactDescriptor:
    """Complete metadata required to identify one runtime file version.

    ``file_object_id`` and ``seed_ref`` identify modeled content independently
    of its native placement. The host/profile/application fields identify the
    local object that owns that content. Executable descriptors must state an
    architecture explicitly; the manager never guesses one from a filename.
    """

    hostname: str
    principal: str
    platform: Platform
    user_profile_id: str
    application_profile_id: str
    application_id: str
    family: str
    source_object_id: str
    native_path: str
    file_object_id: str
    content_version: int
    artifact_version: int
    size_bytes: int
    mime_type: str
    seed_ref: str
    slot: str = "default"
    executable: bool = False
    architecture: Architecture | None = None
    pe_version_info: PeVersionInfo | None = None
    launchd_job: LaunchdSystemJobSpec | None = None
    macos_file: MacosFileMetadata | None = None
    code_signature: MachOCodeSignature | None = None
    mach_o_image: MachOImageIdentity | None = None

    def __post_init__(self) -> None:
        """Fail before registry admission on incomplete or contradictory metadata."""

        for field_name in (
            "hostname",
            "principal",
            "user_profile_id",
            "application_profile_id",
            "application_id",
            "family",
            "source_object_id",
            "native_path",
            "file_object_id",
            "mime_type",
            "seed_ref",
            "slot",
        ):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"runtime artifact {field_name} must not be empty")
        if self.platform not in {"windows", "linux", "macos"}:
            raise ValueError("runtime artifact platform must be windows, linux, or macos")
        canonical_native_path(self.native_path, self.platform)
        if self.content_version < 1:
            raise ValueError("runtime artifact content_version must be at least 1")
        if self.artifact_version < 1:
            raise ValueError("runtime artifact artifact_version must be at least 1")
        if self.size_bytes < 0:
            raise ValueError("runtime artifact size_bytes must be non-negative")
        if self.executable and self.architecture is None:
            raise ValueError("runtime executable artifact requires an explicit architecture")
        if not self.executable and (
            self.architecture is not None or self.pe_version_info is not None
        ):
            raise ValueError(
                "non-executable runtime artifact cannot carry architecture or PE metadata"
            )
        if self.pe_version_info is not None and self.platform != "windows":
            raise ValueError("PE metadata is valid only for Windows runtime artifacts")
        if (self.code_signature is not None or self.mach_o_image is not None) and (
            not self.executable or self.platform != "macos"
        ):
            raise ValueError("Mach-O metadata requires an executable Mac runtime artifact")


class PreparedMacosFileRename:
    """Artifact-only rename capability; loaded executions retain their old version."""

    __slots__ = ("_registry", "_publication")

    def __init__(
        self,
        registry: LocalArtifactVersionRegistry,
        publication: LocalArtifactPreparedGroupCommit,
    ) -> None:
        self._registry = registry
        self._publication = publication

    @property
    def expected_receipt(self) -> LocalArtifactPublicationGroupReceipt:
        """Return the exact receipt for lost-acknowledgement authentication."""
        return self._publication.expected_receipt

    @property
    def committed_receipt(self) -> LocalArtifactPublicationGroupReceipt | None:
        """Return a completed receipt, including after a lost commit return."""
        receipt = self._publication.receipt
        if self._publication.committed and self._registry.authenticates_publication_group_receipt(
            receipt
        ):
            return receipt
        return None

    def observe(self) -> MacosFileRenameObservation:
        """Freeze prepared before/after file facts without granting commit authority."""
        return self._registry.observe_macos_file_rename(self._publication)

    def commit(self) -> LocalArtifactPublicationGroupReceipt:
        """Withdraw the old name and publish the new name atomically."""
        return self._registry.commit_macos_file_rename(self._publication)


class RuntimeContentIdentityManager:
    """Build and prepare exact runtime artifact/content identities."""

    __slots__ = ("_registry",)

    def __init__(self, registry: LocalArtifactVersionRegistry) -> None:
        """Bind the one engine-owned bounded local artifact registry."""

        self._registry = registry

    @property
    def registry(self) -> LocalArtifactVersionRegistry:
        """Return the bound registry for orchestration and census ownership."""

        return self._registry

    @staticmethod
    def build_record(descriptor: RuntimeArtifactDescriptor) -> LocalArtifactVersionRecord:
        """Construct one path-independent content record without publishing it."""

        content = FileContentIdentity(
            file_object_id=descriptor.file_object_id,
            version=descriptor.content_version,
            size_bytes=descriptor.size_bytes,
            mime_type=descriptor.mime_type,
            seed_ref=descriptor.seed_ref,
        )
        artifact = LocalArtifactIdentity(
            hostname=descriptor.hostname,
            principal=descriptor.principal,
            platform=descriptor.platform,
            user_profile_id=descriptor.user_profile_id,
            application_profile_id=descriptor.application_profile_id,
            application_id=descriptor.application_id,
            family=descriptor.family,
            source_object_id=descriptor.source_object_id,
            native_path=descriptor.native_path,
            content_id=content.content_id,
            slot=descriptor.slot,
            version=descriptor.artifact_version,
        )
        binary = None
        if descriptor.executable:
            architecture = descriptor.architecture
            if architecture is None:  # pragma: no cover - descriptor invariant
                raise ValueError("runtime executable architecture is missing")
            binary = LocalArtifactBinaryIdentity(
                artifact_version_id=artifact.artifact_version_id,
                content_id=content.content_id,
                digests=content.digests,
                platform=descriptor.platform,
                architecture=architecture,
                artifact_name=_artifact_name(descriptor.native_path, descriptor.platform),
                pe_version_info=descriptor.pe_version_info,
                code_signature=descriptor.code_signature,
                mach_o_image=descriptor.mach_o_image,
            )
        return LocalArtifactVersionRecord(
            artifact=artifact,
            content=content,
            binary=binary,
            launchd_job=descriptor.launchd_job,
            macos_file=descriptor.macos_file,
        )

    def prepare_publication(
        self,
        descriptor: RuntimeArtifactDescriptor,
        observed_at: datetime,
        *,
        retention: timedelta | None = None,
        lease_owner: str = "",
        lease_until: datetime | None = None,
    ) -> LocalArtifactPublishToken:
        """Validate and reserve publication before a coupled external transaction."""

        return self._registry.prepare_publish_version(
            self.build_record(descriptor),
            observed_at,
            retention=retention,
            lease_owner=lease_owner,
            lease_until=lease_until,
        )

    @contextmanager
    def prepared_macos_file_rename(
        self,
        source: LocalArtifactVersionRecord,
        *,
        native_path: str,
        artifact_version: int,
        metadata: MacosFileMetadata,
        observed_at: datetime,
        retention: timedelta | None = None,
        replacement: LocalArtifactVersionRecord | None = None,
    ) -> Iterator[PreparedMacosFileRename]:
        """Prepare an explicit same-directory rename without inventing file facts.

        Replacement requires the exact currently placed destination record.
        Hard links, cross-directory/cross-volume moves and aliases are excluded.
        Only the supplied change time
        may differ in stat. Historical loaded-image references keep their exact
        version and leases; this operation does not rewrite process observations.
        """
        artifact = replace(source.artifact, native_path=native_path, version=artifact_version)
        binary = (
            None
            if source.binary is None
            else replace(
                source.binary,
                artifact_version_id=artifact.artifact_version_id,
                artifact_name=_artifact_name(native_path, "macos"),
            )
        )
        target = replace(
            source, artifact=artifact, binary=binary, macos_file=detach_file_metadata(metadata)
        )
        self._registry.validate_macos_file_rename(source, target, replacement=replacement)
        with ExitStack() as cleanup:
            removals: list[LocalArtifactPublishToken] = []
            for record in (source,) if replacement is None else (source, replacement):
                removal = self._registry.prepare_publish_version(
                    record,
                    observed_at,
                    retention=retention,
                    withdraw_placement=True,
                    require_existing=True,
                )
                cleanup.callback(self._registry.cancel_prepared, removal)
                removals.append(removal)
            horizon = self._registry.retained_version_deadline(source.artifact.artifact_version_id)
            if horizon is None:
                raise StateError("Mac rename requires its exact source retention horizon")
            target_retention = max(horizon, removals[0].retained_until) - observed_at
            publication = self._registry.prepare_publish_version(
                target, observed_at, retention=target_retention
            )
            cleanup.callback(self._registry.cancel_prepared, publication)
            with self._registry.prepared_publication_group((*removals, publication)) as group:
                yield PreparedMacosFileRename(self._registry, group)

    def prepare_effect_publication(
        self,
        *,
        root_action_id: str,
        stable_source_id: str,
        hostname: str,
        principal: str,
        platform: Platform,
        architecture: Architecture | None,
        native_path: str,
        action: RuntimeFileEffectAction,
        observed_at: datetime,
        owner_kind: RuntimeArtifactOwnerKind,
        deployment_registry: DeploymentContentRegistry | None = None,
        actor_image: str = "",
        executable: bool = False,
        authored_size_bytes: int | None = None,
        authored_mime_type: str = "",
        authored_file_object_id: str = "",
        authored_content_seed_ref: str = "",
        content_version: int = 1,
        artifact_version: int = 1,
        pe_version_info: PeVersionInfo | None = None,
        launchd_job: LaunchdSystemJobSpec | None = None,
        macos_file: MacosFileMetadata | None = None,
        code_signature: MachOCodeSignature | None = None,
        mach_o_image: MachOImageIdentity | None = None,
        retention: timedelta | None = None,
        lease_owner: str = "",
        lease_until: datetime | None = None,
    ) -> LocalArtifactPublishToken | None:
        """Prepare canonical content for one mutating file effect.

        Read/delete effects do not publish a version and return ``None``. For a
        create/modify effect, the caller supplies a path-independent
        ``stable_source_id`` (for example an authored payload or exact effect
        identity). Host, principal, and native path affect only the local
        artifact placement; they never affect content hashes.

        Production user ownership resolves the exact compiled user and actor
        application profile once. A typed system owner receives an explicit
        runtime system profile and never masquerades as a user installation.
        An explicit Mac filesystem observation supplies object and length facts;
        any independently authored values must agree. Otherwise missing byte
        length is represented as zero (unknown modeled length),
        and executable MIME is derived only from the explicit platform flag.
        """

        normalized_action = str(action).strip().casefold()
        if launchd_job is not None:
            if platform != "macos" or executable or normalized_action not in {"create", "modify"}:
                raise ValueError("launchd job semantics require a non-executable Mac file write")
            if authored_content_seed_ref and authored_content_seed_ref != launchd_job.content_seed:
                raise ValueError("launchd file content seed must match its bounded job semantics")
            authored_content_seed_ref = launchd_job.content_seed
        if normalized_action in {"read", "delete"}:
            if any(value is not None for value in (macos_file, code_signature, mach_o_image)):
                raise ValueError("Runtime metadata publication requires a create/modify effect")
            return None
        if normalized_action not in {"create", "modify"}:
            raise ValueError("runtime file effect action must be create, modify, read, or delete")
        if owner_kind not in {"user", "system"}:
            raise ValueError("runtime artifact owner_kind must be user or system")
        if not root_action_id.strip() or not stable_source_id.strip():
            raise ValueError("runtime artifact effect requires root_action_id and stable_source_id")
        canonical_native_path(native_path, platform)
        resolved_architecture = architecture
        if executable and deployment_registry is not None:
            host_deployment = deployment_registry.host_deployment(hostname)
            if host_deployment is not None and host_deployment.platform != platform:
                raise ValueError(
                    "runtime executable platform disagrees with its compiled host deployment"
                )
            if resolved_architecture is None:
                resolved_architecture = deployment_registry.host_architecture(hostname)
        if executable and resolved_architecture is None:
            raise RuntimeContentOwnerError(
                "runtime executable requires an authored or compiler-resolved architecture"
            )

        user_profile = (
            deployment_registry.user_profile_for(hostname, principal, platform)
            if deployment_registry is not None and owner_kind == "user"
            else None
        )
        if deployment_registry is not None and owner_kind == "user" and user_profile is None:
            raise RuntimeContentOwnerError(
                "runtime user artifact requires an exact compiled host/principal profile"
            )
        if user_profile is None:
            user_profile = UserProfileIdentity(
                hostname=hostname,
                principal=principal,
                platform=platform,
                profile_name="runtime-system" if owner_kind == "system" else "runtime-user",
            )

        installation = (
            deployment_registry.installation_for_image(
                hostname,
                actor_image,
                platform,
                principal=principal,
            )
            if deployment_registry is not None and actor_image.strip()
            else None
        )
        application_id = (
            installation.application_id if installation is not None else "runtime-filesystem"
        )
        application_profile = (
            deployment_registry.application_profile_for(
                user_profile.profile_id,
                installation.installation_id,
                installation.application_id,
            )
            if deployment_registry is not None and installation is not None
            else None
        )
        application_profile_id = (
            application_profile.application_profile_id
            if application_profile is not None
            else "runtime-application-profile-"
            + stable_uuid(
                "runtime-artifact-application-profile",
                user_profile.profile_id,
                application_id,
                installation.installation_id if installation is not None else "runtime",
                owner_kind,
            ).replace("-", "")[:32]
        )

        if macos_file is not None:
            if platform != "macos":
                raise ValueError("Mac file metadata requires a Mac runtime file effect")
            # The complete filesystem observation owns these facts. Do not require
            # callers to restate them in parallel scalar fields, or replace known
            # length with the legacy unknown-length sentinel.
            macos_file = detach_file_metadata(macos_file)
            if (
                authored_file_object_id.strip()
                and authored_file_object_id.strip() != macos_file.file_object_id
            ):
                raise ValueError(
                    "Authored file object disagrees with its Mac filesystem observation"
                )
            if authored_size_bytes is not None and (
                type(authored_size_bytes) is not int or authored_size_bytes != macos_file.size_bytes
            ):
                raise ValueError("Authored file size disagrees with its Mac filesystem observation")
            authored_file_object_id = macos_file.file_object_id
            authored_size_bytes = macos_file.size_bytes

        file_object_id = authored_file_object_id.strip() or stable_uuid(
            "runtime-file-content-object",
            stable_source_id,
        )
        seed_ref = authored_content_seed_ref.strip() or (f"runtime-file-content:{stable_source_id}")
        mime_type = authored_mime_type.strip() or _runtime_mime_type(platform, executable)
        size_bytes = 0 if authored_size_bytes is None else authored_size_bytes
        descriptor = RuntimeArtifactDescriptor(
            hostname=hostname,
            principal=principal,
            platform=platform,
            user_profile_id=user_profile.profile_id,
            application_profile_id=application_profile_id,
            application_id=application_id,
            family="dropped-executable" if executable else "process-owned-file",
            source_object_id=stable_uuid(
                "runtime-local-artifact-source",
                root_action_id,
                stable_source_id,
            ),
            native_path=native_path,
            file_object_id=file_object_id,
            content_version=content_version,
            artifact_version=artifact_version,
            size_bytes=size_bytes,
            mime_type=mime_type,
            seed_ref=seed_ref,
            executable=executable,
            architecture=resolved_architecture if executable else None,
            pe_version_info=pe_version_info,
            launchd_job=launchd_job,
            macos_file=macos_file,
            code_signature=code_signature,
            mach_o_image=mach_o_image,
        )
        return self.prepare_publication(
            descriptor,
            observed_at,
            retention=retention,
            lease_owner=lease_owner,
            lease_until=lease_until,
        )

    def resolve_record(
        self,
        hostname: str,
        principal: str,
        native_path: str,
        platform: Platform,
    ) -> LocalArtifactVersionRecord | None:
        """Return exact retained runtime content for one execution placement."""

        return self._registry.resolve_record_for_execution_path(
            hostname,
            principal,
            native_path,
            platform,
        )

    def advance_watermark(self, watermark: datetime) -> tuple[str, ...]:
        """Expire bounded records and return their canonical version IDs."""

        return tuple(
            artifact.artifact_version_id for artifact in self._registry.advance_watermark(watermark)
        )

    def census(self, *, estimate_bytes: bool = False) -> LocalArtifactRegistryCensus:
        """Return the one engine-owned registry census."""

        return self._registry.census(estimate_bytes=estimate_bytes)


def _artifact_name(path: str, platform: Platform) -> str:
    """Return the exact native filename without using it as content identity."""

    if platform == "windows":
        return ntpath.basename(path.replace("/", "\\"))
    if platform == "macos":
        return posixpath.basename(path)
    return posixpath.basename(path.replace("\\", "/"))


def _runtime_mime_type(platform: Platform, executable: bool) -> str:
    """Return an explicit modeled MIME without inspecting path or payload bytes."""

    if not executable:
        return "application/octet-stream"
    return {
        "windows": "application/vnd.microsoft.portable-executable",
        "linux": "application/x-elf",
        "macos": "application/x-mach-binary",
    }[platform]


__all__ = [
    "RuntimeArtifactDescriptor",
    "RuntimeArtifactOwnerKind",
    "RuntimeContentOwnerError",
    "RuntimeContentIdentityManager",
    "RuntimeFileEffectAction",
]


def runtime_executable_lease_owner(hostname: str, retained_until: datetime) -> str:
    """Share one finite run-window lease across executions of each retained version.

    The registry keys leases by version and owner. Using a window owner bounds
    lease count by retained file versions rather than historical process count.
    This conservative owner must not be released when an individual process exits.
    """
    if (
        type(hostname) is not str
        or not hostname.strip()
        or "\0" in hostname
        or type(retained_until) is not datetime
        or retained_until.utcoffset() is None
    ):
        raise ValueError("Executable window lease requires an exact host and aware deadline")
    return stable_uuid(
        "macos-runtime-executable-window",
        hostname.casefold(),
        ensure_utc(retained_until).isoformat(),
    )
