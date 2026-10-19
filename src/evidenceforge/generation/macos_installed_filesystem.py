# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compile explicit installed-file provisioning into immutable modeled stat.

This bounded provider models regular installed executables for a declared time
window. It allocates file objects within explicit host volumes; it never reads
the generator filesystem or derives inodes from paths/content hashes. Size,
allocation, permissions and timestamps remain explicit provisioning inputs.
No default APFS layout, installation date or native validation is implied.
"""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.events.content_identity import canonical_native_path
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_file import MacosFileMetadata, MacosFileTime
from evidenceforge.events.macos_installed_file import MacosInstalledFileObservation
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.models.exceptions import StateError


class MacosInstalledVolumeSpec(BaseModel):
    """Explicit host-local regular-file volume allocation, independent of content."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    hostname: str = Field(min_length=1, max_length=128)
    volume_id: str = Field(min_length=1, max_length=96)
    device: int = Field(ge=-(2**31), lt=2**31)
    first_inode: int = Field(ge=1, lt=2**64)
    preferred_block_size: int = Field(gt=0, lt=2**31)

    @model_validator(mode="after")
    def exact_identity(self) -> Self:
        """Require unambiguous identity components before allocation."""
        if any(
            not value.strip() or "\0" in value or ":" in value
            for value in (self.hostname, self.volume_id)
        ):
            raise ValueError("Installed volume requires exact NUL-free host and volume identities")
        return self


class MacosInstalledFileSpec(BaseModel):
    """Explicit facts for one immutable installation placement and validity window.

    Allocation is in 512-byte units, supplied independently of logical size so
    sparse/compressed files are never silently expanded. Four stat times are
    separate inputs; observation does not update access time or imply execution.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    installation_id: str = Field(min_length=1, max_length=256)
    native_path: str = Field(min_length=1, max_length=4096)
    volume_id: str = Field(min_length=1, max_length=96)
    valid_from: datetime
    valid_until: datetime
    permissions: int = Field(ge=0, le=0o7777)
    uid: int = Field(ge=0, lt=2**32)
    gid: int = Field(ge=0, lt=2**32)
    accessed: MacosFileTime
    modified: MacosFileTime
    changed: MacosFileTime
    born: MacosFileTime
    size_bytes: int = Field(ge=0, lt=2**63)
    allocated_blocks: int = Field(ge=0, lt=2**63)
    flags: int = Field(ge=0, lt=2**32)
    generation: int = Field(ge=0, lt=2**32)

    @model_validator(mode="after")
    def explicit_window(self) -> Self:
        """Keep provisioning distinct from unknown history and future stat facts."""
        path = PurePosixPath(self.native_path)
        if (
            not self.native_path.startswith("/")
            or self.native_path.startswith("//")
            or path.as_posix() != self.native_path
            or ".." in path.parts
            or "\0" in self.native_path
            or self.valid_from.utcoffset() is None
            or self.valid_until.utcoffset() is None
            or self.valid_from >= self.valid_until
        ):
            raise ValueError(
                "Installed file requires an exact absolute path and aware finite window"
            )
        delta = self.valid_from - datetime(1970, 1, 1, tzinfo=UTC)
        start_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
        times = (self.accessed, self.modified, self.changed, self.born)
        if any(value.seconds * 1_000_000_000 + value.nanoseconds > start_ns for value in times):
            raise ValueError("Installed file stat cannot postdate its modeled validity window")
        return self


class MacosInstalledFilesystem:
    """Immutable bounded file-object owner compiled from frozen deployment facts.

    Construction allocates sequential inodes after canonical sorting, before
    any observation. Input iteration and lookup order cannot change identity.
    Reconstruct from the same frozen inputs after recovery; no mutable allocator
    cursor or generator-host state is needed. Runtime writes/renames belong to
    the existing artifact owner, not this immutable installed-file profile.
    """

    __slots__ = ("_deployments", "_files")

    def __init__(
        self,
        deployments: DeploymentContentRegistry,
        *,
        volumes: Iterable[MacosInstalledVolumeSpec],
        files: Iterable[MacosInstalledFileSpec],
    ) -> None:
        if type(deployments) is not DeploymentContentRegistry:
            raise StateError("Installed filesystem requires the exact deployment owner")
        volume_index: dict[tuple[str, str], MacosInstalledVolumeSpec] = {}
        device_index: set[tuple[str, int]] = set()
        for supplied in volumes:
            if type(supplied) is not MacosInstalledVolumeSpec:
                raise StateError("Installed filesystem requires exact volume specifications")
            volume = MacosInstalledVolumeSpec.model_validate_json(supplied.model_dump_json())
            key = (volume.hostname.casefold(), volume.volume_id)
            device_key = (key[0], volume.device)
            if key in volume_index or device_key in device_index:
                raise StateError(
                    "Installed filesystem has duplicate host volume or device identity"
                )
            volume_index[key] = volume
            device_index.add(device_key)
        prepared: list[tuple[str, str, str, MacosInstalledFileSpec]] = []
        placements: set[tuple[str, str]] = set()
        content_sizes: dict[str, int] = {}
        for supplied in files:
            if type(supplied) is not MacosInstalledFileSpec:
                raise StateError("Installed filesystem requires exact file specifications")
            spec = MacosInstalledFileSpec.model_validate_json(supplied.model_dump_json())
            installation = deployments.installation_by_id(spec.installation_id)
            if installation is None or installation.platform != "macos":
                raise StateError("Installed filesystem requires an exact deployed Mac installation")
            host = installation.hostname
            path = canonical_native_path(spec.native_path, "macos")
            if (
                (host, spec.volume_id) not in volume_index
                or path not in installation.normalized_image_paths
                or (host, path) in placements
            ):
                raise StateError("Installed filesystem has unknown volume or conflicting placement")
            binary = deployments.resolve_binary(
                host, spec.native_path, "macos", principal=installation.principal
            )
            selected = deployments.installation_for_image(
                host, spec.native_path, "macos", principal=installation.principal
            )
            if (
                selected != installation
                or binary is None
                or binary.release_id != installation.release_id
            ):
                raise StateError("Installed filesystem placement lost its exact deployed release")
            known_size = content_sizes.setdefault(binary.content_id, spec.size_bytes)
            if known_size != spec.size_bytes:
                raise StateError(
                    "Installed filesystem has conflicting sizes for the same binary content"
                )
            placements.add((host, path))
            prepared.append((host, spec.volume_id, path, spec))
        records: dict[tuple[str, str], tuple[MacosInstalledFileSpec, MacosFileMetadata]] = {}
        next_inodes = {key: volume.first_inode for key, volume in volume_index.items()}
        for host, volume_id, path, spec in sorted(prepared, key=lambda row: row[:3]):
            volume = volume_index[host, volume_id]
            inode = next_inodes[host, volume_id]
            if inode >= 2**64:
                raise StateError("Installed filesystem exhausted its modeled volume inode range")
            metadata = MacosFileMetadata(
                volume_id=volume_id,
                file_object_id=f"{host}:{volume_id}:{inode}",
                device=volume.device,
                inode=inode,
                mode=0o100000 | spec.permissions,
                link_count=1,
                uid=spec.uid,
                gid=spec.gid,
                special_device=0,
                accessed=spec.accessed,
                modified=spec.modified,
                changed=spec.changed,
                born=spec.born,
                size_bytes=spec.size_bytes,
                allocated_blocks=spec.allocated_blocks,
                preferred_block_size=volume.preferred_block_size,
                flags=spec.flags,
                generation=spec.generation,
            )
            records[spec.installation_id, path] = (spec, metadata)
            next_inodes[host, volume_id] = inode + 1
        self._deployments = deployments
        self._files = MappingProxyType(records)

    def observe(
        self,
        deployments: DeploymentContentRegistry,
        process: ProcessIdentity,
        *,
        observed_at: datetime,
    ) -> MacosInstalledFileObservation:
        """Resolve allocated stat for an exact loaded release at a known instant.

        State admission remains the native preparation owner's responsibility.
        A new deployment, runtime executable, reused path or unknown time cannot
        borrow an installed object's facts. Returned models detach internal data.
        """
        if (
            deployments is not self._deployments
            or type(process) is not ProcessIdentity
            or type(observed_at) is not datetime
            or observed_at.utcoffset() is None
            or observed_at < process.execution_started_at
            or process.executable_version is None
            or process.executable_version.platform != "macos"
            or process.executable_version.identity_kind != "installed_release"
        ):
            raise StateError(
                "Installed filesystem observation requires its exact loaded owner and time"
            )
        installation = deployments.installation_for_image(
            process.hostname, process.image, "macos", principal=process.principal
        )
        binary = deployments.resolve_binary(
            process.hostname, process.image, "macos", principal=process.principal
        )
        if (
            installation is None
            or binary is None
            or binary.content_id != process.executable_version.content_id
        ):
            raise StateError("Installed filesystem observation lost its exact loaded release")
        record = self._files.get(
            (installation.installation_id, canonical_native_path(process.image, "macos"))
        )
        if record is None or not record[0].valid_from <= observed_at < record[0].valid_until:
            raise StateError("Installed filesystem has no provisioned file at the observation time")
        return MacosInstalledFileObservation(
            installation, binary, process.image, observed_at, record[1]
        )
