# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic, metadata-only storage world compilation."""

from __future__ import annotations

import fnmatch
import random
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.generation.activity.smb_profiles import advertised_filesystem_default
from evidenceforge.models.scenario import (
    Scenario,
    SmbFileSelector,
    StorageAccessConfig,
    StorageMappingConfig,
    StorageSeedFileConfig,
    StorageServerConfig,
    StorageShareConfig,
    System,
)
from evidenceforge.utils.rng import _stable_seed

_MappingPresentation = tuple[frozenset[str], frozenset[str], str, str]

_UNSUPPORTED_LINUX_SMB_SERVICES = frozenset({"ksmbd", "ksmbd-server", "samba-ad-dc"})
_SAMBA_RESERVED_DISK_SHARE_NAMES = frozenset({"c$", "admin$", "sysvol", "netlogon"})


@lru_cache(maxsize=1)
def _load_catalog_config() -> dict[str, Any]:
    path = get_activity_directory() / "storage_catalog.yaml"
    data = load_with_overlay(
        path,
        "activity/storage_catalog.yaml",
        deep_merge_dict,
    )
    if not isinstance(data, dict):
        raise ValueError("storage_catalog.yaml must contain a mapping")
    return data


_register_trusted_derived_cache(
    __name__,
    "_load_catalog_config",
    globals(),
    _load_catalog_config,
)


class CompiledStorageVolume(BaseModel):
    """Resolved OS-native volume metadata."""

    id: str
    system: str
    platform: str = "windows"
    mount: str
    filesystem: str
    label: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class CompiledStorageAccess(BaseModel):
    """Expanded effective-access sets for one share."""

    read: frozenset[str]
    modify: frozenset[str]
    admin: frozenset[str]
    deny: frozenset[str]

    model_config = ConfigDict(frozen=True, extra="forbid")


class CompiledStorageFile(BaseModel):
    """Metadata for one evidence-eligible file; no payload is retained."""

    file_id: str
    version: int = 1
    share: str
    path: str
    size_bytes: int = Field(ge=0)
    mime_type: str
    tags: tuple[str, ...] = ()
    seed_ref: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @property
    def extension(self) -> str:
        return PureWindowsPath(self.path).suffix.lower()


class CompiledStorageShare(BaseModel):
    """Resolved share plus its bounded deterministic catalog."""

    ref: str
    system: str
    name: str
    volume: str
    root: str
    preset: str
    population: str
    activity: str
    encryption: str
    smb_native_filesystem: str
    audit: str
    access: CompiledStorageAccess
    files: tuple[CompiledStorageFile, ...]
    requested_file_count: int | None = Field(default=None, ge=0)
    realizable_file_count: int | None = Field(default=None, ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class CompiledStorageMapping(BaseModel):
    """Resolved OS-native mapping audience and credential behavior."""

    id: str
    share: str
    users: frozenset[str]
    systems: frozenset[str]
    drive: str | None = None
    mount: str | None = None
    credential_mode: str = "per_user"
    principal: str | None = None
    lifecycle: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class StorageWorldModel:
    """Compiled immutable storage topology with indexed resolution helpers."""

    def __init__(
        self,
        *,
        volumes: Iterable[CompiledStorageVolume],
        shares: Iterable[CompiledStorageShare],
        mappings: Iterable[CompiledStorageMapping],
    ) -> None:
        self.volumes = tuple(volumes)
        self.shares = tuple(shares)
        self.mappings = tuple(mappings)
        self.volumes_by_ref = {
            f"{volume.system}.{volume.id}".casefold(): volume for volume in self.volumes
        }
        self.shares_by_ref = {share.ref.casefold(): share for share in self.shares}
        self.mappings_by_id = {mapping.id.casefold(): mapping for mapping in self.mappings}
        self.files_by_id = {file.file_id: file for share in self.shares for file in share.files}
        self.seed_files_by_ref = {
            (share.ref.casefold(), file.seed_ref.casefold()): file
            for share in self.shares
            for file in share.files
            if file.seed_ref is not None
        }

    @classmethod
    def compile(cls, scenario: Scenario) -> StorageWorldModel:
        compiler = _StorageWorldCompiler(scenario)
        return cls(
            volumes=compiler.volumes,
            shares=compiler.shares,
            mappings=compiler.mappings,
        )

    def share(self, ref: str) -> CompiledStorageShare:
        try:
            return self.shares_by_ref[ref.casefold()]
        except KeyError as exc:
            raise KeyError(f"unknown storage share {ref!r}") from exc

    def select(
        self,
        share_ref: str,
        *,
        file_ref: str | None = None,
        path: str | None = None,
        selector: SmbFileSelector | None = None,
    ) -> tuple[CompiledStorageFile, ...]:
        share = self.share(share_ref)
        if file_ref is not None:
            file = self.seed_files_by_ref.get((share.ref.casefold(), file_ref.casefold()))
            return (file,) if file is not None else ()
        candidates = share.files
        if path is not None:
            folded = path.casefold()
            return tuple(file for file in candidates if file.path.casefold() == folded)
        if selector is None:
            return candidates
        result: list[CompiledStorageFile] = []
        for file in candidates:
            if selector.path_glob and not fnmatch.fnmatch(
                file.path.casefold(), selector.path_glob.replace("/", "\\").casefold()
            ):
                continue
            if selector.extensions and file.extension not in selector.extensions:
                continue
            if selector.tags_any and not {tag.casefold() for tag in selector.tags_any}.intersection(
                tag.casefold() for tag in file.tags
            ):
                continue
            if selector.min_size_bytes is not None and file.size_bytes < selector.min_size_bytes:
                continue
            if selector.max_size_bytes is not None and file.size_bytes > selector.max_size_bytes:
                continue
            result.append(file)
        return tuple(result)

    def server_local_path(self, share: CompiledStorageShare, relative_path: str) -> str:
        volume = self.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
        if volume.platform == "windows" and len(share.name) == 2 and share.name[1] == "$":
            return f"{share.name[0].upper()}:\\{relative_path}"
        if volume.platform == "windows" and share.name.casefold() == "admin$":
            return f"C:\\Windows\\{relative_path}"
        if volume.platform == "linux":
            components = [
                volume.mount.rstrip("/") or "/",
                share.root.replace("\\", "/"),
                relative_path.replace("\\", "/"),
            ]
            root = components[0]
            suffix = "/".join(component.strip("/") for component in components[1:] if component)
            if not suffix:
                return root
            return f"/{suffix}" if root == "/" else f"{root}/{suffix}"
        components = [volume.mount.rstrip("\\"), share.root, relative_path]
        return "\\".join(component.strip("\\") for component in components if component)

    def unc_path(self, share: CompiledStorageShare, relative_path: str = "") -> str:
        suffix = f"\\{relative_path}" if relative_path else ""
        return f"\\\\{share.system}\\{share.name}{suffix}"

    def manifest(
        self,
        *,
        sample_size: int = 5,
        resolved_targets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        shares: list[dict[str, Any]] = []
        for share in self.shares:
            volume = self.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
            provider = "windows" if volume.platform == "windows" else "samba"
            share_document: dict[str, Any] = {
                "ref": share.ref,
                "system": share.system,
                "name": share.name,
                "volume": share.volume,
                "root": share.root,
                "provider": provider,
                "platform": volume.platform,
                "network_root": self.unc_path(share),
                "server_native_root": self.server_local_path(share, ""),
                "backing_filesystem": volume.filesystem,
                "advertised_filesystem": share.smb_native_filesystem,
                "case_policy": "case_insensitive",
                "audit_profile": share.audit,
                "preset": share.preset,
                "population": share.population,
                "activity": share.activity,
                "encryption": share.encryption,
                "smb_native_filesystem": share.smb_native_filesystem,
                "audit": share.audit,
                "file_count": len(share.files),
                "sample_paths": [file.path for file in share.files[:sample_size]],
                "seed_refs": [file.seed_ref for file in share.files if file.seed_ref],
            }
            if share.requested_file_count is not None:
                share_document["population_resolution"] = {
                    "requested_file_count": share.requested_file_count,
                    "effective_file_count": len(share.files),
                    "realizable_file_count": share.realizable_file_count,
                    "capped": True,
                }
            shares.append(share_document)

        mappings: list[dict[str, Any]] = []
        for mapping in self.mappings:
            users = sorted(mapping.users, key=lambda value: (value.casefold(), value))
            systems = sorted(mapping.systems, key=lambda value: (value.casefold(), value))
            presentations: list[dict[str, str]] = []
            if mapping.drive is not None:
                presentations.append(
                    {"platform": "windows", "type": "drive", "root": mapping.drive}
                )
            if mapping.mount is not None:
                presentations.append({"platform": "linux", "type": "mount", "root": mapping.mount})
            mapping_document = mapping.model_dump(mode="json")
            mapping_document.update(
                {
                    "users": users,
                    "systems": systems,
                    "audience": {"users": users, "systems": systems},
                    "presentations": presentations,
                }
            )
            mappings.append(mapping_document)

        manifest = {
            "schema_version": 2,
            "volumes": [volume.model_dump(mode="json") for volume in self.volumes],
            "shares": shares,
            "mappings": mappings,
        }
        if resolved_targets is not None:
            manifest["resolved_storyline_targets"] = resolved_targets
        return manifest


class _StorageWorldCompiler:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.config = scenario.environment.storage
        self.systems = {
            system.hostname.casefold(): system for system in scenario.environment.systems
        }
        self.group_members = {
            group.name.casefold(): set(group.members) for group in scenario.environment.groups or []
        }
        self.volumes: list[CompiledStorageVolume] = []
        self.shares: list[CompiledStorageShare] = []
        self.mappings: list[CompiledStorageMapping] = []
        self._compile()

    @staticmethod
    def _is_windows(system: System) -> bool:
        return "windows" in system.os.casefold()

    @staticmethod
    def _is_linux(system: System) -> bool:
        os_name = system.os.casefold()
        return any(name in os_name for name in ("linux", "ubuntu", "debian", "rhel", "centos"))

    @classmethod
    def _platform(cls, system: System) -> str:
        if cls._is_windows(system):
            return "windows"
        if cls._is_linux(system):
            return "linux"
        return "unknown"

    @staticmethod
    def _is_dc(system: System) -> bool:
        roles = {role.casefold().replace("-", "_") for role in system.roles}
        return system.type == "domain_controller" or "domain_controller" in roles

    @classmethod
    def _is_file_server(cls, system: System) -> bool:
        roles = {role.casefold().replace("-", "_") for role in system.roles}
        services = {service.casefold().replace("-", "_") for service in system.services}
        is_domain_controller = system.type == "domain_controller" or "domain_controller" in roles
        if cls._is_windows(system):
            return "file_server" in roles or (
                not is_domain_controller and bool(services & {"smb", "smb_server", "lanmanserver"})
            )
        return bool(services & {"smb_server", "samba", "smbd"})

    def _compile(self) -> None:
        explicit = {server.system.casefold(): server for server in self.config.servers}
        unknown = sorted(set(explicit) - set(self.systems))
        if unknown:
            raise ValueError("unknown storage server systems: " + ", ".join(unknown))
        unsupported = sorted(
            server.system
            for server in self.config.servers
            if self._platform(self.systems[server.system.casefold()]) == "unknown"
        )
        if unsupported:
            raise ValueError("storage servers must run Windows or Linux: " + ", ".join(unsupported))
        eligible = [
            system
            for system in self.scenario.environment.systems
            if self._platform(system) in {"windows", "linux"}
            and (
                (self._is_windows(system) and self._is_dc(system))
                or self._is_file_server(system)
                or system.hostname.casefold() in explicit
            )
        ]
        file_servers = [system for system in eligible if self._is_file_server(system)]
        file_server_index = {
            system.hostname.casefold(): index for index, system in enumerate(file_servers)
        }
        for system in eligible:
            server = explicit.get(system.hostname.casefold())
            index = file_server_index.get(system.hostname.casefold(), 0)
            self._compile_server(system, server, index=index, file_server_count=len(file_servers))
        self._compile_mappings()

    def _automatic_presets(
        self,
        system: System,
        *,
        index: int,
        file_server_count: int,
    ) -> list[str]:
        presets: list[str] = []
        if self._is_windows(system) and self._is_dc(system):
            presets.append("dc_policy")
        if self._is_file_server(system):
            if file_server_count <= 1 or index == 0:
                presets.extend(("collaboration", "homes"))
            elif index % 3 == 1:
                presets.append("software")
            elif index % 3 == 2:
                presets.append("backup")
            else:
                presets.append("collaboration")
        return presets

    def _compile_server(
        self,
        system: System,
        server: StorageServerConfig | None,
        *,
        index: int,
        file_server_count: int,
    ) -> None:
        platform = self._platform(system)
        self._validate_server_provider(system, platform)
        presets = (
            list(server.presets)
            if server is not None and server.presets is not None
            else self._automatic_presets(system, index=index, file_server_count=file_server_count)
        )
        if platform == "linux" and "dc_policy" in presets:
            raise ValueError("Linux storage servers cannot use the dc_policy preset")
        configured_volumes = server.volumes if server is not None else None
        if configured_volumes is None:
            if platform == "linux":
                mount = "/srv/samba"
                filesystem = "ext4"
            else:
                mount = (
                    "C:\\Windows\\"
                    if presets == ["dc_policy"]
                    else "D:\\"
                    if index % 2 == 0
                    else "C:\\Mounts\\Data\\"
                )
                filesystem = "ntfs"
            volume_id = "system" if presets == ["dc_policy"] else "data"
            volumes = [
                CompiledStorageVolume(
                    id=volume_id,
                    system=system.hostname,
                    platform=platform,
                    mount=mount,
                    filesystem=filesystem,
                    label="System" if volume_id == "system" else "SharedData",
                )
            ]
        else:
            volumes = []
            allowed_filesystems = {"ntfs", "refs"} if platform == "windows" else {"ext4", "xfs"}
            for volume in configured_volumes:
                mount_platform = "linux" if volume.mount.startswith("/") else "windows"
                if mount_platform != platform:
                    raise ValueError(
                        f"storage volume {system.hostname}.{volume.id} mount {volume.mount!r} "
                        f"does not match {platform} server paths"
                    )
                if volume.filesystem not in allowed_filesystems:
                    allowed = ", ".join(sorted(allowed_filesystems))
                    raise ValueError(
                        f"storage volume {system.hostname}.{volume.id} filesystem "
                        f"{volume.filesystem!r} is invalid for {platform}; use {allowed}"
                    )
                volumes.append(
                    CompiledStorageVolume(
                        id=volume.id,
                        system=system.hostname,
                        platform=platform,
                        mount=volume.mount,
                        filesystem=volume.filesystem,
                        label=volume.label or volume.id,
                    )
                )
        admin_volume: CompiledStorageVolume | None = None
        if platform == "windows":
            admin_volume = next(
                (volume for volume in volumes if volume.mount.casefold() == "c:\\"),
                None,
            )
            if admin_volume is None:
                existing_volume_ids = {volume.id.casefold() for volume in volumes}
                admin_volume_id = "system"
                suffix = 2
                while admin_volume_id.casefold() in existing_volume_ids:
                    admin_volume_id = f"system{suffix}"
                    suffix += 1
                admin_volume = CompiledStorageVolume(
                    id=admin_volume_id,
                    system=system.hostname,
                    platform=platform,
                    mount="C:\\",
                    filesystem="ntfs",
                    label="System",
                )
                volumes.append(admin_volume)
        self.volumes.extend(volumes)
        default_volume = (
            server.default_volume
            if server is not None and server.default_volume is not None
            else volumes[0].id
        )
        audit = server.audit if server is not None else "standard"
        generated = [
            share
            for preset in presets
            for share in self._generated_shares(system, preset, default_volume, audit)
        ]
        if admin_volume is not None:
            generated.extend(self._compatibility_shares(system, admin_volume.id, audit))
        explicit_shares = list(server.shares) if server is not None else []
        known_volume_ids = {volume.id.casefold() for volume in volumes}
        unknown_share_volumes = sorted(
            f"{share.id}:{share.volume}"
            for share in explicit_shares
            if share.volume.casefold() not in known_volume_ids
        )
        if unknown_share_volumes:
            raise ValueError(
                "storage shares reference unknown compiled volumes: "
                + ", ".join(unknown_share_volumes)
            )
        generated_ids = {share.id.casefold() for share in generated}
        collisions = sorted(
            share.id for share in explicit_shares if share.id.casefold() in generated_ids
        )
        if collisions:
            raise ValueError(
                "explicit storage shares collide with generated preset IDs; use share_overrides: "
                + ", ".join(collisions)
            )
        overrides = {
            override.share.casefold(): override
            for override in (server.share_overrides if server is not None else [])
        }
        known_generated_refs = {f"{system.hostname}.{share.id}".casefold() for share in generated}
        unknown_overrides = sorted(set(overrides) - known_generated_refs)
        if unknown_overrides:
            raise ValueError(
                "unknown generated storage share override: " + ", ".join(unknown_overrides)
            )
        for share in generated:
            override = overrides.get(f"{system.hostname}.{share.id}".casefold())
            if override is not None:
                share = share.model_copy(
                    update={
                        "population": override.population or share.population,
                        "activity": override.activity or share.activity,
                        "encryption": override.encryption or share.encryption,
                        "smb_native_filesystem": (
                            override.smb_native_filesystem or share.smb_native_filesystem
                        ),
                        "access": override.access or share.access,
                        "seed_files": [*share.seed_files, *override.seed_files],
                    }
                )
            self.shares.append(self._compile_share(system, share, audit))
        for share in explicit_shares:
            self.shares.append(self._compile_share(system, share, audit))

    def _generated_shares(
        self,
        system: System,
        preset: str,
        volume: str,
        audit: str,
    ) -> list[StorageShareConfig]:
        _ = audit
        if preset == "dc_policy":
            return [
                StorageShareConfig(
                    id="sysvol",
                    name="SYSVOL",
                    volume=volume,
                    root="SYSVOL",
                    preset="dc_policy",
                    access=self._default_access(preset),
                ),
                StorageShareConfig(
                    id="netlogon",
                    name="NETLOGON",
                    volume=volume,
                    root="SYSVOL\\scripts",
                    preset="dc_policy",
                    access=self._default_access(preset),
                ),
            ]
        names = {
            "collaboration": ("Shared", "Shared"),
            "homes": ("Users", "Users"),
            "software": ("Software", "Software"),
            "backup": ("Backup", "Backup"),
        }
        name, root = names[preset]
        return [
            StorageShareConfig(
                id=preset,
                name=name,
                volume=volume,
                root=root,
                preset=preset,
                access=self._default_access(preset),
            )
        ]

    def _compatibility_shares(
        self,
        system: System,
        volume: str,
        audit: str,
    ) -> list[StorageShareConfig]:
        """Return sparse administrative disk shares without populating their catalogs."""

        _ = system, audit
        access = StorageAccessConfig(admin=["Domain Admins"])
        return [
            StorageShareConfig(
                id="c_admin",
                name="C$",
                volume=volume,
                preset="collaboration",
                population="small",
                access=access,
            ),
            StorageShareConfig(
                id="admin",
                name="ADMIN$",
                volume=volume,
                preset="collaboration",
                population="small",
                access=access,
            ),
        ]

    @staticmethod
    def _default_access(preset: str) -> StorageAccessConfig:
        if preset == "backup":
            return StorageAccessConfig(
                read=["Backup Operators"],
                modify=["Backup Operators"],
                admin=["Domain Admins"],
            )
        if preset == "homes":
            return StorageAccessConfig(
                read=["Domain Users"],
                modify=["Domain Users"],
                admin=["Domain Admins"],
            )
        return StorageAccessConfig(
            read=["Authenticated Users"],
            modify=["Domain Users"],
            admin=["Domain Admins"],
        )

    @staticmethod
    def _effective_access(access: StorageAccessConfig | None) -> CompiledStorageAccess:
        source = access or StorageAccessConfig(read=["Authenticated Users"])
        admin = frozenset(source.admin)
        modify = frozenset((*source.modify, *admin))
        read = frozenset((*source.read, *modify))
        return CompiledStorageAccess(
            read=read, modify=modify, admin=admin, deny=frozenset(source.deny)
        )

    def _compile_share(
        self,
        system: System,
        share: StorageShareConfig,
        audit: str,
    ) -> CompiledStorageShare:
        self._validate_disk_share_name(system, share)
        ref = f"{system.hostname}.{share.id}"
        population = share.population or self.config.population
        activity = share.activity or self.config.activity
        requested_file_count: int | None = None
        realizable_file_count: int | None = None
        if self._is_windows(system) and share.name.casefold() in {"c$", "admin$"}:
            files = ()
        else:
            files, requested_count, realizable_count = self._compile_catalog(
                ref,
                share.preset,
                population,
                share.seed_files,
            )
            if requested_count > realizable_count:
                requested_file_count = requested_count
                realizable_file_count = realizable_count
        volume = next(
            volume
            for volume in self.volumes
            if volume.system.casefold() == system.hostname.casefold()
            and volume.id.casefold() == share.volume.casefold()
        )
        if share.smb_native_filesystem is not None:
            smb_native_filesystem = share.smb_native_filesystem
        else:
            smb_native_filesystem = advertised_filesystem_default(
                volume.platform,
                volume.filesystem,
            )
        return CompiledStorageShare(
            ref=ref,
            system=system.hostname,
            name=share.name,
            volume=share.volume,
            root=share.root,
            preset=share.preset,
            population=population,
            activity=activity,
            encryption=share.encryption,
            smb_native_filesystem=smb_native_filesystem,
            audit=audit,
            access=self._effective_access(share.access),
            files=files,
            requested_file_count=requested_file_count,
            realizable_file_count=realizable_file_count,
        )

    @classmethod
    def _validate_server_provider(cls, system: System, platform: str) -> None:
        """Reject Linux SMB server providers and topologies outside the V1 model."""

        if platform != "linux":
            return
        normalized_roles = {
            role.strip().casefold().replace("_", "-").replace(" ", "-") for role in system.roles
        }
        normalized_services = {
            service.strip().casefold().replace("_", "-").replace(" ", "-")
            for service in system.services
        }
        if system.type == "domain_controller" or normalized_roles.intersection(
            {"dc", "domain-controller", "domaincontroller"}
        ):
            raise ValueError(
                f"Linux storage server {system.hostname!r} cannot be a domain controller; "
                "V1 supports Samba domain-member file servers only"
            )
        unsupported_services = sorted(
            normalized_services.intersection(_UNSUPPORTED_LINUX_SMB_SERVICES)
        )
        if unsupported_services:
            raise ValueError(
                f"Linux storage server {system.hostname!r} uses unsupported SMB service "
                f"{unsupported_services[0]!r}; V1 supports the Samba smbd provider on "
                "domain-member file servers only"
            )

    @classmethod
    def _validate_disk_share_name(cls, system: System, share: StorageShareConfig) -> None:
        """Reject named-pipe and Samba administrative/DC shares from disk-share storage."""

        normalized_name = share.name.strip().casefold()
        if normalized_name == "ipc$":
            raise ValueError(
                f"storage share {system.hostname}.{share.id} cannot use IPC$; "
                "V1 supports SMB disk shares only"
            )
        if cls._is_linux(system) and normalized_name in _SAMBA_RESERVED_DISK_SHARE_NAMES:
            raise ValueError(
                f"Samba storage share {system.hostname}.{share.id} cannot use reserved name "
                f"{share.name!r}; V1 excludes administrative and Samba AD-DC shares"
            )

    def _compile_catalog(
        self,
        share_ref: str,
        preset: str,
        population: str,
        seeds: list[StorageSeedFileConfig],
    ) -> tuple[tuple[CompiledStorageFile, ...], int, int]:
        data = _load_catalog_config()
        profile = data["profiles"][preset]
        counts = data["population_counts"]
        configured_count = int(
            counts["auto"].get(preset, 64) if population == "auto" else counts[population]
        )
        directory_variants = self._directory_variants(profile)
        subject_variants = self._subject_variants(profile)
        file_profiles = self._file_profiles_by_extension(profile)
        filename_variants = self._filename_variants(subject_variants, file_profiles)
        generated_capacity = len(directory_variants) * len(filename_variants)
        external_seed_count = sum(
            not self._path_is_generated_candidate(
                seed.path,
                directory_variants=directory_variants,
                filename_variants=filename_variants,
            )
            for seed in seeds
        )
        realizable_count = generated_capacity + external_seed_count
        requested_count = max(configured_count, len(seeds))
        target_count = min(requested_count, realizable_count)
        rng = random.Random(_stable_seed(f"storage-catalog:{self.scenario.name}:{share_ref}"))
        files: list[CompiledStorageFile] = []
        used_paths: set[str] = set()
        for seed in seeds:
            mime = self._mime_for_path(profile, seed.path)
            files.append(
                CompiledStorageFile(
                    file_id=self._file_id(share_ref, seed.path),
                    share=share_ref,
                    path=seed.path,
                    size_bytes=seed.size_bytes,
                    mime_type=mime,
                    tags=tuple(seed.tags),
                    seed_ref=seed.ref,
                )
            )
            used_paths.add(seed.path.casefold())
        attempts = 0
        while len(files) < target_count:
            attempts += 1
            if attempts > target_count * 20 + 100:
                break
            directory = rng.choice(profile["directories"])
            if rng.random() < 0.28:
                directory = f"{directory}\\{rng.randint(2023, 2027)}"
            subject = rng.choice(profile["subjects"])
            if rng.random() < 0.48:
                subject = f"{subject}-{rng.choice(['draft', 'final', 'review', 'v2', 'approved'])}"
            file_profile = rng.choices(
                profile["files"],
                weights=[int(entry.get("weight", 1)) for entry in profile["files"]],
                k=1,
            )[0]
            path = f"{directory}\\{subject}{file_profile['extension']}"
            if path.casefold() in used_paths:
                continue
            size = self._file_size(rng, str(file_profile["extension"]), preset)
            files.append(
                CompiledStorageFile(
                    file_id=self._file_id(share_ref, path),
                    share=share_ref,
                    path=path,
                    size_bytes=size,
                    mime_type=str(file_profile["mime"]),
                    tags=(preset, directory.split("\\", 1)[0].casefold()),
                )
            )
            used_paths.add(path.casefold())

        # Rejection sampling preserves the historical output for ordinary profiles. If a
        # compact pack vocabulary approaches its finite product, finish from the explicit
        # candidate space so compilation is bounded and cannot fail from duplicate draws.
        if len(files) < target_count:
            for directory in directory_variants.values():
                for filename, extension_key, file_profile in filename_variants.values():
                    path = f"{directory}\\{filename}"
                    if path.casefold() in used_paths:
                        continue
                    files.append(
                        CompiledStorageFile(
                            file_id=self._file_id(share_ref, path),
                            share=share_ref,
                            path=path,
                            size_bytes=self._file_size(rng, extension_key, preset),
                            mime_type=str(file_profile["mime"]),
                            tags=(preset, directory.split("\\", 1)[0].casefold()),
                        )
                    )
                    used_paths.add(path.casefold())
                    if len(files) >= target_count:
                        break
                if len(files) >= target_count:
                    break
        if len(files) != target_count:
            raise ValueError(
                f"storage catalog capacity calculation failed for {share_ref}: "
                f"expected {target_count} files, built {len(files)}"
            )
        return (
            tuple(sorted(files, key=lambda file: file.path.casefold())),
            requested_count,
            realizable_count,
        )

    @staticmethod
    def _directory_variants(profile: dict[str, Any]) -> dict[str, str]:
        """Return case-insensitively unique directory variants in authored order."""

        variants: dict[str, str] = {}
        for raw_directory in profile["directories"]:
            directory = str(raw_directory)
            for candidate in (directory, *(f"{directory}\\{year}" for year in range(2023, 2028))):
                variants.setdefault(candidate.casefold(), candidate)
        return variants

    @staticmethod
    def _subject_variants(profile: dict[str, Any]) -> dict[str, str]:
        """Return case-insensitively unique subject variants in authored order."""

        variants: dict[str, str] = {}
        for raw_subject in profile["subjects"]:
            subject = str(raw_subject)
            for candidate in (
                subject,
                *(
                    f"{subject}-{suffix}"
                    for suffix in ("draft", "final", "review", "v2", "approved")
                ),
            ):
                variants.setdefault(candidate.casefold(), candidate)
        return variants

    @staticmethod
    def _file_profiles_by_extension(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Return one file profile per case-insensitive extension in authored order."""

        profiles: dict[str, dict[str, Any]] = {}
        for file_profile in profile["files"]:
            extension = str(file_profile["extension"])
            profiles.setdefault(extension.casefold(), file_profile)
        return profiles

    @staticmethod
    def _filename_variants(
        subject_variants: dict[str, str],
        file_profiles: dict[str, dict[str, Any]],
    ) -> dict[str, tuple[str, str, dict[str, Any]]]:
        """Return unique filename products with their owning extension profile."""

        variants: dict[str, tuple[str, str, dict[str, Any]]] = {}
        for subject in subject_variants.values():
            for extension_key, file_profile in file_profiles.items():
                filename = f"{subject}{file_profile['extension']}"
                variants.setdefault(
                    filename.casefold(),
                    (filename, extension_key, file_profile),
                )
        return variants

    @staticmethod
    def _path_is_generated_candidate(
        path: str,
        *,
        directory_variants: dict[str, str],
        filename_variants: dict[str, tuple[str, str, dict[str, Any]]],
    ) -> bool:
        """Return whether a seed path occupies one generated product slot."""

        normalized = path.replace("/", "\\").casefold()
        if "\\" not in normalized:
            return False
        directory, filename = normalized.rsplit("\\", 1)
        if directory not in directory_variants:
            return False
        return filename in filename_variants

    @staticmethod
    def _mime_for_path(profile: dict[str, Any], path: str) -> str:
        extension = PureWindowsPath(path).suffix.casefold()
        for entry in profile["files"]:
            if str(entry["extension"]).casefold() == extension:
                return str(entry["mime"])
        return "application/octet-stream"

    @staticmethod
    def _file_size(rng: random.Random, extension: str, preset: str) -> int:
        if preset == "backup" or extension in {".vhdx", ".bak"}:
            return int(10 ** rng.uniform(7.0, 9.2))
        if preset == "software" or extension in {".msi", ".exe", ".cab", ".zip", ".7z"}:
            return int(10 ** rng.uniform(5.3, 8.2))
        return int(10 ** rng.uniform(3.0, 7.1))

    @staticmethod
    def _file_id(share_ref: str, path: str) -> str:
        return f"file-{_stable_seed(f'storage-file:{share_ref.casefold()}:{path.casefold()}'):016x}"

    def _compile_mappings(self) -> None:
        used_drives: list[_MappingPresentation] = []
        used_mounts: list[_MappingPresentation] = []
        for mapping in self.config.mappings:
            users = set(mapping.audience.users)
            for group in mapping.audience.groups:
                users.update(self.group_members.get(group.casefold(), set()))
            systems = set(mapping.audience.systems)
            client_systems = (
                [
                    self.systems[system.casefold()]
                    for system in systems
                    if system.casefold() in self.systems
                ]
                if systems
                else list(self.systems.values())
            )
            platforms = {self._platform(system) for system in client_systems}
            user_scope = frozenset(user.casefold() for user in users)
            system_scope = frozenset(system.casefold() for system in systems)
            drive = mapping.drive
            if drive is None and "windows" in platforms:
                drive = self._automatic_drive(
                    mapping,
                    users=user_scope,
                    systems=system_scope,
                    used=used_drives,
                )
            mount = mapping.mount
            if mount is None and "linux" in platforms:
                mount = f"/mnt/{mapping.id}"
            if drive is not None:
                existing = self._overlapping_presentation_owner(
                    users=user_scope,
                    systems=system_scope,
                    presentation=drive.casefold(),
                    used=used_drives,
                    different_from_share=mapping.share,
                )
                if existing is not None:
                    raise ValueError(
                        f"storage mapping drive collision for overlapping audiences on {drive}: "
                        f"{existing} and {mapping.share}"
                    )
                used_drives.append((user_scope, system_scope, drive.casefold(), mapping.share))
            if mount is not None:
                existing = self._overlapping_presentation_owner(
                    users=user_scope,
                    systems=system_scope,
                    presentation=mount,
                    used=used_mounts,
                    different_from_share=mapping.share,
                )
                if existing is not None:
                    raise ValueError(
                        f"storage mapping mount collision for overlapping audiences on {mount}: "
                        f"{existing} and {mapping.share}"
                    )
                used_mounts.append((user_scope, system_scope, mount, mapping.share))
            self.mappings.append(
                CompiledStorageMapping(
                    id=mapping.id,
                    share=mapping.share,
                    users=frozenset(users),
                    systems=frozenset(systems),
                    drive=drive,
                    mount=mount,
                    credential_mode=mapping.credential_mode,
                    principal=mapping.principal,
                    lifecycle=mapping.lifecycle,
                )
            )

    @classmethod
    def _automatic_drive(
        cls,
        mapping: StorageMappingConfig,
        *,
        users: frozenset[str],
        systems: frozenset[str],
        used: list[_MappingPresentation],
    ) -> str:
        index = _stable_seed(f"storage-mapping-drive:{mapping.id}") % 19
        for offset in range(19):
            drive = f"{chr(ord('H') + ((index + offset) % 19))}:"
            if (
                cls._overlapping_presentation_owner(
                    users=users,
                    systems=systems,
                    presentation=drive.casefold(),
                    used=used,
                )
                is None
            ):
                return drive
        raise ValueError(f"no free drive letters remain for storage mapping {mapping.id!r}")

    @classmethod
    def _overlapping_presentation_owner(
        cls,
        *,
        users: frozenset[str],
        systems: frozenset[str],
        presentation: str,
        used: list[_MappingPresentation],
        different_from_share: str | None = None,
    ) -> str | None:
        """Return an existing owner when a presentation's effective audiences overlap."""

        for existing_users, existing_systems, existing_presentation, existing_share in used:
            if existing_presentation != presentation:
                continue
            if different_from_share is not None and (
                existing_share.casefold() == different_from_share.casefold()
            ):
                continue
            if cls._audiences_overlap(users, systems, existing_users, existing_systems):
                return existing_share
        return None

    @staticmethod
    def _audiences_overlap(
        left_users: frozenset[str],
        left_systems: frozenset[str],
        right_users: frozenset[str],
        right_systems: frozenset[str],
    ) -> bool:
        """Return whether two mapping selectors can apply to the same user and system."""

        users_overlap = not left_users or not right_users or bool(left_users & right_users)
        systems_overlap = (
            not left_systems or not right_systems or bool(left_systems & right_systems)
        )
        return users_overlap and systems_overlap


def write_storage_manifest(
    path: Path,
    world: StorageWorldModel,
    *,
    resolved_targets: list[dict[str, Any]] | None = None,
) -> None:
    """Write compact author-facing compiled storage topology."""

    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            world.manifest(resolved_targets=resolved_targets),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
