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

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.config import get_activity_directory
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


@lru_cache(maxsize=1)
def _load_catalog_config() -> dict[str, Any]:
    path = get_activity_directory() / "storage_catalog.yaml"
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream) or {}
    if not isinstance(data, dict):
        raise ValueError("storage_catalog.yaml must contain a mapping")
    return data


class CompiledStorageVolume(BaseModel):
    """Resolved Windows volume metadata."""

    id: str
    system: str
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
    audit: str
    access: CompiledStorageAccess
    files: tuple[CompiledStorageFile, ...]

    model_config = ConfigDict(frozen=True, extra="forbid")


class CompiledStorageMapping(BaseModel):
    """Resolved drive mapping audience."""

    id: str
    share: str
    users: frozenset[str]
    systems: frozenset[str]
    drive: str
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
        if len(share.name) == 2 and share.name[1] == "$":
            return f"{share.name[0].upper()}:\\{relative_path}"
        if share.name.casefold() == "admin$":
            return f"C:\\Windows\\{relative_path}"
        volume = self.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
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
        manifest = {
            "schema_version": 1,
            "volumes": [volume.model_dump(mode="json") for volume in self.volumes],
            "shares": [
                {
                    "ref": share.ref,
                    "system": share.system,
                    "name": share.name,
                    "volume": share.volume,
                    "root": share.root,
                    "preset": share.preset,
                    "population": share.population,
                    "activity": share.activity,
                    "encryption": share.encryption,
                    "audit": share.audit,
                    "file_count": len(share.files),
                    "sample_paths": [file.path for file in share.files[:sample_size]],
                    "seed_refs": [file.seed_ref for file in share.files if file.seed_ref],
                }
                for share in self.shares
            ],
            "mappings": [mapping.model_dump(mode="json") for mapping in self.mappings],
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
    def _is_dc(system: System) -> bool:
        roles = {role.casefold().replace("-", "_") for role in system.roles}
        return system.type == "domain_controller" or "domain_controller" in roles

    @staticmethod
    def _is_file_server(system: System) -> bool:
        roles = {role.casefold().replace("-", "_") for role in system.roles}
        services = {service.casefold().replace("-", "_") for service in system.services}
        is_domain_controller = system.type == "domain_controller" or "domain_controller" in roles
        return "file_server" in roles or (
            not is_domain_controller and bool(services & {"smb", "smb_server", "lanmanserver"})
        )

    def _compile(self) -> None:
        explicit = {server.system.casefold(): server for server in self.config.servers}
        unknown = sorted(set(explicit) - set(self.systems))
        if unknown:
            raise ValueError("unknown storage server systems: " + ", ".join(unknown))
        non_windows = sorted(
            server.system
            for server in self.config.servers
            if not self._is_windows(self.systems[server.system.casefold()])
        )
        if non_windows:
            raise ValueError("storage servers must run Windows: " + ", ".join(non_windows))
        eligible = [
            system
            for system in self.scenario.environment.systems
            if self._is_windows(system)
            and (
                self._is_dc(system)
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
        if self._is_dc(system):
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
        presets = (
            list(server.presets)
            if server is not None and server.presets is not None
            else self._automatic_presets(system, index=index, file_server_count=file_server_count)
        )
        configured_volumes = server.volumes if server is not None else None
        if configured_volumes is None:
            mount = (
                "C:\\Windows\\"
                if presets == ["dc_policy"]
                else "D:\\"
                if index % 2 == 0
                else "C:\\Mounts\\Data\\"
            )
            volume_id = "system" if presets == ["dc_policy"] else "data"
            volumes = [
                CompiledStorageVolume(
                    id=volume_id,
                    system=system.hostname,
                    mount=mount,
                    filesystem="ntfs",
                    label="System" if volume_id == "system" else "SharedData",
                )
            ]
        else:
            volumes = [
                CompiledStorageVolume(
                    id=volume.id,
                    system=system.hostname,
                    mount=volume.mount,
                    filesystem=volume.filesystem,
                    label=volume.label or volume.id,
                )
                for volume in configured_volumes
            ]
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
        generated.extend(self._compatibility_shares(system, default_volume, audit))
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
        ref = f"{system.hostname}.{share.id}"
        population = share.population or self.config.population
        activity = share.activity or self.config.activity
        files = (
            ()
            if share.name.casefold() in {"c$", "admin$"}
            else self._compile_catalog(ref, share.preset, population, share.seed_files)
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
            audit=audit,
            access=self._effective_access(share.access),
            files=files,
        )

    def _compile_catalog(
        self,
        share_ref: str,
        preset: str,
        population: str,
        seeds: list[StorageSeedFileConfig],
    ) -> tuple[CompiledStorageFile, ...]:
        data = _load_catalog_config()
        profile = data["profiles"][preset]
        counts = data["population_counts"]
        count = int(counts["auto"].get(preset, 64) if population == "auto" else counts[population])
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
        while len(files) < max(count, len(seeds)):
            attempts += 1
            if attempts > count * 20 + 100:
                raise ValueError(f"unable to build unique storage catalog for {share_ref}")
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
        return tuple(sorted(files, key=lambda file: file.path.casefold()))

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
        used_drives: dict[tuple[str, str, str], str] = {}
        for mapping in self.config.mappings:
            users = set(mapping.audience.users)
            for group in mapping.audience.groups:
                users.update(self.group_members.get(group.casefold(), set()))
            systems = set(mapping.audience.systems)
            drive = mapping.drive or self._automatic_drive(mapping, used_drives)
            for user in users or {"*"}:
                for system in systems or {"*"}:
                    key = (user.casefold(), system.casefold(), drive.casefold())
                    existing = used_drives.get(key)
                    if existing is not None and existing.casefold() != mapping.share.casefold():
                        raise ValueError(
                            f"storage mapping drive collision for {user}/{system}/{drive}: "
                            f"{existing} and {mapping.share}"
                        )
                    used_drives[key] = mapping.share
            self.mappings.append(
                CompiledStorageMapping(
                    id=mapping.id,
                    share=mapping.share,
                    users=frozenset(users),
                    systems=frozenset(systems),
                    drive=drive,
                    lifecycle=mapping.lifecycle,
                )
            )

    @staticmethod
    def _automatic_drive(
        mapping: StorageMappingConfig,
        used: dict[tuple[str, str, str], str],
    ) -> str:
        index = _stable_seed(f"storage-mapping-drive:{mapping.id}") % 19
        users = set(mapping.audience.users) or {"*"}
        systems = set(mapping.audience.systems) or {"*"}
        for offset in range(19):
            drive = f"{chr(ord('H') + ((index + offset) % 19))}:"
            if all(
                (user.casefold(), system.casefold(), drive.casefold()) not in used
                for user in users
                for system in systems
            ):
                return drive
        raise ValueError(f"no free drive letters remain for storage mapping {mapping.id!r}")


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
