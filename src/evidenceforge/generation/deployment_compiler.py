# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compile scenario software placement into immutable deployment indexes.

OS-native binaries and catalog applications share one path-independent content
identity boundary. Host, user, profile, and installation paths are compiled as
placement only, so one release has one digest set across the fleet.
"""

from __future__ import annotations

import ntpath
import posixpath
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace
from itertools import islice

import evidenceforge.generation.deployment_registry as deployment_registry
from evidenceforge.config.schemas import (
    ApplicationDeploymentEntry,
    ApplicationEntry,
    CatalogApplicationDeploymentEntry,
    EdrInstalledSoftwareProduct,
    LegacyStaticApplicationDeploymentEntry,
    LoadedModuleEntry,
    PlatformConfig,
    ScheduledTaskEntry,
    SystemdScheduleEntry,
    SystemServiceEntry,
)
from evidenceforge.events.content_identity import (
    ApplicationProfileIdentity,
    Architecture,
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    FileContentIdentity,
    InstalledSoftwareReleaseIdentity,
    PeVersionInfo,
    Platform,
    SoftwareInstallationIdentity,
    UserProfileIdentity,
    canonical_native_path,
)
from evidenceforge.generation.activity.application_catalog import (
    child_image_from_command,
    load_catalog,
)
from evidenceforge.generation.activity.edr_pools import (
    load_edr_pools,
    normalize_defender_platform_path,
)
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.rsat_tools import load_rsat_tools
from evidenceforge.generation.activity.service_process_profiles import (
    ServiceProcessFamily,
    ServiceProcessSpec,
    load_service_process_profiles,
)
from evidenceforge.generation.activity.system_processes import (
    NativeSystemBinaryDescriptor,
    get_deployed_scheduled_task_descriptors,
    get_deployed_system_service_descriptors,
    get_native_system_binary_descriptors,
    load_system_processes,
    materialize_catalog_image_path,
)
from evidenceforge.generation.activity.systemd_schedules import (
    deployed_systemd_schedule_descriptors,
    schedule_deployment_paths,
)
from evidenceforge.generation.deployment_registry import (
    CompiledApplicationDescriptor,
    DeploymentContentRegistry,
    HostDeploymentSpec,
    UserApplicationAssignmentSpec,
)
from evidenceforge.generation.storage_world import StorageWorldModel
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import HostDeploymentOverride, Scenario, System, User
from evidenceforge.utils.rng import _stable_seed


def infer_system_platform(system: System) -> Platform | None:
    """Return the supported deployment platform without guessing an unknown OS."""

    os_category = _get_os_category(system.os)
    if os_category in {"windows", "linux"}:
        return os_category
    os_name = system.os.casefold()
    if "macos" in os_name or "mac os" in os_name or "darwin" in os_name:
        return "macos"
    return None


def resolve_system_architecture(system: System) -> Architecture:
    """Resolve exact authored architecture or the legacy-compatible x64 default."""

    return system.architecture or "x64"


def resolve_system_build(system: System, platform: Platform) -> str:
    """Resolve exact authored build or preserve the previous Windows inference."""

    if system.os_build:
        return system.os_build
    if platform != "windows":
        return system.os.strip()
    os_name = system.os.casefold()
    if "windows 11" in os_name:
        return "10.0.22621.1"
    if "server" in os_name or system.type in {"server", "domain_controller"}:
        if "2019" in os_name:
            return "10.0.17763.1"
        return "10.0.20348.1"
    return "10.0.19041.1"


def _release_for_descriptor(
    descriptor: NativeSystemBinaryDescriptor,
    *,
    build: str,
    architecture: Architecture,
) -> BinaryReleaseIdentity:
    """Build one canonical native binary identity from release and host facts."""

    version = build if descriptor.release_policy == "host_build" else "unspecified"
    release_build = build if descriptor.release_policy == "host_build" else "unspecified"
    key = BinaryReleaseKey(
        product_id=descriptor.product_id,
        version=version,
        build=release_build,
        architecture=architecture,
        platform=descriptor.platform,
        artifact_name=_artifact_name(descriptor.path, descriptor.platform),
        variant=descriptor.variant,
    )
    pe_version_info = None
    if descriptor.has_pe_version_info:
        pe_version_info = PeVersionInfo(
            file_version=build,
            description=descriptor.description,
            product=descriptor.product,
            company=descriptor.company,
            original_filename=descriptor.original_filename,
        )
    return BinaryReleaseIdentity(key=key, pe_version_info=pe_version_info)


def _native_descriptor_applies_to_system(
    descriptor: NativeSystemBinaryDescriptor,
    system: System,
) -> bool:
    """Return whether one native binary is installed for exact host capabilities."""

    if descriptor.platform != "linux":
        return True
    if descriptor.distro not in {"", "all"}:
        normalized_os = system.os.casefold()
        is_rhel_like = any(
            marker in normalized_os for marker in ("centos", "rhel", "red hat", "rocky", "alma")
        )
        if (descriptor.distro == "rhel") != is_rhel_like:
            return False
    if descriptor.system_types and system.type.casefold() not in descriptor.system_types:
        return False
    roles = {str(role).strip().casefold() for role in (system.roles or ())}
    services = {str(service).strip().casefold() for service in (system.services or ())}
    if descriptor.roles_any or descriptor.services_any:
        return bool(
            roles.intersection(descriptor.roles_any)
            or services.intersection(descriptor.services_any)
        )
    return True


def _deployment_overrides(scenario: Scenario) -> dict[str, HostDeploymentOverride]:
    """Index exact scenario-layer deployment replacements by canonical hostname."""

    return {
        override.system.casefold(): override
        for override in scenario.environment.deployment_overrides
    }


def _deployment_application_entries(
    entries: Iterable[ApplicationEntry] | None,
) -> tuple[tuple[ApplicationEntry, ...], frozenset[str], dict[str, int]]:
    """Load every typed application and the full persona namespace."""

    if entries is not None:
        configured = tuple(
            islice(
                entries,
                deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT + 1,
            )
        )
        if len(configured) > deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT:
            raise ValueError("application_entries exceeds the bounded registry count")
        known_personas = {persona.casefold() for entry in configured for persona in entry.personas}
    else:
        raw_entries = load_catalog().get("applications", [])
        if len(raw_entries) > deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT:
            raise ValueError("application catalog exceeds the bounded registry count")
        known_personas = {
            str(persona).casefold()
            for raw_entry in raw_entries
            for persona in raw_entry.get("personas", [])
        }
        configured = tuple(ApplicationEntry.model_validate(raw_entry) for raw_entry in raw_entries)
    enabled = tuple(
        sorted(
            (
                entry
                for entry in configured
                if any(
                    isinstance(
                        platform.deployment,
                        (
                            ApplicationDeploymentEntry,
                            CatalogApplicationDeploymentEntry,
                            LegacyStaticApplicationDeploymentEntry,
                        ),
                    )
                    for platform in entry.platforms.values()
                )
            ),
            key=lambda entry: entry.id.casefold(),
        )
    )
    selection_ordinals = {entry.id.casefold(): ordinal for ordinal, entry in enumerate(configured)}
    return enabled, frozenset(known_personas), selection_ordinals


def _compiled_application_descriptor(
    application: ApplicationEntry,
    platform: Platform,
    platform_config: PlatformConfig,
    selection_ordinal: int,
) -> CompiledApplicationDescriptor:
    """Compile one complete platform command descriptor."""

    return CompiledApplicationDescriptor(
        application_id=application.id,
        platform=platform,
        image_path=platform_config.image_path,
        command_templates=tuple(platform_config.command_templates or ()),
        categories=tuple(application.categories),
        command_parameter_pools=tuple(
            (name, tuple(values))
            for name, values in sorted((platform_config.command_parameter_pools or {}).items())
        ),
        singleton_per_session=application.singleton_per_session,
        selection_ordinal=selection_ordinal,
    )


def _artifact_name(path: str, platform: Platform) -> str:
    """Extract a source-native artifact name from a non-materialized path template."""

    if platform == "windows":
        return ntpath.basename(path.replace("/", "\\"))
    return posixpath.basename(path)


def _pe_version_info(metadata: dict[str, str] | None) -> PeVersionInfo | None:
    """Compile validated PE metadata without retaining the mutable catalog mapping."""

    if metadata is None:
        return None
    return PeVersionInfo(
        file_version=metadata["file_version"],
        description=metadata["description"],
        product=metadata["product"],
        company=metadata["company"],
        original_filename=metadata["original_filename"],
    )


def _host_build_pe_version_info(
    metadata: dict[str, str] | None,
    host_build: str,
) -> PeVersionInfo | None:
    """Compile OS-owned PE metadata with the exact scenario host build."""

    if metadata is None:
        return None
    return _pe_version_info({**metadata, "file_version": host_build})


def _child_pe_metadata(
    platform_config: PlatformConfig,
    child_path: str,
    platform: Platform,
) -> dict[str, str] | None:
    """Return exact owner metadata with the child artifact's native filename."""

    metadata = platform_config.pe_metadata
    if metadata is None:
        return None
    return {
        **metadata,
        "original_filename": _artifact_name(child_path, platform),
    }


def _release_for_application_artifact(
    application: ApplicationEntry,
    platform: Platform,
    platform_config: PlatformConfig,
    artifact_path: str,
    metadata: dict[str, str] | None,
    architecture: Architecture,
    host_build: str,
) -> BinaryReleaseIdentity:
    """Build one path-independent application executable or module identity."""

    deployment = platform_config.deployment
    if isinstance(deployment, ApplicationDeploymentEntry):
        product_id = deployment.product_id
        version = deployment.version
        build = deployment.build
        variant = deployment.variant
    elif isinstance(deployment, CatalogApplicationDeploymentEntry):
        product_id = deployment.product_id or application.id
        variant = deployment.variant
        if deployment.release_policy == "pe_metadata":
            owner_metadata = platform_config.pe_metadata
            if owner_metadata is None:  # pragma: no cover - schema validates the executable
                raise ValueError("pe_metadata release policy requires exact metadata")
            version = owner_metadata["file_version"]
            build = owner_metadata["file_version"]
        elif deployment.release_policy == "host_build":
            version = host_build
            build = host_build
        else:
            version = "unspecified"
            build = "unspecified"
    elif isinstance(deployment, LegacyStaticApplicationDeploymentEntry):
        # Public/overlay compatibility only. Repository-owned catalog entries
        # use an explicit current policy so this path never invents a version.
        product_id = application.id
        version = "unspecified"
        build = "unspecified"
        variant = "legacy-native"
    else:  # pragma: no cover - caller filters absent descriptors
        raise ValueError("application artifact requires deployment metadata")
    pe_version_info = (
        _host_build_pe_version_info(metadata, host_build)
        if isinstance(deployment, CatalogApplicationDeploymentEntry)
        and deployment.release_policy == "host_build"
        else _pe_version_info(metadata)
    )
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=product_id,
            version=version,
            build=build,
            architecture=architecture,
            platform=platform,
            artifact_name=_artifact_name(artifact_path, platform),
            variant=variant,
        ),
        pe_version_info=pe_version_info,
    )


def _release_for_external_module(
    *,
    platform: Platform,
    artifact_path: str,
    release_policy: str,
    architecture: Architecture,
    host_build: str,
    metadata: dict[str, str] | None = None,
    product_id: str | None = None,
) -> BinaryReleaseIdentity:
    """Build one OS-owned, versioned, or explicitly-unspecified module identity."""

    artifact_name = _artifact_name(artifact_path, platform)
    if release_policy == "host_build":
        product_id = {
            "windows": "microsoft-windows",
            "linux": "linux-host",
            "macos": "macos-host",
        }[platform]
        version = host_build
        build = host_build
        variant = "core-os"
    elif release_policy == "pe_metadata":
        if metadata is None or not product_id:
            raise ValueError("pe_metadata modules require exact metadata and product_id")
        version = metadata["file_version"]
        build = metadata["file_version"]
        variant = "versioned-module"
    elif release_policy == "unspecified":
        normalized_name = "".join(
            character if character.isalnum() or character in ".-_" else "-"
            for character in artifact_name.casefold()
        )
        product_id = product_id or f"legacy-module.{normalized_name}"
        version = "unspecified"
        build = "unspecified"
        variant = "legacy-native"
    else:  # pragma: no cover - caller separates owner_release
        raise ValueError(f"unsupported external module release policy {release_policy!r}")
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=product_id,
            version=version,
            build=build,
            architecture=architecture,
            platform=platform,
            artifact_name=artifact_name,
            variant=variant,
        ),
        pe_version_info=_pe_version_info(metadata),
    )


def _release_for_catalog_executable(
    descriptor: ScheduledTaskEntry | SystemServiceEntry,
    *,
    artifact_path: str,
    architecture: Architecture,
    host_build: str,
) -> BinaryReleaseIdentity:
    """Build one data-owned service/task executable release identity."""

    if descriptor.release_policy is None or descriptor.product_id is None:
        raise ValueError(f"deployment descriptor {descriptor.id!r} is incomplete")
    host_owned = descriptor.release_policy == "host_build"
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=descriptor.product_id,
            version=host_build if host_owned else "unspecified",
            build=host_build if host_owned else "unspecified",
            architecture=architecture,
            platform="windows",
            artifact_name=_artifact_name(artifact_path, "windows"),
            variant="core-os" if host_owned else "legacy-native",
        )
    )


def _release_for_service_process(
    descriptor: ServiceProcessSpec,
    *,
    platform: Platform,
    architecture: Architecture,
    host_build: str,
) -> BinaryReleaseIdentity:
    """Build one exact resident service manager/worker artifact identity."""

    if (
        descriptor.release_policy is None
        or descriptor.product_id is None
        or descriptor.variant is None
    ):
        raise ValueError(f"service process descriptor {descriptor.key!r} is incomplete")
    host_owned = descriptor.release_policy == "host_build"
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=descriptor.product_id,
            version=host_build if host_owned else "unspecified",
            build=host_build if host_owned else "unspecified",
            architecture=architecture,
            platform=platform,
            artifact_name=_artifact_name(descriptor.image, platform),
            variant=descriptor.variant,
        )
    )


def _release_for_linux_schedule(
    descriptor: SystemdScheduleEntry,
    *,
    artifact_path: str,
    architecture: Architecture,
    host_build: str,
) -> BinaryReleaseIdentity:
    """Build one exact Linux timer/cron workload artifact identity."""

    if (
        descriptor.release_policy is None
        or descriptor.product_id is None
        or descriptor.variant is None
    ):
        raise ValueError(f"Linux schedule descriptor {descriptor.id!r} is incomplete")
    host_owned = descriptor.release_policy == "host_build"
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=descriptor.product_id,
            version=host_build if host_owned else "unspecified",
            build=host_build if host_owned else "unspecified",
            architecture=architecture,
            platform="linux",
            artifact_name=_artifact_name(artifact_path, "linux"),
            variant=descriptor.variant,
        )
    )


def _service_process_family_is_selected(
    family: ServiceProcessFamily,
    *,
    platform: Platform,
    host_roles: tuple[str, ...],
    host_services: Iterable[str],
    override_services: Iterable[str] | None,
) -> bool:
    """Resolve one data-owned resident service placement exactly once per host."""

    if family.os_category != platform:
        return False
    normalized_services = {
        str(value).strip().casefold().replace("-", "_") for value in host_services
    }
    family_services = {value.strip().casefold().replace("-", "_") for value in family.services_any}
    if override_services is not None:
        replacement = {value.strip().casefold().replace("-", "_") for value in override_services}
        return family.service_id.casefold().replace(
            "-", "_"
        ) in replacement or not replacement.isdisjoint(family_services)
    normalized_roles = {value.strip().casefold().replace("-", "_") for value in host_roles}
    family_roles = {value.strip().casefold().replace("-", "_") for value in family.roles_any}
    return bool(
        (family_roles and not normalized_roles.isdisjoint(family_roles))
        or (family_services and not normalized_services.isdisjoint(family_services))
        or (not family_roles and not family_services)
    )


def _intern_release(
    releases: dict[tuple[str, ...], BinaryReleaseIdentity],
    release: BinaryReleaseIdentity,
) -> BinaryReleaseIdentity:
    """Intern one exact release, enriching but never contradicting metadata."""

    key = tuple(release.canonical_key)
    existing = releases.get(key)
    if existing is None:
        releases[key] = release
        return release
    if (
        existing.pe_version_info is not None
        and release.pe_version_info is not None
        and existing.pe_version_info != release.pe_version_info
    ):
        raise ValueError(f"binary release {release.content_id!r} has contradictory PE metadata")
    if existing.pe_version_info is None and release.pe_version_info is not None:
        releases[key] = release
        return release
    return existing


def _intern_installation(
    installations: dict[str, SoftwareInstallationIdentity],
    installation: SoftwareInstallationIdentity,
) -> SoftwareInstallationIdentity:
    """Coalesce one exact logical installation and reject descriptor drift."""

    existing = installations.get(installation.installation_id)
    if existing is None:
        installations[installation.installation_id] = installation
        return installation
    if (
        existing.canonical_key != installation.canonical_key
        or existing.platform != installation.platform
    ):
        raise ValueError(
            f"installation {installation.installation_id!r} has contradictory placement"
        )
    existing_root = (
        canonical_native_path(existing.install_root, existing.platform)
        if existing.install_root
        else ""
    )
    incoming_root = (
        canonical_native_path(installation.install_root, installation.platform)
        if installation.install_root
        else ""
    )
    if existing_root and incoming_root and existing_root != incoming_root:
        raise ValueError(
            f"installation {installation.installation_id!r} has contradictory install roots"
        )
    paths_by_key = {
        canonical_native_path(path, existing.platform): path for path in existing.image_paths
    }
    for path in installation.image_paths:
        paths_by_key.setdefault(canonical_native_path(path, existing.platform), path)
    merged = replace(
        existing,
        install_root=existing.install_root or installation.install_root,
        image_paths=tuple(paths_by_key[key] for key in sorted(paths_by_key)),
    )
    installations[installation.installation_id] = merged
    return merged


def _selected_application_architecture(
    platform_config: PlatformConfig,
    host_architecture: Architecture,
) -> Architecture | None:
    """Select an exact host-compatible artifact architecture."""

    deployment = platform_config.deployment
    if isinstance(deployment, LegacyStaticApplicationDeploymentEntry):
        return host_architecture
    if not isinstance(
        deployment,
        (ApplicationDeploymentEntry, CatalogApplicationDeploymentEntry),
    ):
        return None
    if host_architecture in deployment.architectures:
        return host_architecture
    if "neutral" in deployment.architectures:
        return "neutral"
    return None


def _materialize_path(path: str, username: str) -> str:
    """Resolve the only supported placement token at the user installation boundary."""

    return path.replace("{username}", username)


def _path_parent(path: str, platform: Platform) -> str:
    """Return a native parent path without consulting the local filesystem."""

    if platform == "windows":
        return ntpath.dirname(path)
    return posixpath.dirname(path)


def _profile_root(username: str, platform: Platform) -> str:
    """Return the modeled OS profile root for one principal."""

    if platform == "windows":
        return rf"C:\Users\{username}"
    if platform == "macos":
        return f"/Users/{username}"
    return f"/home/{username}"


def _users_by_host(world_model: WorldModel) -> dict[str, tuple[User, ...]]:
    """Index enabled persona users by their already-compiled activity placement."""

    indexed: dict[str, list[User]] = defaultdict(list)
    for user_world in sorted(
        world_model.users.values(),
        key=lambda item: item.user.username.casefold(),
    ):
        user = user_world.user
        if not user.enabled:
            continue
        for system in sorted(
            user_world.activity_systems,
            key=lambda item: item.hostname.casefold(),
        ):
            indexed[system.hostname.casefold()].append(user)
    return {
        hostname: tuple(sorted(users, key=lambda user: user.username.casefold()))
        for hostname, users in indexed.items()
    }


def _persona_allows_application(
    user: User,
    application: ApplicationEntry,
    known_personas: frozenset[str],
) -> bool:
    """Mirror catalog persona eligibility, including its unknown-persona fallback."""

    persona = (user.persona or "").casefold()
    allowed = {value.casefold() for value in application.personas}
    if persona in allowed:
        return True
    return persona not in known_personas and "default" in allowed


def _prevalence_selects(
    hostname: str,
    application: ApplicationEntry,
    platform_config: PlatformConfig,
) -> bool:
    """Apply one stable fleet placement draw independent of Python hash state."""

    deployment = platform_config.deployment
    if isinstance(deployment, LegacyStaticApplicationDeploymentEntry):
        return True
    if not isinstance(
        deployment,
        (ApplicationDeploymentEntry, CatalogApplicationDeploymentEntry),
    ):
        return False
    if deployment.fleet_prevalence >= 1.0:
        return True
    if deployment.fleet_prevalence <= 0.0:
        return False
    material = (
        f"application-deployment:{hostname.casefold()}:{application.id.casefold()}:"
        f"{deployment.version}:{deployment.build}:{deployment.variant}"
    )
    bucket = _stable_seed(material) % 1_000_000
    return bucket < int(deployment.fleet_prevalence * 1_000_000)


def _module_is_selected(
    module_path: str,
    release: BinaryReleaseIdentity,
    selectors: frozenset[str] | None,
) -> bool:
    """Apply an exact module replacement without creating phantom module identities."""

    if selectors is None:
        return True
    candidates = {
        module_path.casefold(),
        module_path.replace("/", "\\").casefold(),
        release.key.artifact_name.casefold(),
        release.content_id.casefold(),
    }
    return not candidates.isdisjoint(selectors)


def compile_deployment_registry(
    scenario: Scenario,
    world_model: WorldModel,
    *,
    descriptors: Iterable[NativeSystemBinaryDescriptor] | None = None,
    application_entries: Iterable[ApplicationEntry] | None = None,
    storage_world: StorageWorldModel | None = None,
) -> DeploymentContentRegistry:
    """Compile immutable content, installation, profile, and assignment truth.

    Native and application release identities are interned by semantic release
    dimensions. Application placement is the exact intersection of host
    compatibility, stable prevalence or host override, installed scope, and
    per-user persona eligibility or user override.
    """

    configured_descriptors = (
        tuple(descriptors)
        if descriptors is not None
        else tuple(
            descriptor
            for platform in ("windows", "linux", "macos")
            for descriptor in get_native_system_binary_descriptors(platform)
        )
    )
    descriptors_by_platform: dict[Platform, tuple[NativeSystemBinaryDescriptor, ...]] = {
        platform: tuple(
            sorted(
                (
                    descriptor
                    for descriptor in configured_descriptors
                    if descriptor.platform == platform
                ),
                key=lambda item: (item.product_id, item.variant, item.exe.casefold()),
            )
        )
        for platform in ("windows", "linux", "macos")
    }
    applications, known_personas, application_selection_ordinals = _deployment_application_entries(
        application_entries
    )
    compiled_application_descriptors: list[CompiledApplicationDescriptor] = []
    application_descriptor_text_bytes = 0
    for application in applications:
        for platform, platform_config in application.platforms.items():
            if platform not in {"windows", "linux", "macos"} or platform_config.deployment is None:
                continue
            if (
                len(compiled_application_descriptors)
                >= deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT
            ):
                raise ValueError("application descriptors exceeds the bounded registry count")
            descriptor = _compiled_application_descriptor(
                application,
                platform,
                platform_config,
                application_selection_ordinals[application.id.casefold()],
            )
            application_descriptor_text_bytes += descriptor.retained_text_bytes
            if (
                application_descriptor_text_bytes
                > deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_TEXT_BYTES
            ):
                raise ValueError("application descriptors exceeds the bounded registry text budget")
            compiled_application_descriptors.append(descriptor)
    application_descriptors = tuple(
        sorted(
            compiled_application_descriptors,
            key=lambda descriptor: (
                descriptor.selection_ordinal,
                descriptor.application_id,
                descriptor.platform,
            ),
        )
    )
    service_process_families = tuple(
        sorted(
            load_service_process_profiles().families.items(),
            key=lambda item: item[0].casefold(),
        )
    )
    application_owned_path_sets: dict[Platform, set[str]] = {
        "windows": set(),
        "linux": set(),
        "macos": set(),
    }
    for application in applications:
        for platform in ("windows", "linux", "macos"):
            platform_config = application.platforms.get(platform)
            if platform_config is None or platform_config.deployment is None:
                continue
            application_owned_path_sets[platform].add(
                canonical_native_path(platform_config.image_path, platform)
            )
            application_owned_path_sets[platform].update(
                canonical_native_path(
                    child_image_from_command(
                        platform,
                        child_command,
                        platform_config.image_path,
                    ),
                    platform,
                )
                for child_command in platform_config.children or ()
            )
            application_owned_path_sets[platform].update(
                canonical_native_path(module.path, platform)
                for module in platform_config.loaded_modules or ()
            )
    application_owned_paths: dict[Platform, frozenset[str]] = {
        platform: frozenset(paths) for platform, paths in application_owned_path_sets.items()
    }
    users_by_host = _users_by_host(world_model)
    overrides = _deployment_overrides(scenario)

    release_by_key: dict[tuple[str, ...], BinaryReleaseIdentity] = {}
    profiles_by_owner: dict[tuple[str, str, Platform], UserProfileIdentity] = {}
    for user_world in sorted(
        world_model.users.values(),
        key=lambda item: item.user.username.casefold(),
    ):
        user = user_world.user
        if not user.enabled:
            continue
        for activity_system in sorted(
            user_world.activity_systems,
            key=lambda item: item.hostname.casefold(),
        ):
            activity_platform = infer_system_platform(activity_system)
            if activity_platform is None:
                continue
            profiles_by_owner.setdefault(
                (
                    activity_system.hostname.casefold(),
                    user.username.casefold(),
                    activity_platform,
                ),
                UserProfileIdentity(
                    hostname=activity_system.hostname,
                    principal=user.username,
                    platform=activity_platform,
                    profile_root=_profile_root(user.username, activity_platform),
                ),
            )
    users_by_name = {
        user.username.casefold(): user for user in scenario.environment.users if user.enabled
    }
    systems_by_name = {
        system.hostname.casefold(): system for system in scenario.environment.systems
    }
    authored_events = tuple(scenario.storyline or ()) + tuple(scenario.red_herrings)
    for authored in sorted(authored_events, key=lambda item: item.id):
        if not any(event.type == "process" for event in authored.events):
            continue
        user = users_by_name.get(authored.actor.casefold())
        system = systems_by_name.get(authored.system.casefold())
        if user is None or system is None:
            continue  # scenario cross-reference validation reports the authored defect
        platform = infer_system_platform(system)
        if platform is None:
            continue
        profiles_by_owner.setdefault(
            (system.hostname.casefold(), user.username.casefold(), platform),
            UserProfileIdentity(
                hostname=system.hostname,
                principal=user.username,
                platform=platform,
                profile_root=_profile_root(user.username, platform),
            ),
        )
    installations_by_id: dict[str, SoftwareInstallationIdentity] = {}
    application_profiles: list[ApplicationProfileIdentity] = []
    assignments: list[UserApplicationAssignmentSpec] = []
    deployment_specs: list[HostDeploymentSpec] = []
    file_contents = (
        ()
        if storage_world is None
        else tuple(
            FileContentIdentity(
                file_object_id=file.file_id,
                version=file.version,
                size_bytes=file.size_bytes,
                mime_type=file.mime_type,
                seed_ref=file.seed_ref or file.file_id,
            )
            for share in sorted(storage_world.shares, key=lambda item: item.ref.casefold())
            for file in sorted(
                share.files,
                key=lambda item: (item.file_id, item.version),
            )
        )
    )
    installed_software_releases = tuple(
        InstalledSoftwareReleaseIdentity(
            product_id=product.product_id,
            name=product.name,
            publisher=product.publisher,
            version=product.version,
            build=product.build,
            architecture=architecture,
            platform="windows",
            scope=product.scope,
        )
        for product in (
            EdrInstalledSoftwareProduct.model_validate(entry)
            for entry in load_edr_pools().get("installed_software_products", ())
        )
        for architecture in product.architectures
    )

    for system in sorted(scenario.environment.systems, key=lambda item: item.hostname.casefold()):
        platform = infer_system_platform(system)
        if platform is None:
            continue
        build = resolve_system_build(system, platform)
        architecture = resolve_system_architecture(system)
        override = overrides.get(system.hostname.casefold())
        host_world = world_model.hosts[system.hostname]
        selected_service_process_families = tuple(
            (family_name, family)
            for family_name, family in service_process_families
            if _service_process_family_is_selected(
                family,
                platform=platform,
                host_roles=host_world.canonical_roles,
                host_services=world_model.service_defaults_by_host[system.hostname],
                override_services=None if override is None else override.services,
            )
        )
        selected_service_descriptors = (
            get_deployed_system_service_descriptors(
                host_type=system.type,
                host=system,
                deployment_key="scenario",
            )
            if platform == "windows"
            else ()
        )
        selected_task_descriptors = (
            get_deployed_scheduled_task_descriptors(system) if platform == "windows" else ()
        )
        selected_linux_schedules = (
            deployed_systemd_schedule_descriptors(
                hostname=system.hostname,
                os_name=system.os,
                roles=host_world.canonical_roles,
                services=world_model.service_defaults_by_host[system.hostname],
            )
            if platform == "linux"
            else ()
        )
        if override is not None and override.services is not None:
            selected_service_ids = frozenset(override.services)
            selected_service_descriptors = tuple(
                descriptor
                for descriptor in selected_service_descriptors
                if descriptor.id in selected_service_ids
            )
            service_ids = tuple(override.services)
        else:
            service_ids = tuple(
                sorted(
                    {
                        *world_model.service_defaults_by_host[system.hostname],
                        *(
                            descriptor.id
                            for descriptor in selected_service_descriptors
                            if descriptor.id is not None
                        ),
                    }
                )
            )
            service_ids = tuple(
                sorted(
                    {
                        *service_ids,
                        *(
                            family.service_id
                            for _family_name, family in selected_service_process_families
                        ),
                    }
                )
            )
        if override is not None and override.tasks is not None:
            selected_task_ids = frozenset(override.tasks)
            selected_task_descriptors = tuple(
                descriptor
                for descriptor in selected_task_descriptors
                if descriptor.id in selected_task_ids
            )
            selected_linux_schedules = tuple(
                descriptor
                for descriptor in selected_linux_schedules
                if descriptor.id in selected_task_ids
            )
            task_ids = tuple(override.tasks)
        else:
            task_ids = tuple(
                sorted(
                    {
                        *(
                            descriptor.id
                            for descriptor in selected_task_descriptors
                            if descriptor.id is not None
                        ),
                        *(
                            descriptor.id
                            for descriptor in selected_linux_schedules
                            if descriptor.id is not None
                        ),
                    }
                )
            )
        capability_owned_paths = {
            canonical_native_path(
                materialize_catalog_image_path(descriptor.image, system),
                platform,
            )
            for descriptor in (*selected_service_descriptors, *selected_task_descriptors)
        }
        host_release_by_path: dict[str, BinaryReleaseIdentity] = {}
        release_groups: dict[
            str, list[tuple[NativeSystemBinaryDescriptor, BinaryReleaseIdentity]]
        ] = defaultdict(list)
        for catalog_descriptor in descriptors_by_platform[platform]:
            if not _native_descriptor_applies_to_system(catalog_descriptor, system):
                continue
            descriptor = replace(
                catalog_descriptor,
                path=normalize_defender_platform_path(
                    catalog_descriptor.path,
                    system.hostname,
                ),
            )
            normalized_descriptor_path = canonical_native_path(descriptor.path, platform)
            if normalized_descriptor_path in application_owned_paths[platform] or (
                normalized_descriptor_path in capability_owned_paths
            ):
                # The application catalog is the richer canonical owner for this
                # physical path. Omitting the path-only system alias prevents two
                # independently versioned definitions for one installed artifact.
                continue
            if descriptor.release_policy == "unspecified" and not descriptor.has_explicit_placement:
                # A path-only third-party row is not proof of installation. Its
                # selected application/service/task owner compiles the artifact.
                # Explicit host capability placement is installation proof even
                # when the legacy package version remains intentionally unknown.
                continue
            release = _release_for_descriptor(
                descriptor,
                build=build,
                architecture=architecture,
            )
            shared_release = _intern_release(release_by_key, release)
            release_groups[shared_release.release_id].append((descriptor, shared_release))
            host_release_by_path[normalized_descriptor_path] = shared_release

        host_installation_ids: list[str] = []
        host_module_content_ids: list[str] = []
        external_modules_by_release: dict[
            str,
            dict[str, tuple[str, BinaryReleaseIdentity]],
        ] = defaultdict(dict)
        for release_id, group in sorted(release_groups.items()):
            _first_descriptor, first_release = group[0]
            installation = SoftwareInstallationIdentity(
                hostname=system.hostname,
                application_id=f"native:{first_release.key.product_id}",
                release_id=release_id,
                platform=platform,
                scope="machine",
                installation_slot=first_release.key.variant,
                image_paths=tuple(descriptor.path for descriptor, _release in group),
            )
            installation = _intern_installation(installations_by_id, installation)
            host_installation_ids.append(installation.installation_id)

        application_replacement = (
            None
            if override is None or override.applications is None
            else {application.casefold() for application in override.applications}
        )
        user_replacements = (
            {
                replacement.user.casefold(): {
                    application.casefold() for application in replacement.applications
                }
                for replacement in (override.user_applications or ())
            }
            if override is not None
            else {}
        )
        module_selectors = (
            None
            if override is None or override.modules is None
            else frozenset(module.casefold() for module in override.modules)
        )

        for application in applications:
            platform_config = application.platforms.get(platform)
            if platform_config is None or platform_config.deployment is None:
                continue
            if application.system_types is not None and system.type not in application.system_types:
                continue
            selected_architecture = _selected_application_architecture(
                platform_config,
                architecture,
            )
            if selected_architecture is None:
                continue
            if application_replacement is not None:
                if application.id.casefold() not in application_replacement:
                    continue
            elif not _prevalence_selects(system.hostname, application, platform_config):
                continue

            deployment = platform_config.deployment
            if not isinstance(
                deployment,
                (
                    ApplicationDeploymentEntry,
                    CatalogApplicationDeploymentEntry,
                    LegacyStaticApplicationDeploymentEntry,
                ),
            ):  # pragma: no cover - guarded above
                raise ValueError("application artifact requires deployment metadata")
            scope = (
                deployment.scope
                if not isinstance(deployment, LegacyStaticApplicationDeploymentEntry)
                else ("user" if "{username}" in platform_config.image_path else "machine")
            )

            eligible_users = tuple(
                user
                for user in users_by_host.get(system.hostname.casefold(), ())
                if _persona_allows_application(user, application, known_personas)
                and application.id.casefold()
                in user_replacements.get(
                    user.username.casefold(),
                    {application.id.casefold()},
                )
            )
            if scope == "user" and not eligible_users:
                continue

            artifact_releases: dict[
                str,
                tuple[str, BinaryReleaseIdentity, bool],
            ] = {}
            executable_release = _release_for_application_artifact(
                application,
                platform,
                platform_config,
                platform_config.image_path,
                platform_config.pe_metadata,
                selected_architecture,
                build,
            )
            executable_path_key = canonical_native_path(platform_config.image_path, platform)
            artifact_releases[executable_path_key] = (
                platform_config.image_path,
                executable_release,
                False,
            )
            for child_command in platform_config.children or ():
                child_path = child_image_from_command(
                    platform,
                    child_command,
                    platform_config.image_path,
                )
                child_release = _release_for_application_artifact(
                    application,
                    platform,
                    platform_config,
                    child_path,
                    _child_pe_metadata(platform_config, child_path, platform),
                    selected_architecture,
                    build,
                )
                artifact_releases.setdefault(
                    canonical_native_path(child_path, platform),
                    (child_path, child_release, False),
                )
            for module in platform_config.loaded_modules or ():
                release_policy = module.release_policy or "unspecified"
                if release_policy == "owner_release":
                    module_release = _release_for_application_artifact(
                        application,
                        platform,
                        platform_config,
                        module.path,
                        module.pe_metadata,
                        selected_architecture,
                        build,
                    )
                else:
                    module_release = _release_for_external_module(
                        platform=platform,
                        artifact_path=module.path,
                        release_policy=release_policy,
                        architecture=selected_architecture,
                        host_build=build,
                        metadata=module.pe_metadata,
                        product_id=module.product_id,
                    )
                if not _module_is_selected(module.path, module_release, module_selectors):
                    continue
                if release_policy == "owner_release":
                    artifact_releases.setdefault(
                        canonical_native_path(module.path, platform),
                        (module.path, module_release, True),
                    )
                    continue
                shared_module = _intern_release(release_by_key, module_release)
                normalized_path = canonical_native_path(module.path, platform)
                external_modules_by_release[shared_module.release_id].setdefault(
                    normalized_path,
                    (module.path, shared_module),
                )
                host_module_content_ids.append(shared_module.content_id)

            shared_artifacts = tuple(
                (
                    path,
                    _intern_release(release_by_key, release),
                    is_module,
                )
                for path, release, is_module in (
                    artifact_releases[key]
                    for key in (
                        executable_path_key,
                        *(key for key in sorted(artifact_releases) if key != executable_path_key),
                    )
                )
            )
            release_ids = {release.release_id for _path, release, _module in shared_artifacts}
            if len(release_ids) != 1:  # pragma: no cover - schema owns one deployment release
                raise ValueError(f"application {application.id!r} artifacts span releases")
            release_id = next(iter(release_ids))
            host_module_content_ids.extend(
                release.content_id for _path, release, is_module in shared_artifacts if is_module
            )
            if scope == "machine":
                installation_users: tuple[User | None, ...] = (None,)
            else:
                installation_users = eligible_users

            installation_by_user: dict[str, SoftwareInstallationIdentity] = {}
            for installation_user in installation_users:
                username = installation_user.username if installation_user is not None else ""
                image_paths = tuple(
                    _materialize_path(path, username)
                    for path, _release, _module in shared_artifacts
                )
                user_profile_id = ""
                if installation_user is not None:
                    user_profile_id = profiles_by_owner.setdefault(
                        (system.hostname.casefold(), username.casefold(), platform),
                        UserProfileIdentity(
                            hostname=system.hostname,
                            principal=username,
                            platform=platform,
                            profile_root=_profile_root(username, platform),
                        ),
                    ).profile_id
                installation = SoftwareInstallationIdentity(
                    hostname=system.hostname,
                    application_id=application.id,
                    release_id=release_id,
                    platform=platform,
                    scope=scope,
                    principal=username,
                    user_profile_id=user_profile_id,
                    installation_slot=(
                        deployment.variant
                        if not isinstance(deployment, LegacyStaticApplicationDeploymentEntry)
                        else "legacy-native"
                    ),
                    install_root=_path_parent(image_paths[0], platform),
                    image_paths=image_paths,
                )
                installation = _intern_installation(installations_by_id, installation)
                host_installation_ids.append(installation.installation_id)
                for image_path, (_template, release, _is_module) in zip(
                    image_paths,
                    shared_artifacts,
                    strict=True,
                ):
                    host_release_by_path[canonical_native_path(image_path, platform)] = release
                installation_by_user[username.casefold()] = installation

            for user in eligible_users:
                profile = profiles_by_owner.setdefault(
                    (system.hostname.casefold(), user.username.casefold(), platform),
                    UserProfileIdentity(
                        hostname=system.hostname,
                        principal=user.username,
                        platform=platform,
                        profile_root=_profile_root(user.username, platform),
                    ),
                )
                installation = installation_by_user[
                    user.username.casefold() if scope == "user" else ""
                ]
                application_profile = ApplicationProfileIdentity(
                    hostname=system.hostname,
                    principal=user.username,
                    platform=platform,
                    user_profile_id=profile.profile_id,
                    installation_id=installation.installation_id,
                    application_id=application.id,
                )
                application_profiles.append(application_profile)
                assignments.append(
                    UserApplicationAssignmentSpec(
                        hostname=system.hostname,
                        principal=user.username,
                        platform=platform,
                        user_profile_id=profile.profile_id,
                        application_profile_id=application_profile.application_profile_id,
                        persona=user.persona or "default",
                        eligible_categories=tuple(application.categories),
                        intensity=float(application.selection_weight) / 10.0,
                        selection_weight=application.selection_weight,
                        selection_ordinal=application_selection_ordinals[application.id.casefold()],
                    )
                )

        for family_name, family in selected_service_process_families:
            family_releases: dict[
                str,
                dict[str, tuple[str, BinaryReleaseIdentity]],
            ] = defaultdict(dict)
            family_processes = (
                family.manager,
                *(family.workers[name] for name in sorted(family.workers)),
            )
            for process in family_processes:
                normalized_path = canonical_native_path(process.image, platform)
                release = _intern_release(
                    release_by_key,
                    _release_for_service_process(
                        process,
                        platform=platform,
                        architecture=architecture,
                        host_build=build,
                    ),
                )
                existing = host_release_by_path.get(normalized_path)
                if existing is not None and existing.canonical_key != release.canonical_key:
                    raise ValueError(
                        f"resident service path {process.image!r} has contradictory release ownership"
                    )
                shared_release = existing or release
                host_release_by_path[normalized_path] = shared_release
                family_releases[shared_release.release_id].setdefault(
                    normalized_path,
                    (process.image, shared_release),
                )

            for release_id, release_paths in sorted(family_releases.items()):
                ordered_paths = tuple(release_paths[key] for key in sorted(release_paths))
                installation = SoftwareInstallationIdentity(
                    hostname=system.hostname,
                    application_id=f"service-process:{family_name}",
                    release_id=release_id,
                    platform=platform,
                    scope="machine",
                    installation_slot=family.service_id,
                    image_paths=tuple(path for path, _release in ordered_paths),
                )
                installation = _intern_installation(installations_by_id, installation)
                host_installation_ids.append(installation.installation_id)

        for schedule in selected_linux_schedules:
            if schedule.id is None:  # pragma: no cover - config boundary supplies it
                raise ValueError("compiled Linux schedule requires an exact deployment id")
            schedule_releases: dict[
                str,
                dict[str, tuple[str, BinaryReleaseIdentity]],
            ] = defaultdict(dict)
            for artifact_path in schedule_deployment_paths(schedule, os_name=system.os):
                normalized_path = canonical_native_path(artifact_path, platform)
                release = _intern_release(
                    release_by_key,
                    _release_for_linux_schedule(
                        schedule,
                        artifact_path=artifact_path,
                        architecture=architecture,
                        host_build=build,
                    ),
                )
                existing = host_release_by_path.get(normalized_path)
                if existing is not None and existing.canonical_key != release.canonical_key:
                    raise ValueError(
                        f"Linux schedule path {artifact_path!r} has contradictory release ownership"
                    )
                shared_release = existing or release
                host_release_by_path[normalized_path] = shared_release
                schedule_releases[shared_release.release_id].setdefault(
                    normalized_path,
                    (artifact_path, shared_release),
                )
            for release_id, release_paths in sorted(schedule_releases.items()):
                ordered_paths = tuple(release_paths[key] for key in sorted(release_paths))
                installation = SoftwareInstallationIdentity(
                    hostname=system.hostname,
                    application_id=f"linux-task:{schedule.id}",
                    release_id=release_id,
                    platform=platform,
                    scope="machine",
                    installation_slot=schedule.variant or "legacy-native",
                    image_paths=tuple(path for path, _release in ordered_paths),
                )
                installation = _intern_installation(installations_by_id, installation)
                host_installation_ids.append(installation.installation_id)

        capability_releases_by_release: dict[
            str,
            dict[str, tuple[str, BinaryReleaseIdentity]],
        ] = defaultdict(dict)
        for descriptor in (*selected_service_descriptors, *selected_task_descriptors):
            image_path = materialize_catalog_image_path(descriptor.image, system)
            normalized_path = canonical_native_path(image_path, platform)
            if normalized_path in host_release_by_path:
                continue
            release = _intern_release(
                release_by_key,
                _release_for_catalog_executable(
                    descriptor,
                    artifact_path=image_path,
                    architecture=architecture,
                    host_build=build,
                ),
            )
            capability_releases_by_release[release.release_id].setdefault(
                normalized_path,
                (image_path, release),
            )
            host_release_by_path[normalized_path] = release

        for release_id, executable_paths in sorted(capability_releases_by_release.items()):
            ordered_paths = tuple(executable_paths[key] for key in sorted(executable_paths))
            first_release = ordered_paths[0][1]
            installation = SoftwareInstallationIdentity(
                hostname=system.hostname,
                application_id=f"capability:{first_release.key.product_id}",
                release_id=release_id,
                platform=platform,
                scope="machine",
                installation_slot=first_release.key.variant,
                image_paths=tuple(path for path, _release in ordered_paths),
            )
            installation = _intern_installation(installations_by_id, installation)
            host_installation_ids.append(installation.installation_id)

        system_process_catalog = load_system_processes()
        module_candidates: list[tuple[LoadedModuleEntry, BinaryReleaseIdentity | None]] = []
        if platform == "windows":
            has_rsat_persona = any(
                user.enabled and (user.persona or "").casefold() in {"sysadmin", "help_desk"}
                for user in scenario.environment.users
            )
            if system.type == "workstation" and has_rsat_persona:
                module_candidates.extend(
                    (LoadedModuleEntry.model_validate(module), None)
                    for tool in sorted(
                        load_rsat_tools(),
                        key=lambda entry: str(entry.get("id") or "").casefold(),
                    )
                    for module in tool.get("loaded_modules", ())
                )
            module_candidates.extend(
                (LoadedModuleEntry.model_validate(module), None)
                for module in system_process_catalog.get("common_loaded_modules", {}).get(
                    "windows", ()
                )
            )
            owner_releases_by_artifact: dict[str, BinaryReleaseIdentity] = {}
            for release in sorted(
                set(host_release_by_path.values()),
                key=lambda item: item.canonical_key,
            ):
                owner_releases_by_artifact.setdefault(
                    release.key.artifact_name.casefold(),
                    release,
                )
            for owner_name, modules in sorted(
                system_process_catalog.get("process_loaded_modules", {}).items()
            ):
                owner_release = owner_releases_by_artifact.get(owner_name.casefold())
                if owner_release is None:
                    continue
                module_candidates.extend(
                    (LoadedModuleEntry.model_validate(module), owner_release) for module in modules
                )
            for service in selected_service_descriptors:
                if not service.loaded_modules:
                    continue
                service_path = materialize_catalog_image_path(service.image, system)
                owner_release = host_release_by_path.get(
                    canonical_native_path(service_path, platform)
                )
                if owner_release is None:  # pragma: no cover - capability compiled above
                    raise ValueError(f"service {service.id!r} has no deployed executable owner")
                module_candidates.extend(
                    (module, owner_release) for module in service.loaded_modules
                )

        system_modules_by_path: dict[str, BinaryReleaseIdentity] = {}
        for module, owner_release in module_candidates:
            module_path = normalize_defender_platform_path(module.path, system.hostname)
            normalized_path = canonical_native_path(module_path, platform)
            existing_path_release = host_release_by_path.get(normalized_path)
            if existing_path_release is not None:
                host_module_content_ids.append(existing_path_release.content_id)
                continue
            release_policy = module.release_policy or "unspecified"
            if release_policy == "owner_release":
                if owner_release is None:
                    continue
                module_release = BinaryReleaseIdentity(
                    key=BinaryReleaseKey(
                        product_id=owner_release.key.product_id,
                        version=owner_release.key.version,
                        build=owner_release.key.build,
                        architecture=owner_release.key.architecture,
                        platform=owner_release.key.platform,
                        artifact_name=_artifact_name(module_path, platform),
                        variant=owner_release.key.variant,
                    ),
                    pe_version_info=_pe_version_info(module.pe_metadata),
                )
            else:
                module_release = _release_for_external_module(
                    platform=platform,
                    artifact_path=module_path,
                    release_policy=release_policy,
                    architecture=architecture,
                    host_build=build,
                    metadata=module.pe_metadata,
                    product_id=module.product_id,
                )
            if not _module_is_selected(module_path, module_release, module_selectors):
                continue
            shared_module = _intern_release(release_by_key, module_release)
            prior_release = system_modules_by_path.setdefault(normalized_path, shared_module)
            if prior_release.canonical_key != shared_module.canonical_key:
                raise ValueError(f"module path {module_path!r} has contradictory release ownership")
            external_modules_by_release[shared_module.release_id].setdefault(
                normalized_path,
                (module_path, shared_module),
            )
            host_release_by_path[normalized_path] = shared_module
            host_module_content_ids.append(shared_module.content_id)

        for release_id, module_paths in sorted(external_modules_by_release.items()):
            ordered_modules = tuple(module_paths[key] for key in sorted(module_paths))
            first_release = ordered_modules[0][1]
            installation = SoftwareInstallationIdentity(
                hostname=system.hostname,
                application_id=f"native:{first_release.key.product_id}",
                release_id=release_id,
                platform=platform,
                scope="machine",
                installation_slot=first_release.key.variant,
                image_paths=tuple(path for path, _release in ordered_modules),
            )
            installation = _intern_installation(installations_by_id, installation)
            host_installation_ids.append(installation.installation_id)
            for path, release in ordered_modules:
                host_release_by_path[canonical_native_path(path, platform)] = release

        host_module_content_ids = sorted(set(host_module_content_ids))

        deployment_specs.append(
            HostDeploymentSpec(
                hostname=system.hostname,
                roles=host_world.canonical_roles,
                platform=platform,
                os_build=build,
                architecture=architecture,
                installation_ids=tuple(sorted(set(host_installation_ids))),
                service_ids=service_ids,
                task_ids=task_ids,
                module_content_ids=tuple(host_module_content_ids),
            )
        )

    return DeploymentContentRegistry(
        binary_releases=sorted(release_by_key.values(), key=lambda item: item.canonical_key),
        installed_software_releases=sorted(
            installed_software_releases,
            key=lambda item: item.canonical_key,
        ),
        user_profiles=sorted(profiles_by_owner.values(), key=lambda item: item.canonical_key),
        installations=sorted(
            installations_by_id.values(),
            key=lambda item: item.canonical_key,
        ),
        application_profiles=application_profiles,
        application_descriptors=application_descriptors,
        host_deployments=deployment_specs,
        user_application_assignments=assignments,
        file_contents=file_contents,
    )


def compile_native_deployment_registry(
    scenario: Scenario,
    world_model: WorldModel,
    *,
    descriptors: Iterable[NativeSystemBinaryDescriptor] | None = None,
    application_entries: Iterable[ApplicationEntry] | None = None,
    storage_world: StorageWorldModel | None = None,
) -> DeploymentContentRegistry:
    """Compatibility name for the production deployment compiler."""

    return compile_deployment_registry(
        scenario,
        world_model,
        descriptors=descriptors,
        application_entries=application_entries,
        storage_world=storage_world,
    )
