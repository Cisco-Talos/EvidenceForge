#!/usr/bin/env python3
"""Build deterministic production-shape deployment/content scale populations.

The public factory is consumed by the unified foundation workload. It retains
metadata and canonical identity only: no executable or file payload bytes are
constructed or stored.
"""

from __future__ import annotations

from array import array
from collections.abc import Iterator
from typing import Literal

from evidenceforge.events.content_identity import (
    ApplicationProfileIdentity,
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    FileContentIdentity,
    InstalledSoftwareReleaseIdentity,
    LocalArtifactIdentity,
    PeVersionInfo,
    SoftwareInstallationIdentity,
    UserProfileIdentity,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    HostDeploymentSpec,
    UserApplicationAssignmentSpec,
)

_CANONICAL_FAMILIES = (
    "binary_releases",
    "installed_software_releases",
    "installations",
    "user_profiles",
    "application_profiles",
    "file_versions",
    "local_artifact_versions",
    "host_deployments",
    "user_application_assignments",
    "service_identities",
    "task_identities",
)


def deployment_population_family_counts(requested_logical: int) -> dict[str, int]:
    """Allocate an exact requested physical denominator across all row families.

    Eleven is the minimum valid population because every canonical family must
    be represented. Remainders are assigned in dependency order, ensuring that
    release/installation/profile rows are never fewer than dependent rows.
    """

    if requested_logical < len(_CANONICAL_FAMILIES):
        raise ValueError(
            "deployment population requires at least 11 physical records so every "
            "canonical family is represented"
        )
    base, remainder = divmod(requested_logical, len(_CANONICAL_FAMILIES))
    return {
        family: base + int(ordinal < remainder)
        for ordinal, family in enumerate(_CANONICAL_FAMILIES)
    }


def _hostname(ordinal: int) -> str:
    return f"scale-host-{ordinal:012d}"


def _principal(ordinal: int) -> str:
    return f"scale-user-{ordinal:012d}"


def _product_id(ordinal: int) -> str:
    return f"scale-product-{ordinal:012d}"


def build_deployment_population(
    requested_logical: int,
    *,
    profile_shape: Literal["uniform", "skewed"] = "uniform",
) -> DeploymentContentRegistry:
    """Return an exact-N immutable registry spanning every canonical family.

    Identity iterators are consumed in dependency order by
    :class:`DeploymentContentRegistry`. Only compact semantic IDs and primitive
    dependency ordinals are retained while later families are generated, so the
    fixture does not keep a second copy of canonical value rows after compile.
    """

    if profile_shape not in {"uniform", "skewed"}:
        raise ValueError("deployment profile_shape must be 'uniform' or 'skewed'")
    counts = deployment_population_family_counts(requested_logical)
    release_ids: list[str] = []
    release_content_ids: list[str] = []
    profile_ids: list[str] = []
    installation_ids: list[str] = []
    installation_profile_ordinals = array("I")
    installation_host_ordinals = array("I")
    application_profile_ids: list[str] = []
    application_profile_installation_ordinals = array("I")
    file_content_ids: list[str] = []
    host_installation_ids: list[list[str]] = [[] for _ordinal in range(counts["host_deployments"])]

    def binary_releases() -> Iterator[BinaryReleaseIdentity]:
        for ordinal in range(counts["binary_releases"]):
            product_id = _product_id(ordinal)
            artifact_name = "scale-app.exe"
            release = BinaryReleaseIdentity(
                key=BinaryReleaseKey(
                    product_id=product_id,
                    version=f"1.{ordinal}.0",
                    build=f"1.{ordinal}.0.0",
                    architecture="x64",
                    platform="windows",
                    artifact_name=artifact_name,
                    variant="stable",
                ),
                pe_version_info=PeVersionInfo(
                    file_version=f"1.{ordinal}.0.0",
                    description="EvidenceForge scale application",
                    product="EvidenceForge Scale Application",
                    company="EvidenceForge Scale Fixture",
                    original_filename=artifact_name,
                ),
            )
            release_ids.append(release.release_id)
            release_content_ids.append(release.content_id)
            yield release

    def installed_releases() -> Iterator[InstalledSoftwareReleaseIdentity]:
        for ordinal in range(counts["installed_software_releases"]):
            yield InstalledSoftwareReleaseIdentity(
                product_id=_product_id(ordinal),
                name=f"Scale Product {ordinal:012d}",
                publisher="EvidenceForge Scale Fixture",
                version=f"1.{ordinal}.0",
                build=f"1.{ordinal}.0.0",
                architecture="x64",
                platform="windows",
                scope="user",
            )

    def user_profiles() -> Iterator[UserProfileIdentity]:
        host_count = counts["host_deployments"]
        for ordinal in range(counts["user_profiles"]):
            profile = UserProfileIdentity(
                hostname=_hostname(ordinal % host_count),
                principal=_principal(ordinal),
                platform="windows",
                profile_root=rf"C:\Users\{_principal(ordinal)}",
            )
            profile_ids.append(profile.profile_id)
            yield profile

    def installations() -> Iterator[SoftwareInstallationIdentity]:
        host_count = counts["host_deployments"]
        profile_count = counts["user_profiles"]
        for ordinal in range(counts["installations"]):
            profile_ordinal = 0 if profile_shape == "skewed" else ordinal % profile_count
            host_ordinal = profile_ordinal % host_count
            product_ordinal = ordinal % len(release_ids)
            product_id = _product_id(product_ordinal)
            principal = _principal(profile_ordinal)
            installation = SoftwareInstallationIdentity(
                hostname=_hostname(host_ordinal),
                application_id=product_id,
                release_id=release_ids[product_ordinal],
                platform="windows",
                scope="user",
                principal=principal,
                user_profile_id=profile_ids[profile_ordinal],
                install_root=rf"C:\Users\{principal}\Apps\{product_id}",
                image_paths=(rf"C:\Users\{principal}\Apps\{product_id}\scale-app.exe",),
            )
            installation_ids.append(installation.installation_id)
            installation_profile_ordinals.append(profile_ordinal)
            installation_host_ordinals.append(host_ordinal)
            host_installation_ids[host_ordinal].append(installation.installation_id)
            yield installation

    def application_profiles() -> Iterator[ApplicationProfileIdentity]:
        for ordinal in range(counts["application_profiles"]):
            installation_ordinal = ordinal % len(installation_ids)
            profile_ordinal = installation_profile_ordinals[installation_ordinal]
            host_ordinal = installation_host_ordinals[installation_ordinal]
            product_id = _product_id(installation_ordinal % len(release_ids))
            profile = ApplicationProfileIdentity(
                hostname=_hostname(host_ordinal),
                principal=_principal(profile_ordinal),
                platform="windows",
                user_profile_id=profile_ids[profile_ordinal],
                installation_id=installation_ids[installation_ordinal],
                application_id=product_id,
                profile_root=(
                    rf"C:\Users\{_principal(profile_ordinal)}\AppData\Roaming\{product_id}"
                ),
            )
            application_profile_ids.append(profile.application_profile_id)
            application_profile_installation_ordinals.append(installation_ordinal)
            yield profile

    def file_contents() -> Iterator[FileContentIdentity]:
        for ordinal in range(counts["file_versions"]):
            content = FileContentIdentity(
                file_object_id=f"scale-file-{ordinal:012d}",
                version=1,
                size_bytes=4_096 + ordinal,
                mime_type="application/octet-stream",
            )
            file_content_ids.append(content.content_id)
            yield content

    def local_artifacts() -> Iterator[LocalArtifactIdentity]:
        for ordinal in range(counts["local_artifact_versions"]):
            application_ordinal = ordinal % len(application_profile_ids)
            installation_ordinal = application_profile_installation_ordinals[application_ordinal]
            profile_ordinal = installation_profile_ordinals[installation_ordinal]
            host_ordinal = installation_host_ordinals[installation_ordinal]
            product_id = _product_id(installation_ordinal % len(release_ids))
            principal = _principal(profile_ordinal)
            yield LocalArtifactIdentity(
                hostname=_hostname(host_ordinal),
                principal=principal,
                platform="windows",
                user_profile_id=profile_ids[profile_ordinal],
                application_profile_id=application_profile_ids[application_ordinal],
                application_id=product_id,
                family="cache",
                source_object_id=f"scale-source-{ordinal:012d}",
                native_path=(
                    rf"C:\Users\{principal}\AppData\Local\{product_id}"
                    rf"\cache\artifact-{ordinal:012d}.bin"
                ),
                content_id=file_content_ids[ordinal % len(file_content_ids)],
                version=1,
            )

    def host_deployments() -> Iterator[HostDeploymentSpec]:
        service_count = counts["service_identities"]
        task_count = counts["task_identities"]
        host_count = counts["host_deployments"]
        for ordinal in range(host_count):
            service_ids = tuple(
                f"scale-service-{service_ordinal:012d}"
                for service_ordinal in range(ordinal, service_count, host_count)
            )
            task_ids = tuple(
                f"scale-task-{task_ordinal:012d}"
                for task_ordinal in range(ordinal, task_count, host_count)
            )
            yield HostDeploymentSpec(
                hostname=_hostname(ordinal),
                roles=("workstation",),
                platform="windows",
                os_build="22631.3880",
                architecture="x64",
                installation_ids=tuple(host_installation_ids[ordinal]),
                service_ids=service_ids,
                task_ids=task_ids,
                module_content_ids=(release_content_ids[ordinal % len(release_content_ids)],),
            )

    def assignments() -> Iterator[UserApplicationAssignmentSpec]:
        for ordinal in range(counts["user_application_assignments"]):
            application_ordinal = ordinal % len(application_profile_ids)
            installation_ordinal = application_profile_installation_ordinals[application_ordinal]
            profile_ordinal = installation_profile_ordinals[installation_ordinal]
            host_ordinal = installation_host_ordinals[installation_ordinal]
            yield UserApplicationAssignmentSpec(
                hostname=_hostname(host_ordinal),
                principal=_principal(profile_ordinal),
                platform="windows",
                user_profile_id=profile_ids[profile_ordinal],
                application_profile_id=application_profile_ids[application_ordinal],
                persona="knowledge_worker",
                eligible_categories=("browser", "user_app"),
                intensity=1.0,
                selection_weight=10,
                selection_ordinal=ordinal,
            )

    registry = DeploymentContentRegistry(
        binary_releases=binary_releases(),
        installed_software_releases=installed_releases(),
        user_profiles=user_profiles(),
        installations=installations(),
        application_profiles=application_profiles(),
        host_deployments=host_deployments(),
        user_application_assignments=assignments(),
        file_contents=file_contents(),
        local_artifacts=local_artifacts(),
    )
    census = registry.scale_census()
    if census.physical_records != requested_logical:
        raise AssertionError(
            "deployment population compiler produced a physical denominator "
            f"of {census.physical_records}, expected {requested_logical}"
        )
    return registry


__all__ = [
    "build_deployment_population",
    "deployment_population_family_counts",
]
