# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded launchd system-domain registration on the shared service lifecycle.

This internal preparation boundary represents an accepted launchd bootstrap only.
It does not write a plist, approve a background item, activate a job, allocate a
process or render native logs. A higher-level bundle must own those distinct
occurrences before this boundary is exposed to scenario authoring.
"""

from datetime import datetime

from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.lifecycle import LogicalServiceIdentity, ServiceInstanceLifecycleIdentity
from evidenceforge.events.macos_launchd import (
    LaunchdSystemJobDefinition,
    LaunchdSystemJobSpec,
    validate_launchd_label,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.lifecycle_production_adapters import (
    ServiceLifecyclePublicationPlan,
    service_boot_id,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc


def macos_system_job_deployment_identity(
    *,
    deployment_registry: DeploymentContentRegistry,
    hostname: str,
    label: str,
    installation_action_id: str,
) -> RuntimeServiceDeploymentIdentity:
    """Prepare a stable installation identity for subsequent registrations."""
    host = deployment_registry.host_deployment(hostname)
    if host is None or host.platform != "macos" or host.architecture != "arm64":
        raise ValueError("Launchd registration requires a compiled arm64 Mac host")
    validate_launchd_label(label)
    logical_id = stable_uuid("macos-launchd-system-job", host.hostname, label)
    return deployment_registry.runtime_service_deployment_identity(
        hostname=host.hostname,
        canonical_name=f"macos-launchd-system:{logical_id}",
        action_id=installation_action_id,
    )


def macos_system_job_content_seed(spec: LaunchdSystemJobSpec) -> str:
    """Bind modeled file content to the exact bounded job semantics."""
    # Exclude loaded placement/installation fields if passed a loaded definition.
    semantic_spec = LaunchdSystemJobSpec(
        **{name: getattr(spec, name) for name in LaunchdSystemJobSpec.model_fields}
    )
    return stable_uuid("macos-launchd-definition", semantic_spec.model_dump_json())


def macos_system_job_bootstrap_plan(
    *,
    deployment_registry: DeploymentContentRegistry,
    hostname: str,
    label: str,
    boot_time: datetime,
    bootstrapped_at: datetime,
    deployment_identity: RuntimeServiceDeploymentIdentity,
    definition: LaunchdSystemJobDefinition,
    runtime_content: RuntimeContentIdentityManager,
    action_id: str,
) -> ServiceLifecyclePublicationPlan:
    """Prepare a loaded, dormant system job without implying process activation.

    Exact labels enter a Mac-specific semantic key before reaching the shared
    service registry's case-insensitive lookup keys. The existing runtime
    deployment identity uses that opaque key; the logical identity retains the
    readable system-domain target. Re-registration gets a fresh instance from
    its action ID while retaining the logical label identity. The caller supplies
    the canonical modeled host spelling, as with other lifecycle adapters.
    """
    host = deployment_registry.host_deployment(hostname)
    if host is None or host.platform != "macos" or host.architecture != "arm64":
        raise ValueError("Launchd registration requires a compiled arm64 Mac host")
    validate_launchd_label(label)
    if not action_id or action_id != action_id.strip():
        raise ValueError("Launchd registration requires an exact action ID")
    boot_time = ensure_utc(boot_time)
    bootstrapped_at = ensure_utc(bootstrapped_at)
    if bootstrapped_at < boot_time:
        raise ValueError("Launchd registration cannot precede its modeled boot")
    logical_id = stable_uuid("macos-launchd-system-job", host.hostname, label)
    if (
        type(deployment_identity) is not RuntimeServiceDeploymentIdentity
        or deployment_identity.hostname != host.hostname
        or deployment_identity.canonical_name != f"macos-launchd-system:{logical_id}"
        or not deployment_registry.admits_service_deployment_identity(deployment_identity)
    ):
        raise ValueError("Launchd registration requires its exact installed job identity")
    if definition.label != label or definition.installation != deployment_identity:
        raise ValueError("Launchd registration requires its exact loaded installation and label")
    artifact = definition.plist
    record = runtime_content.resolve_record(
        hostname, artifact.principal, artifact.native_path, "macos"
    )
    if (
        record is None
        or record.artifact != artifact
        or record.binary is not None
        or record.content.seed_ref != macos_system_job_content_seed(definition)
    ):
        raise ValueError(
            "Launchd bootstrap requires the current canonical plist content and definition"
        )
    boot_id = service_boot_id(host.hostname, boot_time)
    instance_id = stable_uuid("macos-launchd-registration", logical_id, boot_id, action_id)
    object_id = stable_uuid(
        "lifecycle-service-object", host.hostname, boot_id, logical_id, instance_id
    )
    return ServiceLifecyclePublicationPlan(
        logical_identity=LogicalServiceIdentity(
            hostname=hostname,
            logical_service_id=logical_id,
            canonical_name=f"system/{label}",
            service_kind="launchd",
        ),
        instance_identity=ServiceInstanceLifecycleIdentity(
            hostname=hostname,
            object_id=object_id,
            logical_service_id=logical_id,
            boot_id=boot_id,
            instance_id=instance_id,
            started_at=bootstrapped_at,
            launchd_job=definition,
        ),
        action_id=action_id,
        transition_id=stable_uuid("macos-launchd-registration-start", object_id),
    )
