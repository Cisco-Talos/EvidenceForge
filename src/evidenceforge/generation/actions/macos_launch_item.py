# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded launchd system-domain registration on the shared service lifecycle.

This internal preparation boundary represents an accepted launchd bootstrap only.
It does not write a plist, approve a background item, activate a job, allocate a
process or render native logs. A higher-level bundle must own those distinct
occurrences before this boundary is exposed to scenario authoring.
"""

import shlex
from datetime import datetime

from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.lifecycle import (
    LogicalServiceIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceProcessBindingIdentity,
)
from evidenceforge.events.macos_launchd import (
    LaunchdSystemJobDefinition,
    LaunchdSystemJobSpec,
    validate_launchd_label,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    ServiceLifecyclePublicationPlan,
    service_boot_id,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import ProcessMaterializationPlan
from evidenceforge.models.exceptions import StateError
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


def macos_system_job_activation_plan(
    *,
    lifecycle_registry: LifecycleRegistry,
    lifecycle_authority: GeneratorLifecycleAuthority,
    service_object_id: str,
    process_plan: ProcessMaterializationPlan,
    action_id: str,
) -> ServiceLifecyclePublicationPlan:
    """Bind an authenticated root job launch to an already loaded definition.

    The returned plan must use the shared process/service composite commit.
    It publishes neither State nor evidence by itself. UserName credential
    transitions, GUI agents and automatic trigger scheduling remain unsupported.
    """
    if not action_id or action_id != action_id.strip():
        raise ValueError("Launchd activation requires an exact action ID")
    snapshot = lifecycle_registry.get_service_instance(service_object_id)
    if snapshot is None or snapshot.identity.launchd_job is None:
        raise StateError("Launchd activation requires a retained loaded system job")
    if snapshot.closed_at is not None or snapshot.close_barrier is not None:
        raise StateError("Launchd activation cannot reopen an unloading or unloaded job")
    definition = snapshot.identity.launchd_job
    identity = process_plan.identity
    parent = process_plan.parent_identity
    credentials = identity.credentials
    if definition.principal != "root":
        raise StateError("This launchd activation profile requires an explicit root job")
    if (
        identity.hostname != snapshot.identity.hostname
        or identity.image != definition.program
        or identity.command_line != shlex.join(definition.arguments)
        or identity.principal != definition.principal
        or identity.logon_id
        or identity.started_at < snapshot.identity.started_at
        or identity.execution_ordinal != 0
        or identity.audit_pid_version is None
        or credentials is None
        or (
            credentials.real_uid,
            credentials.effective_uid,
            credentials.real_gid,
            credentials.effective_gid,
        )
        != (0, 0, 0, 0)
    ):
        raise StateError("Launchd activation process must match the loaded root job definition")
    if (
        parent is None
        or parent.pid != 1
        or parent.image != "/sbin/launchd"
        or parent.hostname != identity.hostname
        or parent.principal != "root"
        or parent.credentials is None
        or (
            parent.credentials.real_uid,
            parent.credentials.effective_uid,
            parent.credentials.real_gid,
            parent.credentials.effective_gid,
        )
        != (0, 0, 0, 0)
        or parent.audit_pid_version is None
    ):
        raise StateError("Launchd system job requires its exact modeled launchd parent")
    start = lifecycle_registry.transition(
        stable_uuid("macos-launchd-registration-start", service_object_id)
    )
    if start is None or start.subject != snapshot.identity.ref or start.kind != "started":
        raise StateError("Launchd activation is missing its authenticated bootstrap transition")
    binding = ServiceProcessBindingIdentity(
        binding_id=stable_uuid(
            "macos-launchd-process-binding", service_object_id, identity.object_id
        ),
        service_object_id=service_object_id,
        process_object_id=identity.object_id,
        bound_at=identity.started_at,
        role="launchd_job",
        action_id=action_id,
    )
    return ServiceLifecyclePublicationPlan(
        logical_identity=snapshot.logical_identity,
        instance_identity=snapshot.identity,
        action_id=start.action_id,
        transition_id=start.transition_id,
        transition_ordinal=start.transition_ordinal,
        process_bindings=(binding,),
        staged_process_bindings=(
            lifecycle_authority.service_staged_process_binding_member(process_plan, binding),
        ),
    )
