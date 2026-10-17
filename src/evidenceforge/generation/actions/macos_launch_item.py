# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded launchd system-domain registration on the shared service lifecycle.

This internal preparation boundary represents an accepted launchd bootstrap only.
It does not write a plist, approve a background item, activate a job, allocate a
process or render native logs. A higher-level bundle must own those distinct
occurrences before this boundary is exposed to scenario authoring.
"""

import shlex
from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LogicalServiceIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceProcessBindingIdentity,
)
from evidenceforge.events.macos_launchd import (
    LaunchdSystemJobDefinition,
    LaunchdSystemJobSpec,
    validate_launchd_label,
)
from evidenceforge.generation.actions.command_effects import FileEffectAction, FileEffectIntent
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectSpec,
    EndpointStateDisposition,
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactPublishToken,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    ServiceLifecyclePublicationPlan,
    service_boot_id,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceProcessBindingClosure,
    LifecycleServiceProcessClosureRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import (
    ProcessMaterializationPlan,
    ProcessTerminationMaterializationPlan,
    StateManager,
)
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
    return spec.content_seed


def macos_system_job_definition_from_file(
    *,
    runtime_content: RuntimeContentIdentityManager,
    deployment_identity: RuntimeServiceDeploymentIdentity,
    principal: str,
    native_path: str,
) -> LaunchdSystemJobDefinition:
    """Read the modeled job semantics from the current retained file version."""
    record = runtime_content.resolve_record(
        deployment_identity.hostname, principal, native_path, "macos"
    )
    if record is None or record.launchd_job is None:
        raise ValueError("Launchd bootstrap requires a current file with bounded job semantics")
    logical_id = stable_uuid(
        "macos-launchd-system-job", record.artifact.hostname, record.launchd_job.label
    )
    if deployment_identity.canonical_name != f"macos-launchd-system:{logical_id}":
        raise ValueError("Launchd file label must match its exact installation")
    return LaunchdSystemJobDefinition(
        **record.launchd_job.model_dump(),
        installation=deployment_identity,
        plist=record.artifact,
    )


def macos_system_job_write_effect(
    *,
    publication: LocalArtifactPublishToken,
    action: FileEffectAction,
    instance_key: str,
    retention_deadline: datetime,
) -> PreparedEndpointEffect:
    """Bind an exact reserved job file to the shared process-owned effect path.

    The caller owns writer identity, scheduling and token cancellation if root
    preflight fails. The ordinary process bundle owns atomic canonical file and
    source publication. Writing a definition does not bootstrap or run a job.
    """
    retention_deadline = ensure_utc(retention_deadline)
    if retention_deadline > publication.retained_until:
        raise ValueError("Launchd write retention cannot exceed its reserved file lifetime")
    record = publication.record
    if record.artifact.platform != "macos" or record.launchd_job is None:
        raise ValueError("Launchd write requires canonical Mac job file metadata")
    if action not in {FileEffectAction.CREATE, FileEffectAction.MODIFY}:
        raise ValueError("Launchd write action must be create or modify")
    return PreparedEndpointEffect(
        spec=EndpointEffectSpec(
            intent=FileEffectIntent(action=action, path=record.artifact.native_path),
            occurrence_times=(publication.observed_at,),
            instance_key=instance_key,
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=retention_deadline,
        ),
        event_type="file_create" if action == FileEffectAction.CREATE else "file_modify",
        payload=PreparedFileEffectPayload(
            path=record.artifact.native_path,
            action=action,
            artifact_publication=publication,
        ),
    )


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
        or record.launchd_job is None
        or record.launchd_job.content_seed != definition.content_seed
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


@dataclass(frozen=True, slots=True)
class MacosSystemJobUnloadPlan:
    """Explicit terminal unload closure, separate from its request and file removal."""

    closure: LifecycleServiceProcessClosureRequest
    process: ProcessTerminationMaterializationPlan | None = None


def macos_system_job_unload_completion_plan(
    *,
    lifecycle_registry: LifecycleRegistry,
    state_manager: StateManager,
    service_object_id: str,
    completed_at: datetime,
    action_id: str,
) -> MacosSystemJobUnloadPlan:
    """Prepare a dormant or single-process job's terminal unload transition.

    The caller owns the completed outcome and its timing. This adapter does not
    infer SIGTERM delivery, process groups, escalation delays or native messages.
    A process-bearing plan must use the shared process/service closure composite;
    a dormant plan uses the ordinary prepared service closure. Child processes
    require a separate supported group/lifecycle owner and are rejected here.
    """
    if not action_id or action_id != action_id.strip():
        raise ValueError("Launchd unload requires an exact action ID")
    completed_at = ensure_utc(completed_at)
    snapshot = lifecycle_registry.get_service_instance(service_object_id)
    if snapshot is None or snapshot.identity.launchd_job is None:
        raise StateError("Launchd unload requires a retained loaded system job")
    if snapshot.closed_at is not None or snapshot.close_barrier is not None:
        raise StateError("Launchd unload requires a live job without another close intent")
    if completed_at < snapshot.identity.started_at:
        raise StateError("Launchd unload cannot precede bootstrap")

    def control(subject: LifecycleEntityRef) -> LifecycleSubjectClosureControl:
        return LifecycleSubjectClosureControl(
            barrier=LifecycleCloseBarrier(
                barrier_id=stable_uuid(
                    "macos-launchd-unload-barrier", action_id, subject.kind, subject.object_id
                ),
                subject=subject,
                requested_at=completed_at,
                authority="generated",
                action_id=action_id,
            ),
            ticket_id=stable_uuid(
                "macos-launchd-unload-ticket", action_id, subject.kind, subject.object_id
            ),
        )

    bindings, more = lifecycle_registry.service_process_binding_page(
        service_object_id=service_object_id, limit=2
    )
    if more is not None or len(bindings) > 1:
        raise StateError("Launchd unload profile requires at most one active job process")
    service_close = control(snapshot.identity.ref)
    if not bindings:
        return MacosSystemJobUnloadPlan(
            closure=LifecycleServiceProcessClosureRequest(
                binding_closures=(), service_closures=(service_close,)
            )
        )
    binding = bindings[0].identity
    process_snapshot = lifecycle_registry.get_process(binding.process_object_id)
    if process_snapshot is None or process_snapshot.closed_at is not None:
        raise StateError("Launchd unload requires its exact live bound process")
    children, more_children = lifecycle_registry.live_child_process_page(
        binding.process_object_id, limit=1
    )
    if children or more_children is not None:
        raise StateError("Launchd unload of child processes requires process-group ownership")
    process = state_manager.plan_process_termination_materialization(
        system=snapshot.identity.hostname,
        pid=process_snapshot.identity.pid,
        end_time=completed_at,
    )
    if process.identity.object_id != binding.process_object_id:
        raise StateError("Launchd unload cannot substitute a reused process ID")
    if completed_at < binding.bound_at:
        raise StateError("Launchd unload cannot precede process activation")
    return MacosSystemJobUnloadPlan(
        process=process,
        closure=LifecycleServiceProcessClosureRequest(
            binding_closures=(
                LifecycleServiceProcessBindingClosure(
                    identity=binding, closed_at=completed_at, action_id=action_id
                ),
            ),
            process_closures=(control(process_snapshot.identity.ref),),
            service_closures=(service_close,),
        ),
    )
