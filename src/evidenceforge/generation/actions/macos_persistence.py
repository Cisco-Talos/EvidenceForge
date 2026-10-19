# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit system-domain persistence stages using shared publication owners.

A stage is a modeled completed operation. Registration, activation, process exit,
unload and file removal remain distinct; none implies native policy evidence.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import BinaryReleaseIdentity, LocalArtifactBinaryIdentity
from evidenceforge.events.contexts import FileContext, HostContext, ProcessContext
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedDispatch,
    PreparedDispatchStateIntent,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.actions.command_effects import (
    ActionAnchor,
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.macos_launch_item import (
    MacosSystemJobGroupUnloadPlan,
    macos_system_job_bootstrap_plan,
    macos_system_job_definition_from_file,
    macos_system_job_deployment_identity,
    macos_system_job_launch_plan,
    macos_system_job_leader_exit_completion_plan,
    macos_system_job_unload_completion_plan,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactPublishToken,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.runtime_content import (
    RuntimeContentIdentityManager,
    runtime_executable_lease_owner,
)
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid


@dataclass(frozen=True, slots=True)
class MacosPersistenceRequest:
    """An exact root caller requests one explicitly completed system-job operation."""

    caller: ProcessIdentity
    host: HostContext
    timestamp: datetime
    action_id: str
    operation: Literal["write", "bootstrap", "activate", "exit", "unload", "remove"]
    label: str
    path: str | None = None
    definition: LaunchdSystemJobSpec | None = None
    version: int = 1
    size_bytes: int | None = None
    exit_code: int | None = None

    def __post_init__(self) -> None:
        if self.operation not in {"write", "bootstrap", "activate", "exit", "unload", "remove"}:
            raise ValueError("Unknown system-job operation")
        if not self.action_id or not self.label or self.timestamp.tzinfo is None:
            raise ValueError("System-job operation requires identity and an aware timestamp")
        if self.operation in {"write", "bootstrap", "remove"}:
            if (
                self.path is None
                or not self.path.startswith("/Library/LaunchDaemons/")
                or not self.path.endswith(".plist")
                or any(part in {"", ".", ".."} for part in self.path.split("/")[1:])
                or "\\" in self.path
                or any(ord(char) < 32 for char in self.path)
            ):
                raise ValueError(
                    "System-job file stage requires a canonical LaunchDaemons plist path"
                )
        elif self.path is not None:
            raise ValueError("Loaded job stages do not accept a file path")
        if self.operation == "write":
            if (
                self.definition is None
                or self.definition.label != self.label
                or self.definition.principal != "root"
                or type(self.size_bytes) is not int
                or self.size_bytes <= 0
                or type(self.version) is not int
                or self.version <= 0
            ):
                raise ValueError(
                    "System-job write requires an exact root definition, size and version"
                )
        elif self.definition is not None or self.size_bytes is not None or self.version != 1:
            raise ValueError("Only write accepts definition, size and version")
        if self.exit_code is not None and (
            self.operation != "exit"
            or type(self.exit_code) is not int
            or not 0 <= self.exit_code <= 255
        ):
            raise ValueError("Only exit accepts a normal POSIX exit code")


def _context(identity: ProcessIdentity, state: StateManager) -> ProcessContext:
    parent_ref = identity.parentage.current if identity.parentage is not None else None
    parent = (
        state.get_process_identity_by_object_id(parent_ref.object_id)
        if parent_ref is not None
        else None
    )
    return ProcessContext(
        pid=identity.pid,
        parent_pid=identity.parent_pid,
        parent_image=parent.image if parent is not None else "",
        image=identity.image,
        command_line=identity.command_line,
        username=identity.principal,
        logon_id=identity.logon_id,
        start_time=identity.started_at,
        integrity_level="System",
    )


@dataclass(frozen=True, slots=True)
class MacosPersistenceResult:
    """Exact effects completed by a stage, independent of source collection."""

    process: ProcessIdentity | None = None
    terminated: tuple[ProcessIdentity, ...] = ()
    file_action: Literal["create", "modify", "delete"] | None = None

    @property
    def observable(self) -> bool:
        """Whether this stage has a supported canonical source projection."""
        return self.process is not None or bool(self.terminated) or self.file_action is not None


class MacosPersistenceActionBundle:
    """Compose retained file, service and process stages without native-log shortcuts."""

    def __init__(
        self,
        *,
        state: StateManager,
        lifecycle: LifecycleRegistry,
        authority: GeneratorLifecycleAuthority,
        dispatcher: EventDispatcher,
        deployments: DeploymentContentRegistry,
        content: RuntimeContentIdentityManager,
    ) -> None:
        self.state = state
        self.lifecycle = lifecycle
        self.authority = authority
        self.dispatcher = dispatcher
        self.deployments = deployments
        self.content = content
        self.services = LifecycleProductionAdapter(lifecycle)

    def execute(self, request: MacosPersistenceRequest) -> MacosPersistenceResult:
        """Complete one stage; successful file/process sources use canonical owners."""
        caller = request.caller
        credentials = caller.credentials
        if (
            request.host.os_category != "macos"
            or caller.hostname != request.host.hostname
            or caller.principal != "root"
            or credentials is None
            or credentials.effective_uid != 0
            or self.state.get_process(caller.hostname, caller.pid) is None
            or not self.state.is_process_active_at(caller.hostname, caller.pid, request.timestamp)
            or self.state.get_process_identity(caller.hostname, caller.pid) != caller
            or request.timestamp < caller.execution_started_at
        ):
            raise StateError("System launch-item operations require an exact live Mac root caller")
        host = self.deployments.host_deployment(caller.hostname)
        if host is None or host.platform != "macos" or host.architecture != "arm64":
            raise StateError("Launch-item operation requires a compiled arm64 Mac deployment")
        if request.operation in {"write", "remove"}:
            return MacosPersistenceResult(file_action=self._file(request))
        logical_id = stable_uuid("macos-launchd-system-job", host.hostname, request.label)
        if request.operation == "bootstrap":
            self._bootstrap(request)
            return MacosPersistenceResult()
        job = self.lifecycle.service_for_logical_at(caller.hostname, logical_id, request.timestamp)
        if job is None or job.identity.launchd_job is None:
            raise StateError("Launch-item operation requires its currently loaded system job")
        if request.operation == "activate":
            binary = self.dispatcher.resolve_process_binary_identity(
                host.hostname,
                job.identity.launchd_job.principal,
                job.identity.launchd_job.program,
                "macos",
            )
            version = (
                ProcessExecutableVersion.from_binary(binary)
                if type(binary) in {BinaryReleaseIdentity, LocalArtifactBinaryIdentity}
                else None
            )
            plan = macos_system_job_launch_plan(
                lifecycle_registry=self.lifecycle,
                lifecycle_authority=self.authority,
                state_manager=self.state,
                service_object_id=job.identity.object_id,
                started_at=request.timestamp,
                action_id=request.action_id,
                executable_version=version,
            )
            identity = plan.process.identity
            process_context = _context(identity, self.state)
            if version is not None:
                process_context.binary_identity = binary
            event = OccurrenceBuilder(
                timestamp=identity.started_at,
                event_type="process_create",
                src_host=request.host,
                process=process_context,
                identity_plan=EventIdentityPlan(subject=identity),
                lifecycle=ActionLifecycleContext(
                    group_id=identity.lifecycle_group_id,
                    canonical_start=identity.started_at,
                    phase="start",
                    parent_group_id=identity.parent_lifecycle_group_id or None,
                ),
                storyline_origin=True,
            )
            retention = None
            horizon = self.dispatcher.output_end_time
            if (
                type(binary) is LocalArtifactBinaryIdentity
                and horizon is not None
                and horizon.replace(tzinfo=None) != datetime.max
                and horizon > request.timestamp
            ):
                retained_until = self.state.process_history_retained_until(horizon)
                retention = self.content.registry.prepare_version_retention(
                    binary.artifact_version_id,
                    observed_at=request.timestamp,
                    retained_until=retained_until,
                    lease_owner=runtime_executable_lease_owner(identity.hostname, retained_until),
                )
            try:
                prepared = self.dispatcher.prepare_builder(
                    event,
                    state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_START,
                    lifecycle_ticket=plan.process,
                    artifact_publications=(retention,) if retention is not None else (),
                )
                self.dispatcher.validate_prepared(prepared)
                if retention is None:
                    proof = self.authority.materialize_process_service_composite(
                        plan.process, self.services.prepare_service_publication(plan.activation)
                    )
                else:
                    with self.content.registry.prepared_publication(retention) as publication:
                        proof = self.authority.materialize_process_service_composite(
                            plan.process,
                            self.services.prepare_service_publication(plan.activation),
                            commit_external_first=publication.commit_no_fail,
                        )
            finally:
                if retention is not None:
                    self.content.registry.cancel_prepared(retention)
            self.dispatcher.publish_prepared(
                prepared, materialization_receipt=proof.receipt.process_receipt
            )
            return MacosPersistenceResult(process=identity)
        if request.operation == "exit":
            close = macos_system_job_leader_exit_completion_plan(
                lifecycle_registry=self.lifecycle,
                state_manager=self.state,
                service_object_id=job.identity.object_id,
                completed_at=request.timestamp,
                action_id=request.action_id,
                exit_outcome=PosixProcessExit(exit_code=request.exit_code)
                if request.exit_code is not None
                else None,
            )
            plans = close.cohort.process_terminations
        elif request.operation == "unload":
            close = macos_system_job_unload_completion_plan(
                lifecycle_registry=self.lifecycle,
                state_manager=self.state,
                service_object_id=job.identity.object_id,
                completed_at=request.timestamp,
                action_id=request.action_id,
            )
            if not isinstance(close, MacosSystemJobGroupUnloadPlan):
                if close.process is not None:
                    raise StateError("Authored job unload requires explicit group ownership")
                token = self.services.prepare_service_process_closure(close.closure)
                with self.services.claimed_service_process_closure(token) as claimed:
                    claimed.commit_no_fail()
                return MacosPersistenceResult()
            plans = close.cohort.process_terminations
        else:
            raise StateError("Unsupported launch-item operation")
        dispatches: list[PreparedDispatch] = []
        terminated: list[ProcessIdentity] = []
        for plan in plans:
            identity = self.state.get_process_identity_by_object_id(plan.target.identity.object_id)
            live = (
                self.state.get_process(identity.hostname, identity.pid)
                if identity is not None
                else None
            )
            if identity is None or live is None or live.ecar_object_id != identity.object_id:
                raise StateError("Job closure lost its exact live process")
            terminated.append(identity)
            event = process_exit_occurrence(
                host=request.host,
                process=identity,
                timestamp=plan.end_time,
                integrity_level=live.integrity_level,
            )
            event.process.exit_outcome = plan.target.exit_outcome
            event.storyline_origin = True
            prepared = self.dispatcher.prepare_builder(
                event,
                state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE,
                lifecycle_ticket=plan.target,
            )
            self.dispatcher.validate_prepared(prepared)
            dispatches.append(prepared)
        token = self.services.prepare_service_process_closure(close.closure)
        if request.operation == "exit":
            proof = self.authority.materialize_process_group_leader_exit_composite(
                close.cohort, close.group, token
            )
        else:
            proof = self.authority.materialize_process_group_service_closure_composite(
                close.cohort, close.group, token
            )
        for prepared in dispatches:
            self.dispatcher.publish_prepared(prepared, materialization_receipt=proof)
        return MacosPersistenceResult(terminated=tuple(terminated))

    def _bootstrap(self, request: MacosPersistenceRequest) -> None:
        if request.path is None:
            raise StateError("Launch-item bootstrap requires its retained plist path")
        record = self.content.resolve_record(request.caller.hostname, "root", request.path, "macos")
        if record is None:
            raise StateError("Launch-item bootstrap requires a current definition file")
        installation = macos_system_job_deployment_identity(
            deployment_registry=self.deployments,
            hostname=request.caller.hostname,
            label=request.label,
            installation_action_id=record.artifact.artifact_id,
        )
        definition = macos_system_job_definition_from_file(
            runtime_content=self.content,
            deployment_identity=installation,
            principal="root",
            native_path=request.path,
        )
        plan = macos_system_job_bootstrap_plan(
            deployment_registry=self.deployments,
            hostname=request.caller.hostname,
            label=request.label,
            deployment_identity=installation,
            definition=definition,
            runtime_content=self.content,
            boot_time=self.state.get_boot_time(request.caller.hostname),
            bootstrapped_at=request.timestamp,
            action_id=request.action_id,
        )
        token = self.services.prepare_service_publication(plan)
        with self.services.claimed_service_publication(token) as claimed:
            claimed.commit_no_fail()

    def _file(self, request: MacosPersistenceRequest) -> Literal["create", "modify", "delete"]:
        if request.path is None:
            raise StateError("Launch-item file operation requires a native path")
        current = self.content.resolve_record(
            request.caller.hostname, "root", request.path, "macos"
        )
        token: LocalArtifactPublishToken
        if request.operation == "remove":
            if (
                current is None
                or current.launchd_job is None
                or current.launchd_job.label != request.label
            ):
                raise StateError("Launch-item removal requires its current definition file")
            token = self.content.registry.prepare_publish_version(
                current, request.timestamp, withdraw_placement=True
            )
            kind, action = "file_delete", "delete"
        else:
            if (
                request.definition is None
                or request.definition.label != request.label
                or request.size_bytes is None
            ):
                raise StateError("Launch-item write requires exact definition and size")
            action = "modify" if current is not None else "create"
            token = self.content.prepare_effect_publication(
                root_action_id=request.action_id,
                stable_source_id=stable_uuid(
                    "macos-launchd-file", request.caller.hostname, request.path, request.label
                ),
                hostname=request.caller.hostname,
                principal="root",
                platform="macos",
                architecture="arm64",
                native_path=request.path,
                action=action,
                observed_at=request.timestamp,
                owner_kind="system",
                authored_size_bytes=request.size_bytes,
                authored_mime_type="application/xml",
                launchd_job=request.definition,
                content_version=request.version,
                artifact_version=request.version,
            )
            if token is None:
                raise StateError("Launch-item write did not reserve its file")
            kind = "file_modify" if current is not None else "file_create"
        timing: SourceTimingPreparation | None = None
        try:
            builder = self.state.begin_action_cohort_materialization()
            builder.patch_process_activity(request.caller, request.timestamp)
            state_plan = builder.seal()
            effect = OwnedEffectOccurrencePlan(
                owner=EffectOccurrenceOwner.MACOS_LAUNCH_ITEM_FILE,
                kind=EffectOccurrenceKind.FILE,
                root_action_id=request.action_id,
                instance_key=request.path,
                occurrence_count=1,
            )
            event = OccurrenceBuilder(
                effect_provenance=effect.provenance(0),
                timestamp=request.timestamp,
                event_type=kind,
                src_host=request.host,
                process=_context(request.caller, self.state),
                file=FileContext(path=request.path, action=action, pid=request.caller.pid),
                identity_plan=EventIdentityPlan(actor=request.caller),
                storyline_origin=True,
                lifecycle=ActionLifecycleContext(
                    group_id=request.caller.lifecycle_group_id,
                    canonical_start=request.caller.started_at,
                    phase="dependent",
                    parent_group_id=request.caller.parent_lifecycle_group_id or None,
                ),
            )
            audit = ExecutionEffectPlan(
                ActionAnchor("macos_launch_item", request.action_id, source="storyline"), ()
            )
            with self.dispatcher.source_timing_planner.prepared_planning() as timing:
                prepared = self.dispatcher.prepare_builder(
                    event,
                    state_intent=PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT,
                    lifecycle_ticket=state_plan,
                    artifact_publications=(token,),
                    source_timing_preparation=timing,
                )
            batch = self.dispatcher.prepare_action_cohort_batch(
                request.action_id,
                state_plan,
                (prepared,),
                (ExecutionEffectAuditCohortEntry(audit, audit.reconcile(())),),
                (),
                (),
                owned_effect_plans=(effect,),
            )
            result = self.dispatcher.publish_prepared_action_cohort_batch(batch)
            for error in result.projection_errors:
                if error is not None:
                    raise error
            return action
        finally:
            if timing is not None and not timing.committed:
                timing.cancel()
            if self.content.registry.authenticates_prepared_publication(token):
                self.content.registry.cancel_prepared(token)
