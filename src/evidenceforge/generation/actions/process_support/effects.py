# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare process-owned endpoint evidence and publish auxiliary bundle requests."""

from __future__ import annotations

import logging
import ntpath
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, FileContext, ProcessContext, RegistryContext
from evidenceforge.events.contracts import EffectOccurrenceKind, SemanticOccurrenceKey
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import EntityIdentity, EventIdentityPlan, ProcessIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.actions import (
    EffectExecutionOutcome,
    EffectKind,
    EffectOutcomeStatus,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ExecutionEffectReconciliation,
    NmapCommandProbeActionBundle,
    NmapCommandProbeRequest,
    ScannerEffectIntent,
    UnplannedEffectFailure,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.endpoint_effects import PreparedProcessEndpointEffectPlan
from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

from . import policy
from .capabilities import ExecuteNmapCommandProbeBundleCapability, ProcessIdentityCapabilities

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessEvidencePreparer:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _execute_nmap_command_probe_bundle: ExecuteNmapCommandProbeBundleCapability
    _execution_effect_audit: ExecutionEffectAuditCounter
    _loaded_modules_by_process: set[tuple[str, int, str, str]]
    dispatcher: EventDispatcher
    state_manager: StateManager
    identity: ProcessIdentityCapabilities

    def _prepare_process_owned_endpoint_effects_for_publication(
        self,
        *,
        system: System,
        prepared: PreparedProcessEndpointEffectPlan,
        storyline_origin: bool,
        action_cohort_owned: bool = False,
        process_identity: ProcessIdentity | None = None,
        process_closes_at: datetime | None = None,
        pid: int | None = None,
        parent_pid: int | None = None,
    ) -> tuple[
        ExecutionEffectReconciliation,
        tuple[tuple[OccurrenceBuilder, LocalArtifactPublishToken | None], ...],
    ]:
        """Bind and stage an endpoint DAG against an allocation-free process identity."""

        from types import SimpleNamespace

        from evidenceforge.events.contracts import (
            EffectOccurrenceProvenance,
        )
        from evidenceforge.generation.actions.command_effects import (
            EffectExecutionOutcome,
            EffectOutcomeStatus,
            FileEffectIntent,
            RegistryEffectIntent,
        )
        from evidenceforge.generation.actions.endpoint_effects import (
            EndpointEffectExecutionPlan,
            EndpointEffectPreparedCommit,
            ExactProcessEffectActor,
            PreparedFileEffectPayload,
            PreparedRegistryEffectPayload,
            ProcessOwnedEndpointEffectActionBundle,
            ProcessOwnedEndpointEffectRequest,
            bind_prepared_process_endpoint_effect_plan,
        )

        if process_identity is None:
            if pid is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "endpoint effects require an exact process identity or PID",
                )
            process_identity = self.state_manager.get_process_identity(system.hostname, pid)
            running_process = self.state_manager.get_process(system.hostname, pid)
            if process_identity is None or running_process is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    f"endpoint effects require live exact process {system.hostname}:{pid}",
                )
            process_closes_at = running_process.end_time
        if parent_pid is not None and parent_pid != process_identity.parent_pid:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "endpoint effect parent PID drifted from its exact process identity",
            )

        actor = ExactProcessEffectActor(
            hostname=process_identity.hostname,
            pid=process_identity.pid,
            process_object_id=process_identity.object_id,
            lifecycle_id=process_identity.lifecycle_group_id,
            image=process_identity.image,
            command_line=process_identity.command_line,
            username=process_identity.principal,
            logon_id=process_identity.logon_id,
            started_at=process_identity.started_at,
            closes_at=process_closes_at,
        )
        request = bind_prepared_process_endpoint_effect_plan(prepared, actor)
        host_context = self.identity.host_context(system)
        auth_context = AuthContext(
            username=actor.username,
            user_sid=self.identity.user_sid(actor.username),
            logon_id=actor.logon_id,
        )
        process_context = ProcessContext(
            pid=process_identity.pid,
            parent_pid=process_identity.parent_pid,
            image=actor.image,
            command_line=actor.command_line,
            username=actor.username,
            logon_id=actor.logon_id,
            start_time=actor.started_at,
        )
        effect_graph = prepared.execution_plan
        if effect_graph is None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint publication requires its frozen execution-effect graph",
            )
        nodes_by_instance_key = {node.instance_key: node for node in effect_graph.ordered_nodes}
        builders_by_key: dict[
            str,
            tuple[tuple[OccurrenceBuilder, LocalArtifactPublishToken | None], ...],
        ] = {}
        for effect in prepared.admitted_effects:
            spec = effect.spec
            payload = effect.payload
            intent = spec.intent
            if isinstance(intent, FileEffectIntent):
                if not isinstance(payload, PreparedFileEffectPayload):
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_PLAN,
                        "prepared file effect lost its source-native payload",
                    )
                semantic_key = f"{system.hostname}:{payload.path.casefold()}"
                subject = EntityIdentity(
                    object_id=stable_uuid("file-identity", semantic_key),
                    kind="file",
                    hostname=system.hostname,
                    semantic_key=semantic_key,
                )
                builder_template = OccurrenceBuilder(
                    timestamp=actor.started_at,
                    event_type=effect.event_type,
                    src_host=host_context,
                    auth=auth_context,
                    process=process_context,
                    file=FileContext(
                        path=payload.path,
                        action=payload.action.value,
                        pid=process_identity.pid,
                        artifact_identity=(
                            payload.artifact_publication.record.artifact
                            if payload.artifact_publication is not None
                            else None
                        ),
                        content_identity=(
                            payload.artifact_publication.record.content
                            if payload.artifact_publication is not None
                            else None
                        ),
                    ),
                    storyline_origin=storyline_origin,
                )
            elif isinstance(intent, RegistryEffectIntent):
                if not isinstance(payload, PreparedRegistryEffectPayload):
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_PLAN,
                        "prepared registry effect lost its source-native payload",
                    )
                target = f"{payload.key}\\{payload.value_name}"
                semantic_key = f"{system.hostname}:{target.casefold()}:{payload.value}"
                subject = EntityIdentity(
                    object_id=stable_uuid("registry-identity", semantic_key),
                    kind="registry",
                    hostname=system.hostname,
                    semantic_key=semantic_key,
                )
                builder_template = OccurrenceBuilder(
                    timestamp=actor.started_at,
                    event_type=effect.event_type,
                    src_host=host_context,
                    auth=auth_context,
                    process=process_context,
                    registry=RegistryContext(
                        key=target,
                        value=payload.value,
                        value_type=payload.value_type,
                        action=payload.action.value,
                        pid=process_identity.pid,
                    ),
                    storyline_origin=storyline_origin,
                )
            else:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_INTENT,
                    "prepared process endpoint adapters accept only file and registry effects",
                )
            node = nodes_by_instance_key.get(spec.instance_key)
            if node is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.MISSING_DEPENDENCY,
                    "prepared process endpoint payload has no matching effect node",
                )
            artifact_publication = (
                payload.artifact_publication
                if isinstance(payload, PreparedFileEffectPayload)
                else None
            )
            publication_occurrences = (
                tuple(enumerate(spec.occurrence_times))
                if action_cohort_owned
                else ((0, spec.occurrence_times[0]),)
            )
            builders_by_key[spec.instance_key] = tuple(
                (
                    replace(
                        builder_template,
                        timestamp=occurrence_time,
                        occurrence_key=(
                            SemanticOccurrenceKey(
                                action_id=stable_uuid(
                                    "canonical-action",
                                    process_identity.lifecycle_group_id,
                                ),
                                role=node.role,
                                instance_key=stable_uuid(
                                    "endpoint-effect-occurrence",
                                    effect_graph.action_id,
                                    node.node_id,
                                    occurrence_ordinal,
                                    occurrence_time.isoformat(),
                                ),
                            )
                            if action_cohort_owned
                            else None
                        ),
                        identity_plan=EventIdentityPlan(
                            subject=subject,
                            actor=process_identity,
                        ),
                        lifecycle=(
                            ActionLifecycleContext(
                                group_id=process_identity.lifecycle_group_id,
                                canonical_start=process_identity.started_at,
                                phase="dependent",
                                parent_group_id=(
                                    process_identity.parent_lifecycle_group_id or None
                                ),
                            )
                            if action_cohort_owned
                            else None
                        ),
                        effect_provenance=EffectOccurrenceProvenance.planned(
                            kind=(
                                EffectOccurrenceKind.FILE
                                if isinstance(intent, FileEffectIntent)
                                else EffectOccurrenceKind.REGISTRY
                            ),
                            root_action_id=prepared.root_anchor.action_id,
                            plan_action_id=effect_graph.action_id,
                            node_id=node.node_id,
                            occurrence_ordinal=occurrence_ordinal,
                        ),
                    ),
                    artifact_publication,
                )
                for occurrence_ordinal, occurrence_time in publication_occurrences
            )

        staged_builders: tuple[tuple[OccurrenceBuilder, LocalArtifactPublishToken | None], ...] = ()

        def preflight(
            candidate_request: ProcessOwnedEndpointEffectRequest,
            _anchor: ActionAnchor,
        ) -> EndpointEffectExecutionPlan:
            expected = candidate_request.execution_plan
            if expected is None or candidate_request.actor != actor:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "process endpoint actor drifted from its allocation-free identity",
                )
            for occurrence in expected.occurrences():
                if occurrence.timestamp < process_identity.started_at or (
                    process_closes_at is not None and occurrence.timestamp >= process_closes_at
                ):
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                        "process endpoint occurrence falls outside its prepared actor lifetime",
                    )
            return expected

        def prepare(
            candidate_request: ProcessOwnedEndpointEffectRequest,
        ) -> EndpointEffectPreparedCommit:
            nonlocal staged_builders
            plan = candidate_request.execution_plan
            if plan is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process endpoint staging requires its exact frozen plan",
                )
            suppressed = frozenset(plan.suppressed_instance_keys)
            admitted_keys = tuple(
                spec.instance_key for spec in plan.specs if spec.instance_key not in suppressed
            )
            if set(admitted_keys) != builders_by_key.keys():
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process endpoint builders drifted from admitted planned instances",
                )
            staged_builders = tuple(
                builder for key in admitted_keys for builder in builders_by_key[key]
            )
            specs_by_key = {spec.instance_key: spec for spec in plan.specs}
            outcomes = []
            for node in plan.effects.ordered_nodes:
                spec = specs_by_key[node.instance_key]
                if node.instance_key in suppressed:
                    outcomes.append(
                        EffectExecutionOutcome(
                            node_id=node.node_id,
                            status=EffectOutcomeStatus.SUPPRESSED,
                            completed_at=actor.started_at,
                            reason="optional endpoint effect omitted outside its prepared interval",
                            canonical_occurrence_count=0,
                        )
                    )
                    continue
                outcomes.append(
                    EffectExecutionOutcome(
                        node_id=node.node_id,
                        status=EffectOutcomeStatus.REALIZED,
                        completed_at=spec.occurrence_times[-1],
                        child_action_id=(actor.lifecycle_id if action_cohort_owned else ""),
                        canonical_occurrence_count=node.intent.occurrence_cardinality,
                    )
                )
            return EndpointEffectPreparedCommit.create(plan, tuple(outcomes))

        def commit(
            _candidate_request: ProcessOwnedEndpointEffectRequest,
            _prepared_commit: EndpointEffectPreparedCommit,
        ) -> None:
            return None

        adapter = SimpleNamespace(
            _preflight_process_owned_endpoint_effects=preflight,
            _prepare_process_owned_endpoint_effects=prepare,
            _commit_process_owned_endpoint_effects=commit,
        )
        reconciliation = ProcessOwnedEndpointEffectActionBundle(adapter, request).execute()
        return reconciliation, staged_builders

    def _emit_process_command_network_effects(
        self,
        *,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        command_line: str,
        effect_plan: ExecutionEffectPlan | None = None,
    ) -> None:
        """Emit direct network effects for well-known network-scanning commands."""
        probe_request = NmapCommandProbeRequest(
            user=user,
            system=system,
            time=time,
            pid=pid,
            process_name=process_name,
            command_line=command_line,
        )
        bundle = NmapCommandProbeActionBundle(
            executor=self,
            request=probe_request,
        )
        if effect_plan is None:
            bundle.execute()
            return

        probe_count = self._execute_nmap_command_probe_bundle(probe_request)
        scanner_nodes = tuple(
            node for node in effect_plan.nodes if isinstance(node.intent, ScannerEffectIntent)
        )
        if scanner_nodes:
            outcomes = (
                EffectExecutionOutcome(
                    node_id=scanner_nodes[0].node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    canonical_occurrence_count=probe_count,
                ),
            )
            unplanned_failures = ()
        elif probe_count:
            outcomes = ()
            unplanned_failures = (
                UnplannedEffectFailure(
                    effect_kind=EffectKind.SCANNER,
                    canonical_occurrence_count=probe_count,
                    reason="nmap emitted canonical probes for an explicit no-effect plan",
                ),
            )
        else:
            outcomes = ()
            unplanned_failures = ()
        reconciliation = effect_plan.reconcile(
            outcomes,
            unplanned_failures=unplanned_failures,
        )
        self._execution_effect_audit.record(reconciliation)
        reconciliation.require_complete()

    def _emit_windows_process_startup_modules(
        self,
        *,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        from_storyline: bool,
    ) -> None:
        """Emit the configured Windows loader chain during process initialization."""
        from evidenceforge.generation.activity.dll_load_profiles import (
            select_startup_dlls_for_process,
        )

        exe_basename = ntpath.basename(process_name).lower()
        startup_modules = select_startup_dlls_for_process(
            exe_basename,
            seed_parts=(system.hostname, system.os),
        )
        elapsed_ms = 1 + (
            _stable_seed(f"windows-startup-modules:{system.hostname}:{pid}:{time.isoformat()}") % 4
        )
        for load_order, module in enumerate(startup_modules, start=1):
            dll_path = str(module["path"])
            self.generate_image_load(
                user=user,
                system=system,
                time=time + timedelta(milliseconds=elapsed_ms),
                pid=pid,
                image=process_name,
                dll_path=dll_path,
                signed=bool(module["signed"]),
                signature=str(module["signature"]),
                signature_status=str(module["signature_status"]),
                load_phase="startup",
                load_order=load_order,
                from_storyline=from_storyline,
            )
            spacing_seed = _stable_seed(
                f"windows-startup-module-spacing:{system.hostname}:{pid}:"
                f"{time.isoformat()}:{load_order}:{module['path']}"
            )
            elapsed_ms += 1 + (spacing_seed % 7)

    def generate_image_load(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        image: str,
        dll_path: str,
        signed: bool = True,
        signature: str = "Microsoft Windows",
        signature_status: str = "Valid",
        load_phase: str = "runtime",
        load_order: int = 0,
        from_storyline: bool = False,
    ) -> None:
        """Generate Sysmon Event 7 (ImageLoaded) for DLL/module loading.

        Args:
            user: User running the process that loaded the DLL
            system: System where the load occurs
            time: Event timestamp
            pid: PID of the process loading the DLL
            image: Full path of the process image
            dll_path: Full path of the loaded DLL
            signed: Whether the DLL is signed
            signature: Signer name (e.g., "Microsoft Windows")
            signature_status: Signature validation status (Valid, Expired, etc.)
            load_phase: Canonical process phase (startup or runtime)
            load_order: One-based initialization order for startup modules
            from_storyline: Whether the owning process came from authored activity
        """
        from evidenceforge.events.contexts import ImageLoadContext, ProcessContext
        from evidenceforge.generation.activity.dll_load_profiles import (
            module_is_compatible_with_process,
        )

        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None:
            logger.debug(
                "Skipping image load for non-running process: %s pid=%s image=%s dll=%s",
                system.hostname,
                pid,
                image,
                dll_path,
            )
            return
        if time >= proc.start_time and not self.state_manager.is_process_active_at(
            system.hostname, pid, time
        ):
            logger.debug(
                "Skipping image load outside owning process lifetime: %s pid=%s dll=%s",
                system.hostname,
                pid,
                dll_path,
            )
            return
        image = normalize_defender_platform_path(proc.image, system.hostname)
        dll_path = policy._materialize_module_profile_path(
            dll_path,
            system=system,
            username=proc.username or user.username,
            pid=pid,
            process_start=proc.start_time,
        )
        dll_path = normalize_defender_platform_path(dll_path, system.hostname)
        exe_basename = ntpath.basename(image).lower()
        if not module_is_compatible_with_process(exe_basename, dll_path):
            logger.warning(
                "Skipping module load incompatible with its configured process owner: "
                "%s pid=%s image=%s dll=%s",
                system.hostname,
                pid,
                image,
                dll_path,
            )
            return
        module_identity = None
        deployment_registry = getattr(self.dispatcher, "deployment_registry", None)
        if deployment_registry is not None:
            module_identity = deployment_registry.resolve_binary(
                system.hostname,
                dll_path,
                "windows",
                principal=proc.username or user.username,
            )
            if (
                module_identity is None
                or deployment_registry.host_module_handle(
                    system.hostname,
                    module_identity.content_id,
                )
                is None
            ):
                logger.debug(
                    "Skipping image load for undeployed module: %s pid=%s image=%s dll=%s",
                    system.hostname,
                    pid,
                    image,
                    dll_path,
                )
                return
        if load_phase not in {"startup", "runtime"}:
            raise ValueError(f"load_phase must be 'startup' or 'runtime', got {load_phase!r}")
        if load_phase == "startup" and load_order <= 0:
            raise ValueError("startup module loads require a positive load_order")
        time = self._clamp_time_after_process_start(system, pid, time)
        session_end_time = (
            self.state_manager.get_session_end_time(proc.logon_id) if proc.logon_id else None
        )
        if session_end_time is not None and ensure_utc(time) >= ensure_utc(session_end_time):
            logger.debug(
                "Skipping image load after owning session ended: %s pid=%s logon_id=%s dll=%s",
                system.hostname,
                pid,
                proc.logon_id,
                dll_path,
            )
            return
        if not self._mark_loaded_module(system.hostname, pid, proc.start_time, dll_path):
            logger.debug(
                "Skipping duplicate image load for process instance: %s pid=%s dll=%s",
                system.hostname,
                pid,
                dll_path,
            )
            return
        self.state_manager.update_process_activity_time(system.hostname, pid, time)
        self.state_manager.get_process_object_id(system.hostname, pid)
        event = OccurrenceBuilder(
            timestamp=time,
            event_type="image_load",
            src_host=self.identity.host_context(system),
            process=ProcessContext(
                pid=pid,
                parent_pid=proc.parent_pid,
                image=image,
                command_line=proc.command_line,
                username=proc.username,
                logon_id=proc.logon_id,
                start_time=proc.start_time,
            ),
            image_load=ImageLoadContext(
                image_loaded=dll_path,
                signed=signed,
                signature=signature,
                signature_status=signature_status,
                load_phase=load_phase,
                load_order=load_order,
                binary_identity=module_identity,
            ),
            storyline_origin=from_storyline,
        )
        self.dispatcher.dispatch_builder(event)

    def _clamp_time_after_process_start(
        self, system: System, pid: int, time: datetime, *, offset_ms: int = 100
    ) -> datetime:
        """Ensure dependent process telemetry is not timestamped before process start."""
        process = self.state_manager.get_process(system.hostname, pid)
        if process and process.start_time and time <= process.start_time:
            return process.start_time + timedelta(milliseconds=offset_ms)
        return time

    def _mark_loaded_module(
        self,
        hostname: str,
        pid: int,
        process_start: datetime | None,
        dll_path: str,
    ) -> bool:
        """Return False when this process instance already loaded the module."""
        process_start_key = process_start.isoformat() if process_start is not None else ""
        module_key = (hostname, pid, process_start_key, dll_path.lower())
        if module_key in self._loaded_modules_by_process:
            return False
        self._loaded_modules_by_process.add(module_key)
        return True
