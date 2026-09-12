# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan bounded process admission and prepare uncommitted process effects."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import cast

from evidenceforge.events.content_identity import (
    Architecture,
    Platform,
    UnresolvedBinaryIdentity,
    canonical_native_path,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions import (
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    NmapCommandProbePlan,
    NmapCommandProbeRequest,
    ProcessExecutionPreparedEffects,
    ProcessExecutionRequest,
    ProcessRuntimeImageLoadPlan,
    ScannerEffectIntent,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.endpoint_effects import (
    PreparedEndpointEffect,
    PreparedProcessEffectActor,
    PreparedProcessEndpointEffectPlan,
)
from evidenceforge.generation.actions.process_execution import (
    ProcessLifetimeMode,
    ProcessLifetimePlan,
)
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.network_params import nmap_command_probe_config
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS as _SYSTEM_ACCOUNTS
from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime as _linux_foreground_lifetime,
)
from evidenceforge.generation.activity.process_helpers import (
    _linux_shell_process_reserves_foreground as _linux_shell_process_reserves_foreground,
)
from evidenceforge.generation.activity.service_process_profiles import matching_service_worker
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactPublishToken,
)
from evidenceforge.generation.runtime_content import (
    RuntimeContentIdentityManager,
    RuntimeContentOwnerError,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime, TimingSampler
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

from . import policy as process_policy
from .actors import ProcessActorResolver
from .capabilities import BoundedProcessReuseCapability, PlanNmapCommandProbesCapability
from .foreground import ProcessForegroundLifecycle
from .parents import ProcessParentResolver
from .sources import ProcessSourceTiming

logger = logging.getLogger(__name__)

_FILE_ACTION_EVENT_TYPES = process_policy._FILE_ACTION_EVENT_TYPES
_runtime_artifact_owner_kind = process_policy._runtime_artifact_owner_kind
_session_source_ready_time = process_policy._session_source_ready_time
_windows_process_lifetime_plan = process_policy._windows_process_lifetime_plan
_LINUX_FOREGROUND_SHELL_RELEASE_MAX_MS = process_policy._LINUX_FOREGROUND_SHELL_RELEASE_MAX_MS


@dataclass(frozen=True)
class ProcessPreflightPlanner:
    """Ephemeral preparation over current owners; reservations stay in their registry."""

    state_manager: StateManager
    timing_runtime: TimingRuntime
    dispatcher: EventDispatcher
    _runtime_content_manager: RuntimeContentIdentityManager | None
    _scenario_end_time: datetime | None
    actors: ProcessActorResolver
    parents: ProcessParentResolver
    sources: ProcessSourceTiming
    foreground: ProcessForegroundLifecycle
    bounded_reuse_intent: BoundedProcessReuseCapability
    plan_scanner: PlanNmapCommandProbesCapability

    def _preflight_bounded_process_source_deadline(
        self,
        request: ProcessExecutionRequest,
    ) -> ProcessExecutionRequest | None:
        """Reject an impossible process-create source deadline before bundle planning."""

        if request.source_visible_by is None:
            return request
        source_deadline = ensure_utc(request.source_visible_by)
        request = replace(request, source_visible_by=source_deadline)
        actor = self.actors._prepare_process_effect_actor(request)
        if (
            matching_service_worker(
                os_category=_get_os_category(request.system.os),
                image=actor.image,
                command_line=actor.command_line,
                username=actor.username,
            )
            is not None
        ):
            # Profiled service workers own their manager/worker composite admission.
            return request
        parent_pid = request.parent_pid
        if not request.require_exact_parent:
            parent_pid = self.parents._resolve_existing_prepared_process_parent(
                system=request.system,
                user=request.user,
                time=actor.started_at,
                logon_id=actor.logon_id,
                parent_pid=parent_pid,
                process_username=actor.username,
            )
        if parent_pid != request.parent_pid:
            request = replace(request, parent_pid=parent_pid)
            actor = self.actors._prepare_process_effect_actor(request)
        reuse_found, reuse_intent = self.bounded_reuse_intent(
            request=request,
            actor=actor,
        )
        if reuse_found:
            return replace(request, reuse_intent=reuse_intent) if reuse_intent is not None else None
        parent_source_time = (
            self.sources._process_source_frontier_or_bound(
                system=request.system,
                pid=parent_pid,
            )
            if parent_pid > 0
            else None
        )
        session = self.state_manager.get_session(actor.logon_id) if actor.logon_id else None
        source_bound = self.sources._process_create_source_bound(
            system=request.system,
            canonical_time=actor.started_at,
            parent_source_time=parent_source_time,
            session_source_time=(
                _session_source_ready_time(session) if session is not None else None
            ),
        )
        return request if source_bound <= source_deadline else None

    @staticmethod
    def _nmap_command_probe_count(plan: NmapCommandProbePlan) -> int:
        """Return exact canonical connection cardinality for one bounded plan."""

        return len(plan.targets) if plan.discovery else len(plan.targets) * len(plan.ports)

    def _plan_process_execution_effects(
        self,
        request: ProcessExecutionRequest,
        anchor: ActionAnchor,
    ) -> ExecutionEffectPlan:
        """Plan bounded command effects before allocating the root process."""

        planning_request = NmapCommandProbeRequest(
            user=request.user,
            system=request.system,
            time=request.time,
            pid=-1,
            process_name=request.process_name,
            command_line=request.command_line,
        )
        scanner_plan = self.plan_scanner(
            planning_request,
            nmap_command_probe_config(),
        )
        if scanner_plan is None:
            return ExecutionEffectPlan(anchor=anchor)
        probe_count = self._nmap_command_probe_count(scanner_plan)
        scanner_node = ExecutionEffectNode.create(
            anchor,
            ScannerEffectIntent(
                tool="nmap",
                target=request.command_line,
                probe_count=probe_count,
            ),
        )
        return ExecutionEffectPlan(anchor=anchor, nodes=(scanner_node,))

    def _plan_process_execution_side_effects(
        self,
        request: ProcessExecutionRequest,
        anchor: ActionAnchor,
    ) -> ProcessExecutionPreparedEffects | None:
        """Freeze endpoint/module intent before any PID, lifecycle, or event mutation."""

        if request.reuse_intent is not None:
            return ProcessExecutionPreparedEffects(
                root_anchor=anchor,
                actor=self.actors._prepare_process_effect_actor(request),
            )

        from evidenceforge.generation.actions.command_effects import (
            EffectRequirement,
            FileEffectAction,
            FileEffectIntent,
            RegistryEffectAction,
            RegistryEffectIntent,
        )
        from evidenceforge.generation.actions.endpoint_effects import (
            EndpointEffectSpec,
            EndpointStateDisposition,
            PreparedEndpointEffect,
            PreparedFileEffectPayload,
            PreparedRegistryEffectPayload,
        )

        if (
            matching_service_worker(
                os_category=_get_os_category(request.system.os),
                image=request.process_name,
                command_line=request.command_line,
                username=request.user.username,
            )
            is not None
        ):
            return None

        actor = self.actors._prepare_process_effect_actor(request)
        rng = self._process_endpoint_effect_rng(request, actor)
        endpoint_window_candidates = [actor.started_at + timedelta(days=1)]
        scenario_end = self._scenario_end_time
        if isinstance(scenario_end, datetime):
            endpoint_window_candidates.append(ensure_utc(scenario_end))
        dispatcher_end = getattr(self.dispatcher, "output_end_time", None)
        if isinstance(dispatcher_end, datetime):
            endpoint_window_candidates.append(ensure_utc(dispatcher_end))
        endpoint_window_end = min(endpoint_window_candidates)
        source_ready_floor = actor.started_at + timedelta(seconds=4)
        planned: list[PreparedEndpointEffect] = list(request.requested_endpoint_effects)

        process_name = actor.image
        command_line = actor.command_line
        process_username = actor.username
        os_category = _get_os_category(request.system.os)
        exe_lower = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        bundle_owned_service_payload = exe_lower in {
            "psexesvc.exe",
            "healthmonitorsvc.exe",
        }
        if request.ensure_file_event and not bundle_owned_service_payload:
            lower_path = process_name.lower()
            windows_path = lower_path.replace("/", "\\")
            is_system_binary = (
                windows_path.startswith("c:\\windows\\system32\\")
                or windows_path.startswith("c:\\windows\\syswow64\\")
                or windows_path.startswith("c:\\program files\\")
                or windows_path.startswith("c:\\program files (x86)\\")
                or lower_path.startswith(
                    (
                        "/bin/",
                        "/sbin/",
                        "/usr/bin/",
                        "/usr/sbin/",
                        "/usr/local/bin/",
                        "/usr/local/sbin/",
                    )
                )
            )
            if not is_system_binary:
                occurrence_time = max(
                    actor.started_at + timedelta(milliseconds=120),
                    source_ready_floor,
                )
                planned.append(
                    PreparedEndpointEffect(
                        spec=EndpointEffectSpec(
                            intent=FileEffectIntent(
                                action=FileEffectAction.CREATE,
                                path=process_name,
                            ),
                            occurrence_times=(occurrence_time,),
                            instance_key="guaranteed-process-image-create",
                            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
                            retention_deadline=max(
                                endpoint_window_end,
                                occurrence_time + timedelta(microseconds=1),
                            ),
                        ),
                        event_type="file_create",
                        payload=PreparedFileEffectPayload(
                            path=process_name,
                            action=FileEffectAction.CREATE,
                        ),
                    )
                )

        semantic_file_effect = None
        if not request.suppress_command_file_effect:
            from evidenceforge.generation.activity.edr_pools import select_command_file_side_effect

            semantic_file_effect = select_command_file_side_effect(process_name, command_line)
            if semantic_file_effect is not None:
                action, path = semantic_file_effect
                file_action = FileEffectAction(action)
                occurrence_time = max(
                    actor.started_at + timedelta(milliseconds=180),
                    source_ready_floor + timedelta(milliseconds=1),
                )
                mutates = file_action in {FileEffectAction.CREATE, FileEffectAction.MODIFY}
                planned.append(
                    PreparedEndpointEffect(
                        spec=EndpointEffectSpec(
                            intent=FileEffectIntent(action=file_action, path=path),
                            occurrence_times=(occurrence_time,),
                            instance_key="semantic-command-file",
                            state_disposition=(
                                EndpointStateDisposition.DURABLE_FINAL
                                if mutates
                                else EndpointStateDisposition.NONE
                            ),
                            retention_deadline=(
                                max(
                                    endpoint_window_end,
                                    occurrence_time + timedelta(microseconds=1),
                                )
                                if mutates
                                else None
                            ),
                        ),
                        event_type=_FILE_ACTION_EVENT_TYPES[action],
                        payload=PreparedFileEffectPayload(path=path, action=file_action),
                    )
                )
        if (
            not request.suppress_command_file_effect
            and semantic_file_effect is None
            and rng.random() < 0.40
        ):
            from evidenceforge.generation.activity.edr_pools import select_file_side_effect

            side_effect = select_file_side_effect(
                process_name=process_name,
                command_line=command_line,
                os_category=os_category,
                rng=rng,
                user=process_username,
            )
            if side_effect is not None:
                action, path = side_effect
                file_action = FileEffectAction(action)
                occurrence_time = max(
                    actor.started_at + timedelta(milliseconds=rng.randint(110, 650)),
                    source_ready_floor + timedelta(milliseconds=2),
                )
                mutates = file_action in {FileEffectAction.CREATE, FileEffectAction.MODIFY}
                planned.append(
                    PreparedEndpointEffect(
                        spec=EndpointEffectSpec(
                            intent=FileEffectIntent(action=file_action, path=path),
                            occurrence_times=(occurrence_time,),
                            instance_key="ambient-process-file",
                            requirement=EffectRequirement.OPTIONAL,
                            state_disposition=(
                                EndpointStateDisposition.DURABLE_FINAL
                                if mutates
                                else EndpointStateDisposition.NONE
                            ),
                            retention_deadline=(
                                max(
                                    endpoint_window_end,
                                    occurrence_time + timedelta(microseconds=1),
                                )
                                if mutates
                                else None
                            ),
                        ),
                        event_type=_FILE_ACTION_EVENT_TYPES[action],
                        payload=PreparedFileEffectPayload(path=path, action=file_action),
                    )
                )

        runtime_image_load: ProcessRuntimeImageLoadPlan | None = None
        if os_category == "windows" and rng.random() < 0.30:
            from evidenceforge.generation.activity.dll_load_profiles import (
                get_runtime_dlls_for_process,
            )

            dll_profiles = get_runtime_dlls_for_process(exe_lower)
            dll_profile = rng.choice(dll_profiles) if dll_profiles else {}
            dll_path = str(dll_profile.get("path", ""))
            module_time = max(
                actor.started_at + timedelta(milliseconds=rng.randint(120, 1500)),
                source_ready_floor + timedelta(milliseconds=2),
            )
            if dll_path and module_time < endpoint_window_end:
                runtime_image_load = ProcessRuntimeImageLoadPlan(
                    timestamp=module_time,
                    path=dll_path,
                    signed=bool(dll_profile.get("signed", True)),
                    signature=str(dll_profile.get("signature", "Microsoft Windows")),
                    signature_status=str(dll_profile.get("signature_status", "Valid")),
                )

        registry_writers = {
            "svchost.exe",
            "services.exe",
            "explorer.exe",
            "powershell.exe",
            "rundll32.exe",
            "msiexec.exe",
            "reg.exe",
            "regedit.exe",
            "taskhostw.exe",
            "usoclient.exe",
            "dllhost.exe",
            "tiworker.exe",
            "trustedinstaller.exe",
            "mpcmdrun.exe",
            "msmpeng.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
        }
        storyline_registry_writers = {"reg.exe", "regedit.exe", "msiexec.exe"}
        if (
            os_category == "windows"
            and exe_lower in registry_writers
            and (not request.from_storyline or exe_lower in storyline_registry_writers)
            and rng.random() < 0.50
        ):
            from evidenceforge.generation.activity.edr_pools import (
                get_registry_keys_hkcu,
                get_registry_keys_hklm,
                materialize_registry_effect,
                registry_entries_for_process,
            )

            hklm_writers = {
                "svchost.exe",
                "services.exe",
                "reg.exe",
                "regedit.exe",
                "msiexec.exe",
            }
            count = rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
            pool_hkcu = registry_entries_for_process(get_registry_keys_hkcu(), process_name)
            pool_hklm = registry_entries_for_process(get_registry_keys_hklm(), process_name)
            for registry_index in range(count):
                if process_username in _SYSTEM_ACCOUNTS:
                    eligible_registry = pool_hklm
                elif exe_lower in hklm_writers:
                    eligible_registry = pool_hklm + pool_hkcu
                else:
                    eligible_registry = pool_hkcu
                if not eligible_registry:
                    continue
                key, value_name, details = rng.choice(eligible_registry)
                registry_time = max(
                    actor.started_at + timedelta(milliseconds=rng.randint(120, 950)),
                    source_ready_floor + timedelta(milliseconds=3 + registry_index),
                )
                key, value_name, details, value_type = materialize_registry_effect(
                    (key, value_name, details),
                    rng,
                    request.user.username if request.user else "SYSTEM",
                    registry_time,
                    host_key=request.system.hostname,
                    host_ip=request.system.ip,
                    host_os=request.system.os,
                    deployment_registry=getattr(self.dispatcher, "deployment_registry", None),
                )
                planned.append(
                    PreparedEndpointEffect(
                        spec=EndpointEffectSpec(
                            intent=RegistryEffectIntent(
                                action=RegistryEffectAction.MODIFY,
                                key=key,
                                value_name=value_name,
                            ),
                            occurrence_times=(registry_time,),
                            instance_key=f"ambient-registry-{registry_index}",
                            requirement=EffectRequirement.OPTIONAL,
                            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
                            retention_deadline=max(
                                endpoint_window_end,
                                registry_time + timedelta(microseconds=1),
                            ),
                        ),
                        event_type="registry_modify",
                        payload=PreparedRegistryEffectPayload(
                            key=key,
                            value_name=value_name,
                            value=details,
                            value_type=value_type,
                            action=RegistryEffectAction.MODIFY,
                        ),
                    )
                )

        allocation_free_endpoint = (
            PreparedProcessEndpointEffectPlan(
                root_anchor=anchor,
                actor=actor,
                window_end=endpoint_window_end,
                retention_horizon_end=endpoint_window_end,
                effects=tuple(planned),
            )
            if planned
            else None
        )
        if allocation_free_endpoint is not None:
            root_effect_plan = request.effect_plan or self._plan_process_execution_effects(
                request,
                anchor,
            )
            self.actors._process_endpoint_uses_action_cohort(
                actor=actor,
                admitted_effects=allocation_free_endpoint.admitted_effects,
                effect_plan=root_effect_plan,
            )

        runtime_content_manager = self._runtime_content_manager
        deployment_registry = getattr(self.dispatcher, "deployment_registry", None)
        host_deployment = (
            deployment_registry.host_deployment(request.system.hostname)
            if isinstance(deployment_registry, DeploymentContentRegistry)
            else None
        )
        effective_architecture: Architecture | None = request.system.architecture or (
            host_deployment.architecture if host_deployment is not None else None
        )
        newly_reserved: list[LocalArtifactPublishToken] = []
        if runtime_content_manager is not None:
            platform = cast(Platform, os_category)
            prepared_file_effects: list[PreparedEndpointEffect] = []
            try:
                for effect in planned:
                    payload = effect.payload
                    if (
                        not isinstance(payload, PreparedFileEffectPayload)
                        or payload.artifact_publication is not None
                    ):
                        prepared_file_effects.append(effect)
                        continue
                    same_as_actor_image = canonical_native_path(
                        payload.path,
                        platform,
                    ) == canonical_native_path(actor.image, platform)
                    executable = same_as_actor_image and effective_architecture is not None
                    publication = runtime_content_manager.prepare_effect_publication(
                        root_action_id=anchor.action_id,
                        stable_source_id=(
                            f"{anchor.action_id}:{effect.spec.instance_key}:"
                            f"{effect.spec.intent.semantic_key}"
                        ),
                        hostname=request.system.hostname,
                        principal=actor.username,
                        platform=platform,
                        architecture=effective_architecture,
                        native_path=payload.path,
                        action=payload.action.value,
                        observed_at=effect.spec.occurrence_times[0],
                        owner_kind=_runtime_artifact_owner_kind(
                            platform,
                            actor.username,
                            actor.logon_id,
                        ),
                        deployment_registry=deployment_registry,
                        actor_image=actor.image,
                        executable=executable,
                    )
                    if publication is not None:
                        newly_reserved.append(publication)
                    prepared_file_effects.append(
                        replace(
                            effect,
                            payload=replace(payload, artifact_publication=publication),
                        )
                    )
            except RuntimeContentOwnerError as exc:
                for publication in newly_reserved:
                    runtime_content_manager.registry.cancel_prepared(publication)
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "prepared process runtime-content owner is inadmissible: "
                    f"host={request.system.hostname!r} principal={actor.username!r} "
                    f"image={actor.image!r}: {exc}",
                ) from exc
            except (ExecutionEffectPlanError, StateError, ValueError):
                for publication in newly_reserved:
                    runtime_content_manager.registry.cancel_prepared(publication)
                raise
            planned = prepared_file_effects

        try:
            endpoint = (
                replace(
                    allocation_free_endpoint,
                    effects=tuple(planned),
                )
                if allocation_free_endpoint is not None
                else None
            )
            lifetime_plan = self._plan_process_lifetime(request, actor)
            provisional_termination = self._plan_process_provisional_termination(
                request,
                actor,
                lifetime_plan,
            )
            endpoint_close_floor: datetime | None = None
            if (
                provisional_termination is not None
                and endpoint is not None
                and endpoint.latest_admitted_occurrence is not None
            ):
                endpoint_close_floor = endpoint.latest_admitted_occurrence + timedelta(
                    milliseconds=25
                )
                provisional_termination = max(provisional_termination, endpoint_close_floor)
            if actor.session_deadline is not None and provisional_termination is not None:
                release_margin_ms = (
                    _LINUX_FOREGROUND_SHELL_RELEASE_MAX_MS + 25
                    if os_category == "linux"
                    and _linux_foreground_lifetime(actor.image, actor.command_line) is not None
                    else 25
                )
                close_ceiling = actor.session_deadline - timedelta(milliseconds=release_margin_ms)
                if endpoint_close_floor is not None and endpoint_close_floor > close_ceiling:
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                        "prepared endpoint effects leave no interval for the process lifecycle close",
                    )
                if provisional_termination > close_ceiling:
                    provisional_termination = close_ceiling
                if provisional_termination <= actor.started_at:
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                        "prepared process actor leaves no interval for its lifecycle close: "
                        f"host={request.system.hostname!r} image={actor.image!r} "
                        f"started_at={actor.started_at.isoformat()} "
                        f"session_deadline={actor.session_deadline.isoformat()} "
                        f"planned_close={provisional_termination.isoformat()}",
                    )

            root_binary_publication: LocalArtifactPublishToken | None = None
            if runtime_content_manager is not None:
                platform = cast(Platform, os_category)
                endpoint_has_binary = bool(
                    endpoint is not None
                    and any(
                        isinstance(effect.payload, PreparedFileEffectPayload)
                        and effect.payload.artifact_publication is not None
                        and effect.payload.artifact_publication.record.binary is not None
                        and canonical_native_path(
                            effect.payload.artifact_publication.record.artifact.native_path,
                            platform,
                        )
                        == canonical_native_path(actor.image, platform)
                        for effect in endpoint.admitted_effects
                    )
                )
                resolved_binary = self.dispatcher.resolve_process_binary_identity(
                    request.system.hostname,
                    actor.username,
                    actor.image,
                    platform,
                )
                if not endpoint_has_binary and isinstance(
                    resolved_binary,
                    UnresolvedBinaryIdentity,
                ):
                    if effective_architecture is None:
                        raise ExecutionEffectPlanError(
                            ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                            "unresolved process executable requires exact host architecture",
                        )
                    root_binary_publication = runtime_content_manager.prepare_effect_publication(
                        root_action_id=anchor.action_id,
                        stable_source_id=f"{anchor.action_id}:root-process-image",
                        hostname=request.system.hostname,
                        principal=actor.username,
                        platform=platform,
                        architecture=effective_architecture,
                        native_path=actor.image,
                        action="create",
                        observed_at=actor.started_at,
                        owner_kind=_runtime_artifact_owner_kind(
                            platform,
                            actor.username,
                            actor.logon_id,
                        ),
                        deployment_registry=deployment_registry,
                        actor_image=actor.image,
                        executable=True,
                    )
                    if root_binary_publication is None:
                        raise ExecutionEffectPlanError(
                            ExecutionEffectPlanErrorCode.INVALID_PLAN,
                            "unresolved process executable did not prepare a binary publication",
                        )
                    newly_reserved.append(root_binary_publication)

            return ProcessExecutionPreparedEffects(
                root_anchor=anchor,
                actor=actor,
                endpoint=endpoint,
                runtime_image_load=runtime_image_load,
                lifetime_plan=lifetime_plan,
                provisional_termination=provisional_termination,
                root_binary_publication=root_binary_publication,
            )
        except RuntimeContentOwnerError as exc:
            if runtime_content_manager is not None:
                for publication in newly_reserved:
                    runtime_content_manager.registry.cancel_prepared(publication)
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "prepared process runtime-content owner is inadmissible: "
                f"host={request.system.hostname!r} principal={actor.username!r} "
                f"image={actor.image!r}: {exc}",
            ) from exc
        except (ExecutionEffectPlanError, StateError, ValueError):
            if runtime_content_manager is not None:
                for publication in newly_reserved:
                    runtime_content_manager.registry.cancel_prepared(publication)
            raise

    @staticmethod
    def _process_endpoint_effect_rng(
        request: ProcessExecutionRequest,
        actor: PreparedProcessEffectActor,
    ) -> random.Random:
        """Return the worker/order-stable RNG for one process endpoint preflight."""

        return random.Random(
            _stable_seed(f"process_endpoint_preflight:{request.stable_id}:{actor.stable_id}")
        )

    def _plan_process_provisional_termination(
        self,
        request: ProcessExecutionRequest,
        actor: PreparedProcessEffectActor,
        lifetime_plan: ProcessLifetimePlan,
    ) -> datetime | None:
        """Freeze a foreground close time before allocating its PID or state."""

        os_category = _get_os_category(request.system.os)
        lifetime = lifetime_plan.bounds
        if lifetime is None:
            return None

        if os_category == "windows":
            if lifetime_plan.mode == ProcessLifetimeMode.UNCLASSIFIED:
                parent = self.state_manager.get_process(
                    request.system.hostname,
                    request.parent_pid,
                )
                parent_exe = (
                    parent.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].casefold()
                    if parent is not None
                    else ""
                )
                if parent_exe not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                    return None
            distribution, relationship_key, scope, sample_key = (
                process_policy._process_provisional_termination_timing_request(
                    request,
                    actor,
                    lifetime_plan,
                )
            )
            owner_sampler = self.timing_runtime.sampler
            preview_sampler = TimingSampler(
                namespace=owner_sampler.namespace,
                generation_seed=owner_sampler.generation_seed,
            )
            return preview_sampler.after(
                actor.started_at,
                distribution,
                relationship_key=relationship_key,
                scope=scope,
                sample_key=sample_key,
            )

        if os_category != "linux" or not _linux_shell_process_reserves_foreground(
            actor.image, actor.command_line
        ):
            return None
        actor_exe = actor.image.rsplit("/", 1)[-1].lower()
        if actor_exe in {"bash", "sh", "zsh"} and actor.command_line.strip() == f"-{actor_exe}":
            return None
        parent_owns_foreground = (
            self.foreground._foreground_shell_key(
                system=request.system,
                username=actor.username,
                logon_id=actor.logon_id,
                parent_pid=request.parent_pid,
            )
            is not None
        )
        if not parent_owns_foreground:
            session = self.state_manager.get_session(actor.logon_id)
            if (
                request.lifecycle_group_id
                and session is not None
                and request.lifecycle_group_id == session.lifecycle_group_id
            ):
                # Explicit session-bootstrap members are closed by their exact
                # session owner, which preserves the descendant-first graph.
                return None
            parent_owns_foreground = bool(
                actor.logon_id
                and session is not None
                and session.system.casefold() == request.system.hostname.casefold()
            )
        if not parent_owns_foreground:
            return None
        distribution, relationship_key, scope, sample_key = (
            process_policy._process_provisional_termination_timing_request(
                request,
                actor,
                lifetime_plan,
            )
        )
        owner_sampler = self.timing_runtime.sampler
        preview_sampler = TimingSampler(
            namespace=owner_sampler.namespace,
            generation_seed=owner_sampler.generation_seed,
        )
        return preview_sampler.after(
            actor.started_at,
            distribution,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )

    @staticmethod
    def _plan_process_lifetime(
        request: ProcessExecutionRequest,
        actor: PreparedProcessEffectActor,
    ) -> ProcessLifetimePlan:
        """Return the immutable lifetime ownership for one prepared process actor."""

        os_category = _get_os_category(request.system.os)
        if os_category == "windows":
            return _windows_process_lifetime_plan(actor.image, actor.command_line)
        if os_category == "linux":
            lifetime = _linux_foreground_lifetime(actor.image, actor.command_line)
            if lifetime is not None:
                return ProcessLifetimePlan(
                    mode=ProcessLifetimeMode.BOUNDED,
                    minimum_seconds=lifetime[0],
                    maximum_seconds=lifetime[1],
                    classification="linux-foreground-command",
                )
            if _linux_shell_process_reserves_foreground(actor.image, actor.command_line):
                return ProcessLifetimePlan(
                    mode=ProcessLifetimeMode.SESSION_OWNED,
                    classification="linux-interactive-foreground-command",
                )
            return ProcessLifetimePlan(
                mode=ProcessLifetimeMode.PERSISTENT,
                classification="linux-background-or-service-process",
            )
        return ProcessLifetimePlan(
            mode=ProcessLifetimeMode.UNCLASSIFIED,
            minimum_seconds=1.0,
            maximum_seconds=8.0,
            classification="unsupported-platform-process",
        )

    def _cancel_uncommitted_process_artifact_publications(
        self,
        prepared_effects: ProcessExecutionPreparedEffects | None,
    ) -> None:
        """Release every prepared artifact reservation not consumed by a successful bundle."""

        manager = self._runtime_content_manager
        if manager is None or prepared_effects is None:
            return
        for publication in prepared_effects.artifact_publications:
            manager.registry.cancel_prepared(publication)
