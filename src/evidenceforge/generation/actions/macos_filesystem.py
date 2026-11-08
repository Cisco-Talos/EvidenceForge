# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded file operations through the shared State/artifact/source publication journal.

Callers supply canonical file and directory facts. This bundle does not infer an
empty create from a completed write, allocate host-derived stat, or reinterpret a
generic file effect as a native filesystem observation.
"""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import FileContext, HostContext, ProcessContext
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.events.dispatcher import (
    ActionCohortPublicationResult,
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedDispatchStateIntent,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.macos_file_operation import MacosFileOperationObservation
from evidenceforge.events.macos_filesystem_state import MacosFilesystemChange
from evidenceforge.generation.actions.command_effects import (
    ActionAnchor,
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.models.exceptions import StateError


@dataclass(frozen=True, slots=True)
class MacosFilesystemRequest:
    """One exact live actor performs one explicitly modeled file operation."""

    action_id: str
    host: HostContext
    actor: ProcessIdentity
    observation: MacosFileOperationObservation
    storyline_cluster_id: str | None = None
    filesystem_change: MacosFilesystemChange | None = None
    placement_lease_owner: str = ""
    placement_lease_until: datetime | None = None


class MacosFilesystemActionBundle:
    """Publish canonical file state and correlated evidence in a single exact cohort."""

    def __init__(self, dispatcher: EventDispatcher) -> None:
        self.dispatcher = dispatcher

    def prepare(self, request: MacosFilesystemRequest) -> PreparedActionCohortBatch:
        """Prepare without committing; the returned journal owns all reserved members."""
        dispatcher = self.dispatcher
        state = dispatcher.state_manager
        registry = dispatcher.local_artifact_registry
        actor, observation = request.actor, request.observation
        observation.__post_init__()
        time = observation.observed_at
        if (
            not request.action_id.strip()
            or registry is None
            or request.host.os_category != "macos"
            or request.host.hostname != actor.hostname
            or observation.source.artifact.hostname.casefold() != actor.hostname.casefold()
            or observation.source.artifact.principal.casefold() != actor.principal.casefold()
            or state.get_process_identity(actor.hostname, actor.pid) != actor
            or not state.is_process_active_at(actor.hostname, actor.pid, time)
            or time < actor.execution_started_at
        ):
            raise StateError(
                "Mac file operation requires its exact current live actor and registry"
            )
        tokens: list[LocalArtifactPublishToken] = []
        timing = None
        handed_off = False
        try:
            if observation.operation == "rename":
                for record in (observation.source,) + (
                    (observation.replacement,) if observation.replacement is not None else ()
                ):
                    tokens.append(
                        registry.prepare_publish_version(
                            record, time, withdraw_placement=True, require_existing=True
                        )
                    )
                horizon = registry.retained_version_deadline(
                    observation.source.artifact.artifact_version_id
                )
                if horizon is None:
                    raise StateError("Mac rename requires its retained source horizon")
                tokens.append(
                    registry.prepare_publish_version(
                        observation.target,
                        time,
                        retention=max(horizon, tokens[0].retained_until) - time,
                        lease_owner=request.placement_lease_owner,
                        lease_until=request.placement_lease_until,
                    )
                )
            else:
                tokens.append(
                    registry.prepare_publish_version(
                        observation.source,
                        time,
                        withdraw_placement=observation.operation == "unlink",
                        require_existing=observation.operation == "unlink"
                        or (observation.operation == "close" and observation.previous is None),
                        lease_owner=request.placement_lease_owner,
                        lease_until=request.placement_lease_until,
                    )
                )
            builder = state.begin_action_cohort_materialization()
            if request.filesystem_change is None:
                builder.patch_process_activity(actor, time)
            else:
                builder.patch_macos_filesystem(actor, request.filesystem_change)
            plan = builder.seal()
            effect = OwnedEffectOccurrencePlan(
                owner=EffectOccurrenceOwner.MACOS_FILESYSTEM,
                kind=EffectOccurrenceKind.FILE,
                root_action_id=request.action_id,
                instance_key=observation.source.artifact.artifact_version_id,
                occurrence_count=1,
            )
            record = observation.target if observation.operation == "rename" else observation.source
            assert record is not None
            kind, action = {
                "create": ("file_create", "create"),
                "close": ("file_close", "close"),
                "rename": ("file_rename", "rename"),
                "unlink": ("file_delete", "delete"),
            }[observation.operation]
            event = OccurrenceBuilder(
                timestamp=time,
                event_type=kind,
                src_host=request.host,
                effect_provenance=effect.provenance(0),
                identity_plan=EventIdentityPlan(actor=actor),
                process=ProcessContext(
                    pid=actor.pid,
                    parent_pid=actor.parent_pid,
                    image=actor.image,
                    command_line=actor.command_line,
                    username=actor.principal,
                    logon_id=actor.logon_id,
                    start_time=actor.started_at,
                ),
                file=FileContext(
                    path=record.artifact.native_path,
                    action=action,
                    pid=actor.pid,
                    macos_operation=observation,
                    previous_path=observation.source.artifact.native_path
                    if observation.operation == "rename"
                    else None,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=actor.lifecycle_group_id,
                    canonical_start=actor.started_at,
                    phase="dependent",
                    parent_group_id=actor.parent_lifecycle_group_id or None,
                ),
                storyline_origin=request.storyline_cluster_id is not None,
                storyline_cluster_id=request.storyline_cluster_id,
            )
            audit = ExecutionEffectPlan(
                ActionAnchor(
                    "macos_filesystem",
                    request.action_id,
                    source="storyline" if request.storyline_cluster_id else "baseline",
                ),
                (),
            )
            with dispatcher.source_timing_planner.prepared_planning() as timing:
                prepared = dispatcher.prepare_builder(
                    event,
                    state_intent=PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT,
                    lifecycle_ticket=plan,
                    artifact_publications=tuple(tokens),
                    source_timing_preparation=timing,
                )
            batch = dispatcher.prepare_action_cohort_batch(
                request.action_id,
                plan,
                (prepared,),
                (ExecutionEffectAuditCohortEntry(audit, audit.reconcile(())),),
                (),
                (),
                owned_effect_plans=(effect,),
                exact_projection=True,
            )
            handed_off = True
            return batch
        finally:
            if not handed_off:
                if timing is not None and not timing.committed:
                    timing.cancel()
                for token in reversed(tokens):
                    if registry.authenticates_prepared_publication(token):
                        registry.cancel_prepared(token)

    def execute(self, request: MacosFilesystemRequest) -> ActionCohortPublicationResult:
        """Commit once and return the authenticated result, including any retained source tail."""
        return self.dispatcher.publish_prepared_action_cohort_batch(self.prepare(request))
