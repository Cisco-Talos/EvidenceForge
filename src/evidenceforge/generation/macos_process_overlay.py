# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only relationship projection inside a validated State cohort boundary."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.process_observation import (
    ProcessParentObservation,
    ProcessRelationshipObservation,
    ProcessResponsibilityObservation,
)
from evidenceforge.events.responsibility import ResponsibleProcessReference
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager


class MacosProcessRelationshipOverlay:
    """Index an already authenticated cohort while its State read lock is held.

    This ephemeral view grants no commit authority and never changes State.
    Selected transition owners supply their exact subject after/before image.
    Other identity transitions and closes apply only when strictly earlier;
    equal-time transitions share a pre-transition boundary independent of tuple
    order. Explicit same-time staged birth references retain their existing
    authenticated dependency order.
    """

    def __init__(self, state: StateManager, cohort: ActionCohortMaterializationPlan) -> None:
        self._state = state
        self._births = {item.identity.object_id: item.identity for item in cohort.processes}
        self._executions = {item.target.object_id: item for item in cohort.process_executions}
        self._activity = {
            state._action_process_identity(item.target).object_id: item
            for item in cohort.process_activity_patches
        }
        self._closes = {item.identity.object_id: item for item in cohort.process_terminations}

    def _process_at(self, object_id: str, at: datetime) -> ProcessIdentity | None:
        birth = self._births.get(object_id)
        identity = (
            birth
            if birth is not None
            else self._state.get_process_identity_by_object_id(object_id, event_time=at)
        )
        if identity is None or identity.started_at > at:
            return None
        closed = self._closes.get(object_id)
        if closed is not None and closed.end_time < at:
            return None
        execution = self._executions.get(object_id)
        if execution is not None and execution.after.execution_started_at < at:
            identity = execution.after
        patch = self._activity.get(object_id)
        if patch is not None and patch.activity_time < at:
            if patch.parentage_change is not None:
                identity = replace(
                    identity,
                    parent_pid=patch.parentage_change.after.current_pid,
                    parentage=patch.parentage_change.after,
                )
            if patch.job_control_change is not None:
                identity = replace(identity, job_control=patch.job_control_change.after)
            if patch.audit_binding is not None:
                identity = replace(identity, credentials=patch.audit_binding.after)
            drop = patch.privilege_drop or patch.service_drop
            if drop is not None:
                identity = replace(identity, credentials=drop.after, principal=drop.after_principal)
        return identity

    def observe(self, identity: ProcessIdentity, at: datetime) -> ProcessRelationshipObservation:
        """Join an exact selected subject to its event-time relationship owners."""
        if identity.parentage is None or identity.responsibility is None:
            raise StateError(
                "Planned observation requires known process facts and known relationship owners"
            )
        parent_ref = identity.parentage.current
        parent = self._process_at(parent_ref.object_id, at) if parent_ref is not None else None
        if parent_ref is not None and parent is None:
            raise StateError("Planned observation lost its active parent; adoption is required")
        reference = identity.responsibility.responsible
        if reference is None:
            responsibility = ProcessResponsibilityObservation(identity, identity, at, "absent")
        else:
            responsible = self._process_at(reference.object_id, at)
            if responsible is not None:
                responsibility = ProcessResponsibilityObservation(
                    identity, responsible, at, "active"
                )
            else:
                closed = self._closes.get(reference.object_id)
                retained = self._state._processes_by_object_id.get(reference.object_id) or (
                    self._state._ended_processes_by_object_id.get(reference.object_id)
                )
                if closed is not None and closed.end_time < at:
                    owner = ResponsibleProcessReference(
                        closed.identity.hostname,
                        closed.identity.object_id,
                        closed.identity.pid,
                        closed.identity.started_at,
                    )
                    ended_at = closed.end_time
                elif retained is not None and retained.end_time is not None:
                    owner = ResponsibleProcessReference(
                        retained.system, retained.ecar_object_id, retained.pid, retained.start_time
                    )
                    ended_at = retained.end_time
                else:
                    raise StateError("Planned responsibility lost exact retained lifetime history")
                if reference != owner or ended_at > at:
                    raise StateError("Planned responsibility has no exact prior terminal proof")
                responsibility = ProcessResponsibilityObservation(
                    identity, identity, at, "exited", ended_at
                )
        try:
            return ProcessRelationshipObservation(
                ProcessParentObservation(identity, parent, at), responsibility
            )
        except ValueError as error:
            raise StateError("Planned relationships disagree with canonical ownership") from error
