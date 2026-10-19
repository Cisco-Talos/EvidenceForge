# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded child adoption shared by explicit and ordinary Mac process exits."""

from datetime import datetime

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.lifecycle import LifecycleTransition
from evidenceforge.events.parentage import ProcessParentageChange
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.state_manager import ActionCohortMaterializationBuilder, StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid


def prepare_surviving_child_adoptions(
    *,
    lifecycle_registry: LifecycleRegistry,
    state_manager: StateManager,
    builder: ActionCohortMaterializationBuilder,
    members: tuple[ProcessIdentity, ...],
    closing_ids: set[str],
    completed_at: datetime,
    action_id: str,
) -> tuple[LifecycleTransition, ...]:
    """Prepare bounded exact direct-child adoption for an explicit terminal set."""
    adoptions: list[LifecycleTransition] = []
    for member in members:
        children, more = lifecycle_registry.live_child_process_page(member.object_id, limit=257)
        if more is not None:
            raise StateError("Process exit cleanup exceeds its child ownership budget")
        for child in children:
            if child.identity.object_id in closing_ids:
                continue
            if len(adoptions) >= 256:
                raise StateError("Process exit cleanup exceeds its adoption budget")
            current_child = state_manager.get_process_identity_by_object_id(
                child.identity.object_id
            )
            adopter = state_manager.get_process_identity(member.hostname, 1)
            if current_child is None or adopter is None:
                raise StateError("Process exit cleanup lost a child or explicit system parent")
            adopted = builder.adopt_process_after_parent_exit(
                current_child, adopter=adopter, changed_at=completed_at
            )
            change = ProcessParentageChange(
                current_child.parentage, adopted.parentage, completed_at
            )
            adoptions.append(
                LifecycleTransition(
                    transition_id=stable_uuid(
                        "posix-parent-exit-adoption", action_id, child.identity.object_id
                    ),
                    subject=child.identity.ref,
                    kind="dependent",
                    canonical_time=completed_at,
                    action_id=action_id + ":adoption:" + child.identity.object_id,
                    reason="Process parent exit adoption",
                    parentage_change=change,
                )
            )
    return tuple(adoptions)
