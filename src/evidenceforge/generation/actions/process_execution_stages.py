# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ephemeral process plans; existing managers retain every durable identity and claim."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.events.dispatcher import PreparedActionCohortBatch, PreparedDispatch
    from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
    from evidenceforge.events.lifecycle import SessionEndPlan
    from evidenceforge.generation.actions.command_effects import ExecutionEffectReconciliation
    from evidenceforge.generation.actions.endpoint_effects import (
        PreparedProcessEffectActor,
        PreparedProcessEndpointEffectPlan,
    )
    from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
    from evidenceforge.generation.source_timing import SourceTimingPreparation
    from evidenceforge.generation.state_manager import (
        ActionCohortMaterializationPlan,
        ProcessMaterializationPlan,
    )


@dataclass(frozen=True)
class ProcessExecutionAdmission:
    """Preflight effects and the existing root/cohort admission decisions."""

    endpoint: PreparedProcessEndpointEffectPlan | None
    actor: PreparedProcessEffectActor | None
    uses_action_cohort: bool
    requires_new_root: bool


@dataclass(frozen=True)
class ProcessActorResolution:
    """Resolved identity and initial launch intent before parent and timing planning."""

    image: str
    command_line: str
    executable: str
    username: str
    logon_id: str
    integrity: str
    parent_pid: int
    time: datetime
    session_end_plan: SessionEndPlan | None


@dataclass(frozen=True)
class ProcessLaunchPlan:
    """Final parent, canonical start and native token fields for a resolved actor."""

    actor: ProcessActorResolution
    time: datetime
    parent_pid: int
    logon_type: int
    integrity: str
    token_elevation: str
    mandatory_label: str


@dataclass(frozen=True)
class ProcessRootPlan:
    """Exact uncommitted State identities and the existing optional cohort plan."""

    process: ProcessMaterializationPlan
    cohort: ActionCohortMaterializationPlan | None
    session_id: int
    session_identity: SessionIdentity | None
    parent_identity: ProcessIdentity | None


@dataclass(frozen=True)
class ProcessEvidencePlan:
    """Canonical root evidence with its source deadline and modeled provisional close."""

    event: OccurrenceBuilder
    provisional_termination: datetime | None
    source_visible_by: datetime | None
    binary_publication: LocalArtifactPublishToken | None


@dataclass(frozen=True)
class PreparedProcessPublication:
    """Validated publication capabilities passed unchanged to the existing commit paths."""

    root_dispatch: PreparedDispatch
    dependent_dispatches: tuple[PreparedDispatch, ...]
    timing: SourceTimingPreparation
    artifacts: tuple[LocalArtifactPublishToken, ...]
    reconciliation: ExecutionEffectReconciliation | None
    cohort: PreparedActionCohortBatch | None
