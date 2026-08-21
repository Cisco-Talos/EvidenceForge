# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""EventDispatcher routes sealed occurrences to StateManager and emitters.

Two-layer filtering for emitter selection:
1. Format eligibility: emitter.can_handle(event)
2. Network visibility: for network events, check NetworkVisibilityEngine
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock, RLock, get_ident
from typing import TYPE_CHECKING, cast
from weakref import ReferenceType, ref

from evidenceforge.events.base import (
    CanonicalOccurrence,
    OccurrenceBuilder,
    RawProjectionRequest,
)
from evidenceforge.events.collection_policy import (
    CollectionCapability,
    ProjectionAdmission,
    ProjectionEnvelope,
    ProjectionRole,
)
from evidenceforge.events.content_identity import (
    Platform,
    ProcessBinaryIdentity,
    UnresolvedBinaryIdentity,
    VirtualKernelBinaryIdentity,
    canonical_native_path,
)
from evidenceforge.events.contracts import (
    ContextKind,
    EffectOccurrenceDisposition,
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    EffectOccurrenceProvenance,
    EventKind,
    OccurrenceRole,
    OwnedEffectOccurrencePlan,
    SemanticOccurrenceKey,
    shadow_seal,
)
from evidenceforge.events.network import NetworkSensorObservation, NetworkTransactionPlan
from evidenceforge.events.observation import (
    ObservationDecision,
    ObservationPolicy,
    ObservationStatus,
    ObservationSummary,
    source_family_for_format,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.utils.rng import stable_uuid

if TYPE_CHECKING:
    from evidenceforge.generation.actions.command_effects import (
        ExecutionEffectAuditCohortEntry,
        ExecutionEffectAuditCommitReceipt,
        ExecutionEffectAuditCounter,
        PreparedExecutionEffectAuditCommit,
    )
    from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
    from evidenceforge.generation.deployment_registry import (
        DeploymentContentRegistry,
        LocalArtifactPreparedGroupCommit,
        LocalArtifactPublicationGroupReceipt,
        LocalArtifactPublishToken,
        LocalArtifactVersionRegistry,
    )
    from evidenceforge.generation.emitters.base import (
        ExactPublicationAuthorityCensus,
        ExactPublicationBatch,
        LogEmitter,
    )
    from evidenceforge.generation.intent_ledger import (
        IntentExecutionBatchReceipt,
        IntentExecutionBatchRequest,
        IntentExecutionBatchToken,
        IntentExecutionLedger,
        PreparedIntentExecutionBatch,
    )
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import (
        LifecycleActionCohortAdmissionToken,
        LifecycleActionCohortReceipt,
        LifecycleActionCohortRequest,
        PreparedLifecycleActionCohort,
    )
    from evidenceforge.generation.lifecycle_shadow import (
        LifecycleShadow,
        LifecycleShadowViolationSummary,
    )
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.generation.persistent_smb_projection import (
        PersistentSmbProjectionCommittedMemberRecovery,
        PersistentSmbProjectionGroupCensus,
        PersistentSmbProjectionGroupToken,
        PersistentSmbProjectionMemberCertification,
        PersistentSmbProjectionMemberCommitReceipt,
        PersistentSmbProjectionMemberRecovery,
        PersistentSmbProjectionMemberToken,
        PersistentSmbProjectionPhase,
    )
    from evidenceforge.generation.source_timing import (
        SourceTimingPlan,
        SourceTimingPlanner,
        SourceTimingPreparation,
        SourceTimingPreparationReceipt,
    )
    from evidenceforge.generation.state_manager import (
        ActionCohortMaterializationPlan,
        ActionCohortMaterializationResult,
        PreparedActionCohortMaterialization,
        StateManager,
    )
    from evidenceforge.generation.timing import TimingRuntime

logger = logging.getLogger(__name__)

# Backward-compatible mutable views of the canonical catalog groups.
FORMAT_GROUPS: dict[str, set[str]] = {
    group_name: set(DEFAULT_SOURCE_CATALOG.expand((group_name,)))
    for group_name in DEFAULT_SOURCE_CATALOG.groups
}

# Formats subject to network visibility filtering (expanded emitter names)
_NETWORK_FORMATS = FORMAT_GROUPS["zeek"] | {"snort_alert", "cisco_asa"}
_ZEEK_CONN_DEPENDENTS = FORMAT_GROUPS["zeek"] - {"zeek_conn"}
_ZEEK_FILES_DEPENDENTS = {"zeek_x509", "zeek_ocsp", "zeek_pe"}
_NETWORK_SENSOR_TRANSPORT_EVENT_TYPES = {"connection", "dhcp_lease"}
_OBSERVATION_STATUS_PRECEDENCE: dict[ObservationStatus, int] = {
    "out_of_window": 0,
    "filtered": 1,
    "dropped": 2,
    "delayed": 3,
    "visible": 4,
}
_CURRENT_AUTHORED_INTENT = object()
_MAX_ACTION_COHORT_DISPATCHES = 256
_MAX_ACTION_COHORT_AUDIT_ENTRIES = 256
_MAX_ACTION_COHORT_EFFECT_MEMBER_BINDINGS = _MAX_ACTION_COHORT_DISPATCHES
_MAX_ACTION_COHORT_EXTERNAL_EFFECT_LINKS = 256
_MAX_ACTION_COHORT_OWNED_EFFECT_PLANS = 256
_MAX_ACTION_COHORT_OWNED_EFFECT_OCCURRENCES = _MAX_ACTION_COHORT_DISPATCHES
_MAX_ACTION_COHORT_NESTED_EFFECT_MEMBERS = 8 * _MAX_ACTION_COHORT_DISPATCHES
_DEFAULT_ACTION_COHORT_PREPARATION_CAPACITY = 1_024
_DEFAULT_ACTION_COHORT_MEMBER_CAPACITY = 65_536
_DEFAULT_ACTION_COHORT_BYTE_CAPACITY = 64 * 1_024 * 1_024
_DEFAULT_ACTION_COHORT_RECEIPT_CAPACITY = 4_096
_MAX_DEFERRED_SESSION_PUBLICATION_MEMBERS = 256
_MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS = 4_096
_PERSISTENT_SMB_PROJECTION_TARGET_ORDER = (
    "zeek_conn",
    "zeek_smb_mapping",
    "zeek_smb_files",
    "zeek_files",
    "ecar",
    "windows_event_security",
)


@dataclass(frozen=True, slots=True)
class _ProjectionTarget:
    """One exact immutable source target as it advances through dispatch stages."""

    format_name: str
    emitter: LogEmitter
    source_ordinal: int
    role: ProjectionRole
    required_capabilities: CollectionCapability
    optional_capabilities: CollectionCapability
    envelope: ProjectionEnvelope | None = None
    decision: ObservationDecision | None = None
    topology_visible: bool = True
    projected_timestamp: datetime | None = None
    source_timing: SourceTimingPlan | None = None
    network_observations: tuple[NetworkSensorObservation, ...] | None = None


@dataclass(frozen=True, slots=True)
class _LegacyProjectionTarget:
    """One fully timed legacy source row frozen before canonical publication."""

    format_name: str
    emitter: LogEmitter
    status: ObservationStatus
    occurrence: CanonicalOccurrence | None = None


class PreparedDispatchStateIntent(StrEnum):
    """How canonical state becomes authoritative for one prepared occurrence."""

    APPLY = "apply"
    EXTERNAL_TRANSPORT = "external_transport"
    EXTERNAL_MATERIALIZED_START = "external_materialized_start"
    EXTERNAL_MATERIALIZED_CLOSE = "external_materialized_close"
    EXTERNAL_DEPENDENT = "external_dependent"
    EXTERNAL_NETWORK_DEPENDENT = "external_network_dependent"
    EXTERNAL_ACTION_COHORT = "external_action_cohort"
    EXTERNAL_DEFERRED_TRANSPORT = "external_deferred_transport"
    EXTERNAL_DEFERRED_DEPENDENT = "external_deferred_dependent"


@dataclass(frozen=True, slots=True)
class _PreparedProjection:
    """Exact source projection plan with every timing/missingness decision frozen."""

    mode: str
    occurrence: CanonicalOccurrence
    initial_statuses: tuple[tuple[str, ObservationStatus], ...] = ()
    legacy_targets: tuple[_LegacyProjectionTarget, ...] = ()
    compiled_targets: tuple[_ProjectionTarget, ...] = ()


class PreparedDispatch:
    """Opaque integrity-bound one-shot publication prepared without global mutation.

    When source timing is transactional, the publication binds the preparation's
    stable owner token. Validation authenticates its sealed overlay, while publish
    additionally requires the owner-issued receipt created by ``commit_no_fail``.
    """

    __slots__ = (
        "_action_cohort_batch_id",
        "_authored_intent_id",
        "_consumed",
        "_binary_identity_kind",
        "_artifact_publications",
        "_expected_state_version",
        "_integrity_token",
        "_lifecycle_ticket",
        "_lock",
        "_network_dependent_batch_id",
        "_deferred_session_publication_batch_id",
        "_occurrence",
        "_projection",
        "_source_timing_preparation",
        "_state_intent",
    )

    def __init__(
        self,
        *,
        occurrence: CanonicalOccurrence,
        projection: _PreparedProjection,
        expected_state_version: int,
        state_intent: PreparedDispatchStateIntent,
        lifecycle_ticket: object | None,
        binary_identity_kind: str,
        artifact_publications: tuple[LocalArtifactPublishToken, ...],
        source_timing_preparation: SourceTimingPreparation | None,
        authored_intent_id: str | None,
        integrity_token: str,
    ) -> None:
        self._occurrence = occurrence
        self._projection = projection
        self._expected_state_version = expected_state_version
        self._state_intent = state_intent
        self._lifecycle_ticket = lifecycle_ticket
        self._action_cohort_batch_id: int | None = None
        self._authored_intent_id = authored_intent_id
        self._network_dependent_batch_id: int | None = None
        self._deferred_session_publication_batch_id: int | None = None
        self._binary_identity_kind = binary_identity_kind
        self._artifact_publications = artifact_publications
        self._source_timing_preparation = source_timing_preparation
        self._integrity_token = integrity_token
        self._consumed = False
        self._lock = Lock()

    @property
    def occurrence_id(self) -> str:
        """Return only the stable identity needed to coordinate a prepared batch."""

        return self._occurrence.occurrence_id

    def _claim(self) -> None:
        """Consume the prepared publication exactly once after dispatcher validation."""

        with self._lock:
            if self._consumed:
                raise EventContractError("Prepared dispatch was already published")
            self._consumed = True


class PreparedActionCohortProjection:
    """Opaque State-neutral source projection awaiting one exact cohort plan."""

    __slots__ = (
        "__weakref__",
        "_consumed",
        "_dispatcher_token",
        "_integrity_token",
        "_preparation_id",
    )

    def __init__(
        self,
        *,
        dispatcher_token: int,
        preparation_id: int,
        integrity_token: str,
    ) -> None:
        self._dispatcher_token = dispatcher_token
        self._preparation_id = preparation_id
        self._integrity_token = integrity_token
        self._consumed = False


class PreparedPersistentSmbSourcePublication:
    """Opaque exact-row batch retained until the projection group is acknowledged."""

    __slots__ = (
        "__weakref__",
        "_consumed",
        "_dispatcher_token",
        "_integrity_token",
        "_publication_id",
    )

    def __init__(
        self,
        *,
        dispatcher_token: int,
        publication_id: int,
        integrity_token: str,
    ) -> None:
        self._dispatcher_token = dispatcher_token
        self._publication_id = publication_id
        self._integrity_token = integrity_token
        self._consumed = False


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PersistentSmbSourcePublicationResult:
    """Callback-free exact source result authenticated by its owning dispatcher."""

    group_id: int
    generation_id: str
    publication_key: str
    publication_binding_digest: str
    target_formats: tuple[str, ...]
    member_operation_ids: tuple[str, ...]
    row_facts: tuple[tuple[str, str, int], ...]
    projection_identifiers: tuple[tuple[tuple[str, str], ...], ...]
    publication_digest: str
    _integrity: str = ""


@dataclass(frozen=True, slots=True)
class PersistentSmbSourcePublicationCensus:
    """Constant-time census of retained SMB exact-publication work."""

    active_publications: int
    prepared_publications: int
    published_unacknowledged: int
    acknowledged_terminal_proofs: int
    retained_rows: int
    retained_bytes: int
    capacity: int


@dataclass(frozen=True, slots=True)
class ActionCohortSourceProjectionFacts:
    """Detached source-native timing facts for one frozen projection target."""

    format_name: str
    source_ordinal: int
    status: ObservationStatus
    projected_timestamp: datetime | None
    finalized_times: tuple[tuple[str, datetime], ...]

    def finalized_time(self, render_key: str) -> datetime | None:
        """Return this target's exact finalized time for ``render_key`` if present."""

        if type(render_key) is not str or not render_key:
            raise ValueError("Source render key must be a non-empty exact str")
        return next(
            (timestamp for key, timestamp in self.finalized_times if key == render_key),
            None,
        )


class ActionCohortProjectionDisposition(StrEnum):
    """Authenticated source-row requirement for one exact projection preflight."""

    SOURCE_FRONTIERS_REQUIRED = "source_frontiers_required"
    EXACT_WARMUP_SUPPRESSED = "exact_warmup_suppressed"


@dataclass(frozen=True, slots=True)
class ActionCohortProjectionFacts:
    """Detached canonical and source-native facts from one projection preflight."""

    occurrence: CanonicalOccurrence
    initial_statuses: tuple[tuple[str, ObservationStatus], ...]
    sources: tuple[ActionCohortSourceProjectionFacts, ...]
    disposition: ActionCohortProjectionDisposition

    def finalized_times_for(self, render_key: str) -> tuple[datetime, ...]:
        """Return every ordered source-target time finalized for ``render_key``."""

        if type(render_key) is not str or not render_key:
            raise ValueError("Source render key must be a non-empty exact str")
        return tuple(
            timestamp
            for source in self.sources
            if source.status in {"visible", "delayed"}
            if (timestamp := source.finalized_time(render_key)) is not None
        )

    def latest_finalized_time(
        self,
        render_keys: tuple[str, ...],
    ) -> datetime | None:
        """Return the latest exact source-visible time among ordered render keys."""

        if (
            type(render_keys) is not tuple
            or not render_keys
            or any(type(render_key) is not str or not render_key for render_key in render_keys)
        ):
            raise ValueError("Source render keys must be a non-empty exact tuple of str")
        candidates = tuple(
            timestamp
            for render_key in render_keys
            for timestamp in self.finalized_times_for(render_key)
        )
        return max(candidates, default=None)


class PreparedActionCohortBatch:
    """Opaque dispatcher-owned reservation for one ordered action publication."""

    __slots__ = (
        "__weakref__",
        "_audit_binding_token",
        "_artifact_publications",
        "_batch_id",
        "_consumed",
        "_dispatcher_token",
        "_dispatches",
        "_exact_projection",
        "_integrity_token",
        "_intent_binding_token",
        "_lifecycle_binding_token",
        "_root_action_id",
        "_source_timing_preparation",
        "_state_plan",
    )

    def __init__(
        self,
        *,
        dispatcher_token: int,
        batch_id: int,
        root_action_id: str,
        state_plan: ActionCohortMaterializationPlan,
        dispatches: tuple[PreparedDispatch, ...],
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_binding_token: LifecycleActionCohortAdmissionToken,
        audit_binding_token: object,
        artifact_publications: tuple[LocalArtifactPublishToken, ...],
        intent_binding_token: IntentExecutionBatchToken | None,
        exact_projection: bool,
    ) -> None:
        self._dispatcher_token = dispatcher_token
        self._batch_id = batch_id
        self._root_action_id = root_action_id
        self._state_plan = state_plan
        self._dispatches = dispatches
        self._source_timing_preparation = source_timing_preparation
        self._lifecycle_binding_token = lifecycle_binding_token
        self._audit_binding_token = audit_binding_token
        self._artifact_publications = artifact_publications
        self._intent_binding_token = intent_binding_token
        self._exact_projection = exact_projection
        self._integrity_token = ""
        self._consumed = False

    @property
    def occurrence_count(self) -> int:
        """Return the exact bounded prepared member count."""

        return len(self._dispatches)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class ActionCohortPublicationReceipt:
    """Exact dispatcher-issued proof of every nested canonical publication."""

    dispatcher_id: str
    receipt_id: str
    publication_token: str
    root_action_id: str
    state_semantic_id: str
    expected_state_version: int
    committed_state_version: int
    occurrence_ids: tuple[str, ...]
    member_integrity_digest: str
    nested_publication_tokens: tuple[tuple[str, str], ...]
    _integrity: str = ""
    _published: bool = False


class ActionCohortProjectionOutcome:
    """Preallocated terminal rendering outcome for one ordered cohort member."""

    __slots__ = ("_error", "_identifiers", "_occurrence_id", "_status")

    def __init__(self, occurrence_id: str) -> None:
        self._occurrence_id = occurrence_id
        self._identifiers: tuple[tuple[str, str], ...] = ()
        self._error: BaseException | None = None
        self._status = "pending"

    @property
    def occurrence_id(self) -> str:
        """Return the exact canonical member identity."""

        return self._occurrence_id

    @property
    def identifiers(self) -> tuple[tuple[str, str], ...]:
        """Return ordered source identifiers produced before terminal completion."""

        return self._identifiers

    @property
    def error(self) -> BaseException | None:
        """Return the terminal emitter failure, if this member failed to render."""

        return self._error

    @property
    def status(self) -> str:
        """Return pending, started, succeeded, failed, or skipped terminal state."""

        return self._status


@dataclass(frozen=True, slots=True)
class ActionCohortPublicationResult:
    """Immutable result of one canonical commit and ordered projection tail."""

    receipt: ActionCohortPublicationReceipt
    state: ActionCohortMaterializationResult
    lifecycle: LifecycleActionCohortReceipt
    audit: object
    artifacts: LocalArtifactPublicationGroupReceipt | None
    intent: IntentExecutionBatchReceipt | None
    timing: object
    projections: tuple[ActionCohortProjectionOutcome, ...]

    @property
    def projection_identifiers(self) -> tuple[tuple[tuple[str, str], ...], ...]:
        """Return ordered frozen identifier projections for compatibility callers."""

        return tuple(outcome.identifiers for outcome in self.projections)

    @property
    def projection_errors(self) -> tuple[BaseException | None, ...]:
        """Return ordered terminal rendering errors without hiding committed receipt truth."""

        return tuple(outcome.error for outcome in self.projections)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class StateNeutralProjectionPublicationReceipt:
    """Authenticated dispatcher proof for one canonical State-neutral publication."""

    dispatcher_id: str
    receipt_id: str
    publication_token: str
    occurrence_ids: tuple[str, ...]
    member_integrity_digest: str
    timing_preparation_id: int
    timing_overlay_digest: str
    timing_publication_token: str
    intent_publication_token: str
    _integrity: str = ""
    _published: bool = False


@dataclass(frozen=True, slots=True)
class StateNeutralProjectionPublicationResult:
    """Immutable canonical-owner receipts and recoverable exact projection outcome."""

    receipt: StateNeutralProjectionPublicationReceipt
    timing: SourceTimingPreparationReceipt
    intent: IntentExecutionBatchReceipt | None
    projection: ActionCohortProjectionOutcome


@dataclass(frozen=True, slots=True)
class ExactProjectionRecoveryCensus:
    """Constant-time bounded census of dispatcher-retained exact publication work."""

    unresolved_recoveries: int
    reserved_recoveries: int
    active_recoveries: int
    recovery_capacity: int
    high_water_recoveries: int
    state_neutral_receipts: int
    authority: ExactPublicationAuthorityCensus


@dataclass(frozen=True, slots=True)
class ActionCohortPublicationCensus:
    """Constant-time bounded census of dispatcher-owned transient capabilities."""

    prepared_batches: int
    claimed_batches: int
    retained_members: int
    retained_bytes: int
    capability_locators: int
    prepared_projections: int
    projection_groups: int
    projection_retained_bytes: int
    committed_receipts: int
    preparation_capacity: int
    member_capacity: int
    retained_byte_capacity: int
    receipt_capacity: int


@dataclass(frozen=True, slots=True)
class ActionCohortEffectMemberBinding:
    """Exact realized effect-node occurrence bound to one prepared member object."""

    entry_ordinal: int
    node_id: str
    occurrence_ordinal: int
    member: PreparedDispatch

    def __post_init__(self) -> None:
        """Reject ambiguous binding keys before dispatcher authentication."""

        if type(self.entry_ordinal) is not int or self.entry_ordinal < 0:
            raise ValueError("Effect-member entry ordinal must be a non-negative exact int")
        if type(self.node_id) is not str or not self.node_id:
            raise ValueError("Effect-member binding requires a node ID")
        if type(self.occurrence_ordinal) is not int or self.occurrence_ordinal < 0:
            raise ValueError("Effect-member binding ordinal must be a non-negative exact int")
        if type(self.member) is not PreparedDispatch:
            raise TypeError("Effect-member binding requires an exact prepared dispatch")


@dataclass(frozen=True, slots=True)
class ActionCohortExternalEffectLink:
    """Exact State-owned identity proving one linked effect node's external owner."""

    entry_ordinal: int
    node_id: str
    owner: object

    def __post_init__(self) -> None:
        """Reject ambiguous link keys before State-backed authentication."""

        if type(self.entry_ordinal) is not int or self.entry_ordinal < 0:
            raise ValueError("External-effect entry ordinal must be a non-negative exact int")
        if type(self.node_id) is not str or not self.node_id:
            raise ValueError("External-effect link requires a node ID")


@dataclass(frozen=True, slots=True)
class _ActionCohortObservationDelta:
    """One precomputed dispatcher summary and optional intent-ledger increment."""

    cluster_id: str
    source: str
    status: ObservationStatus
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class _ActionCohortPreparedObservationCluster:
    """One affected-only preallocated source-summary cluster update."""

    cluster_id: str
    canonical_cluster: dict[str, ObservationSummary] | None
    new_cluster: dict[str, ObservationSummary] | None
    source_updates: tuple[tuple[str, ObservationSummary], ...]


class PreparedActionCohortCapability:
    """One-shot same-thread composite commit capability for a claimed batch."""

    __slots__ = (
        "__weakref__",
        "_active",
        "_batch_id",
        "_claim_token",
        "_committed",
        "_dispatcher",
        "_receipt",
        "_result",
    )

    def __init__(
        self,
        dispatcher: EventDispatcher,
        *,
        batch_id: int,
        claim_token: str,
    ) -> None:
        self._dispatcher = dispatcher
        self._batch_id = batch_id
        self._claim_token = claim_token
        self._active = True
        self._committed = False
        self._receipt: ActionCohortPublicationReceipt | None = None
        self._result: ActionCohortPublicationResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether canonical publication crossed its no-fail boundary."""

        return self._committed

    @property
    def receipt(self) -> ActionCohortPublicationReceipt | None:
        """Return the outer receipt once canonical publication commits."""

        return self._receipt

    @property
    def result(self) -> ActionCohortPublicationResult | None:
        """Return the completed result after every projection renders."""

        return self._result

    def commit_no_fail(self) -> ActionCohortPublicationResult:
        """Commit every prevalidated owner, then render the frozen projection tail."""

        return self._dispatcher._commit_claimed_action_cohort(self)

    def _close(self) -> None:
        self._active = False


@dataclass(slots=True)
class _PreparedActionCohortProjectionRecord:
    """Canonical retained preflight values keyed by an exact weak carrier."""

    preparation_id: int
    carrier_id: int
    carrier_ref: ReferenceType[PreparedActionCohortProjection]
    owner_thread_id: int
    occurrence: CanonicalOccurrence
    projection: _PreparedProjection
    source_timing_preparation: SourceTimingPreparation
    authored_intent_id: str | None
    binary_identity_kind: str
    facts: ActionCohortProjectionFacts
    occurrence_digest: str
    projection_digest: str
    facts_digest: str
    timing_digest: str
    integrity_token: str
    retained_bytes: int
    state: str = "prepared"


@dataclass(slots=True)
class _PersistentSmbSourcePublicationRecord:
    """Dispatcher-private exact rows and group receipts retained through handoff."""

    publication_id: int
    carrier_id: int
    carrier_ref: ReferenceType[PreparedPersistentSmbSourcePublication]
    group: PersistentSmbProjectionGroupToken
    group_id: int
    generation_id: str
    publication_key: str
    publication_binding_digest: str
    target_formats: tuple[str, ...]
    exact_publication_batch: ExactPublicationBatch
    projections: tuple[_PreparedProjection, ...]
    projection_identifiers: tuple[tuple[tuple[str, str], ...], ...]
    row_facts: tuple[tuple[str, str, int], ...]
    retained_bytes: int
    integrity_token: str
    state: str = "prepared"
    active_thread_id: int | None = None
    commit_receipts: tuple[PersistentSmbProjectionMemberCommitReceipt, ...] = ()
    result: PersistentSmbSourcePublicationResult | None = None
    acknowledge_cursor: int = 0


@dataclass(slots=True)
class _PreparedActionCohortBatchRecord:
    """Trusted canonical batch and nested reservations retained by the dispatcher."""

    batch_id: int
    carrier_id: int
    carrier_ref: ReferenceType[PreparedActionCohortBatch]
    root_action_id: str
    state_plan: ActionCohortMaterializationPlan
    dispatches: tuple[PreparedDispatch, ...]
    member_ids: tuple[int, ...]
    member_locks: tuple[object, ...]
    member_integrity_tokens: tuple[str, ...]
    member_occurrence_ids: tuple[str, ...]
    member_occurrences: tuple[CanonicalOccurrence, ...]
    member_projections: tuple[_PreparedProjection, ...]
    trusted_projections: tuple[_PreparedProjection, ...]
    member_expected_state_versions: tuple[int, ...]
    member_authored_intent_ids: tuple[str | None, ...]
    member_binary_identity_kinds: tuple[str, ...]
    source_timing_preparation: SourceTimingPreparation
    lifecycle_request: LifecycleActionCohortRequest
    lifecycle_token: LifecycleActionCohortAdmissionToken
    audit_entries: tuple[ExecutionEffectAuditCohortEntry, ...]
    effect_member_bindings: tuple[ActionCohortEffectMemberBinding, ...]
    external_effect_links: tuple[ActionCohortExternalEffectLink, ...]
    owned_effect_plans: tuple[OwnedEffectOccurrencePlan, ...]
    published_provenances: tuple[EffectOccurrenceProvenance, ...]
    execution_effect_audit: ExecutionEffectAuditCounter
    audit_preparation: PreparedExecutionEffectAuditCommit
    artifact_registry: LocalArtifactVersionRegistry | None
    artifact_publications: tuple[LocalArtifactPublishToken, ...]
    intent_ledger: IntentExecutionLedger | None
    intent_request: IntentExecutionBatchRequest | None
    intent_token: IntentExecutionBatchToken | None
    exact_projection: bool
    exact_projection_kind: str
    exact_all_suppressed: bool
    exact_publication_batch: ExactPublicationBatch | None
    exact_prepared_identifiers: tuple[tuple[str, str], ...]
    exact_prepared_row_count: int
    observation_deltas: tuple[_ActionCohortObservationDelta, ...]
    observation_digest: str
    member_integrity_digest: str
    state_plan_digest: str
    effect_binding_digest: str
    nested_token_digest: str
    integrity_token: str
    retained_bytes: int
    member_cleanup_status: list[bool]
    artifact_cleanup_status: list[bool]
    prepared_observation_updates: tuple[_ActionCohortPreparedObservationCluster, ...] | None = None
    prepared_binary_counts: Counter[str] | None = None
    prepared_latest_network_observations_uid: str = ""
    prepared_latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
    prepared_latest_network_plan: NetworkTransactionPlan | None = None
    observation_committed: bool = False
    state: str = "prepared"
    claim_thread_id: int | None = None
    claim_token: str = ""
    capability_id: int | None = None
    capability_ref: ReferenceType[PreparedActionCohortCapability] | None = None
    timing_claimed: SourceTimingPreparation | None = None
    audit_claimed: PreparedExecutionEffectAuditCommit | None = None
    artifact_claimed: LocalArtifactPreparedGroupCommit | None = None
    intent_claimed: PreparedIntentExecutionBatch | None = None
    lifecycle_claimed: PreparedLifecycleActionCohort | None = None
    state_claimed: PreparedActionCohortMaterialization | None = None
    expected_timing_receipt: SourceTimingPreparationReceipt | None = None
    expected_audit_receipt: ExecutionEffectAuditCommitReceipt | None = None
    expected_artifact_receipt: LocalArtifactPublicationGroupReceipt | None = None
    expected_intent_receipt: IntentExecutionBatchReceipt | None = None
    expected_lifecycle_receipt: LifecycleActionCohortReceipt | None = None
    expected_state_result: ActionCohortMaterializationResult | None = None
    expected_state_result_publication_token: str = ""
    publication_receipt: ActionCohortPublicationReceipt | None = None
    publication_result: ActionCohortPublicationResult | None = None
    projection_outcomes: tuple[ActionCohortProjectionOutcome, ...] = ()
    exact_recovery: _ExactProjectionRecoveryRecord | None = None
    receipt_eviction_id: int | None = None
    members_cleanup_complete: bool = False
    intent_cleanup_complete: bool = False
    audit_cleanup_complete: bool = False
    lifecycle_cleanup_complete: bool = False
    timing_cleanup_complete: bool = False
    artifact_cleanup_complete: bool = False
    exact_cleanup_complete: bool = False


@dataclass(slots=True)
class _StateNeutralProjectionPublicationRecord:
    """Trusted non-State canonical owners retained through exact sink recovery."""

    occurrence_id: str
    member_integrity_digest: str
    source_timing_preparation: SourceTimingPreparation
    authored_intent_id: str | None
    intent_ledger: IntentExecutionLedger | None
    intent_request: IntentExecutionBatchRequest | None
    intent_token: IntentExecutionBatchToken | None
    observation_deltas: tuple[_ActionCohortObservationDelta, ...]
    exact_publication_batch: ExactPublicationBatch
    projection_outcome: ActionCohortProjectionOutcome
    exact_kind: str
    exact_all_suppressed: bool
    prepared_row_count: int
    prepared_observation_updates: tuple[_ActionCohortPreparedObservationCluster, ...] | None = None
    observation_committed: bool = False
    expected_timing_receipt: SourceTimingPreparationReceipt | None = None
    expected_intent_receipt: IntentExecutionBatchReceipt | None = None
    publication_receipt: StateNeutralProjectionPublicationReceipt | None = None
    publication_result: StateNeutralProjectionPublicationResult | None = None
    receipt_eviction_id: int | None = None


@dataclass(slots=True)
class _ExactProjectionRecoveryRecord:
    """Strong receipt-keyed ownership of one prepared exact batch and its cursor."""

    kind: str
    receipt: (
        ActionCohortPublicationReceipt
        | StateNeutralProjectionPublicationReceipt
        | DeferredSessionPublicationReceipt
    )
    result: (
        ActionCohortPublicationResult
        | StateNeutralProjectionPublicationResult
        | DeferredSessionPublicationResult
    )
    batch: ExactPublicationBatch
    outcome: ActionCohortProjectionOutcome
    occurrence_ids: tuple[str, ...]
    member_integrity_digest: str
    identifiers: tuple[tuple[str, str], ...]
    outcomes: tuple[ActionCohortProjectionOutcome, ...] = ()
    member_identifiers: tuple[tuple[tuple[str, str], ...], ...] = ()
    target_proofs: tuple[DeferredSessionExactTargetProof, ...] = ()
    owner_record: object | None = None
    state: str = "reserved"
    active_thread_id: int | None = None


@dataclass(slots=True)
class _ActionCohortPreparationCleanupRecord:
    """Trusted reservation retained until a failed batch preparation is fully undone."""

    cleanup_id: int
    batch_id: int | None
    root_action_id: str
    dispatches: tuple[PreparedDispatch, ...]
    source_timing_preparation: SourceTimingPreparation
    lifecycle_authority: GeneratorLifecycleAuthority
    lifecycle_request: LifecycleActionCohortRequest
    lifecycle_token: LifecycleActionCohortAdmissionToken | None
    execution_effect_audit: ExecutionEffectAuditCounter
    artifact_registry: LocalArtifactVersionRegistry | None
    artifact_publications: tuple[LocalArtifactPublishToken, ...]
    audit_entries: tuple[ExecutionEffectAuditCohortEntry, ...]
    owned_effect_plans: tuple[OwnedEffectOccurrencePlan, ...]
    published_provenances: tuple[EffectOccurrenceProvenance, ...]
    audit_preparation: PreparedExecutionEffectAuditCommit | None
    intent_ledger: IntentExecutionLedger | None
    intent_request: IntentExecutionBatchRequest | None
    intent_token: IntentExecutionBatchToken | None
    exact_publication_batch: ExactPublicationBatch | None
    retained_bytes: int
    member_locks: tuple[object, ...]
    member_installed: list[bool]
    member_cleanup_complete: list[bool]
    artifact_cleanup_status: list[bool]
    state: str = "preparing"
    intent_cleanup_complete: bool = False
    audit_cleanup_complete: bool = False
    lifecycle_cleanup_complete: bool = False
    timing_cleanup_complete: bool = False
    artifact_cleanup_complete: bool = False
    exact_cleanup_complete: bool = False


class PreparedNetworkDependentBatch:
    """Opaque claimed batch of projection-only dependents for one network root."""

    __slots__ = (
        "_consumed",
        "_audit_binding_token",
        "_dispatcher_token",
        "_dispatches",
        "_integrity_token",
        "_plan",
        "_root",
        "_source_timing_preparation",
    )

    def __init__(
        self,
        *,
        dispatcher_token: int,
        audit_binding_token: object,
        root: object,
        plan: OwnedEffectOccurrencePlan,
        dispatches: tuple[PreparedDispatch, ...],
        source_timing_preparation: SourceTimingPreparation,
    ) -> None:
        self._dispatcher_token = dispatcher_token
        self._audit_binding_token = audit_binding_token
        self._root = root
        self._plan = plan
        self._dispatches = dispatches
        self._source_timing_preparation = source_timing_preparation
        self._integrity_token = ""
        self._consumed = False

    @property
    def occurrence_count(self) -> int:
        """Return the exact bounded cardinality claimed by this batch."""

        return len(self._dispatches)


class PreparedDeferredSessionPublicationBatch:
    """Opaque dispatcher reservation for one committed-root projection tail.

    The carrier deliberately exposes only bounded cardinality.  The dispatcher
    retains the authenticated composition, root, timing preparation, and exact
    ordered dispatch objects needed by immediate SSH/RDP publication.  A future
    protocol owner may reuse the inner exact-row machinery only through its own
    exact authenticated adapter; this carrier never accepts a generic owner.
    """

    __slots__ = (
        "_batch_id",
        "_consumed",
        "_dispatcher_id",
        "_integrity_token",
        "_occurrence_count",
    )

    def __init__(
        self,
        *,
        dispatcher_id: str,
        batch_id: int,
        occurrence_count: int,
    ) -> None:
        self._dispatcher_id = dispatcher_id
        self._batch_id = batch_id
        self._occurrence_count = occurrence_count
        self._integrity_token = ""
        self._consumed = False

    @property
    def occurrence_count(self) -> int:
        """Return the exact bounded prepared member count."""

        return self._occurrence_count


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class DeferredSessionPublicationPrecommit:
    """Opaque dispatcher seal claimed by lifecycle at the last reversible fence."""

    dispatcher_id: str
    batch_id: int
    composition_token: str
    member_digest: str
    target_proof_digest: str
    all_suppressed: bool
    _integrity: str = ""


@dataclass(frozen=True, slots=True)
class DeferredSessionPublicationCensus:
    """Constant-time census of retained deferred-session publication work."""

    prepared_batches: int
    retained_members: int
    retained_bytes: int
    committed_receipts: int
    pending_receipts: int
    receipt_reservations: int
    receipt_eviction_reservations: int
    recovery_reservations: int
    preparation_capacity: int
    member_capacity: int
    retained_byte_capacity: int
    receipt_capacity: int


@dataclass(frozen=True, slots=True)
class DeferredSessionExactTargetProof:
    """Frozen exact-row range for one ordered deferred member source target."""

    occurrence_id: str
    member_ordinal: int
    target_ordinal: int
    format_name: str
    row_start: int
    row_end: int
    source_order_keys: tuple[int, ...] = ()
    windows_ordering_facts: tuple[tuple[int, str, str, int], ...] = ()

    @property
    def row_count(self) -> int:
        """Return the positive exact-row cardinality staged by this target."""

        return self.row_end - self.row_start


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class DeferredSessionPublicationReceipt:
    """Authenticated proof naming one exact postcanonical source publication."""

    dispatcher_id: str
    receipt_id: str
    publication_token: str
    composition_token: str
    physical_transport_id: str
    occurrence_ids: tuple[str, ...]
    member_integrity_digest: str
    target_proof_digest: str
    materialization_receipt_token: str
    intent_publication_token: str
    _integrity: str = ""
    _published: bool = False


@dataclass(frozen=True, slots=True)
class DeferredSessionPublicationResult:
    """Terminal exact source result for a committed deferred-session root."""

    receipt: DeferredSessionPublicationReceipt
    materialization_receipt: object
    identifiers: tuple[tuple[tuple[str, str], ...], ...]
    projections: tuple[ActionCohortProjectionOutcome, ...]
    target_proofs: tuple[DeferredSessionExactTargetProof, ...]


@dataclass(frozen=True, slots=True)
class _PreparedNetworkDependentBatchCapability:
    """Dispatcher-owned trusted preimage for one claimed network-dependent batch."""

    batch_id: int
    integrity_token: str
    root: object
    plan: OwnedEffectOccurrencePlan
    dispatches: tuple[PreparedDispatch, ...]
    source_timing_preparation: SourceTimingPreparation
    execution_effect_audit: ExecutionEffectAuditCounter
    audit_preparation: PreparedExecutionEffectAuditCommit
    published_provenances: tuple[EffectOccurrenceProvenance, ...]
    audit_claim_context: AbstractContextManager[PreparedExecutionEffectAuditCommit] | None = None
    audit_claimed: PreparedExecutionEffectAuditCommit | None = None
    precommit_authenticated: bool = False


@dataclass(slots=True)
class _PreparedDeferredSessionPublicationRecord:
    """Trusted preimage and retry cursor for one ordered projection tail."""

    batch_id: int
    carrier: PreparedDeferredSessionPublicationBatch
    composition: object
    coordinator: object
    composition_token: str
    physical_transport_id: str
    root: object
    source_timing_preparation: SourceTimingPreparation
    dispatches: tuple[PreparedDispatch, ...]
    member_locks: tuple[object, ...]
    member_integrity_tokens: tuple[str, ...]
    occurrence_ids: tuple[str, ...]
    member_binary_identity_kinds: tuple[str, ...]
    all_suppressed: bool
    retained_bytes: int
    integrity_token: str
    exact_publication_batch: ExactPublicationBatch | None = None
    prepared_identifiers: tuple[tuple[tuple[str, str], ...], ...] = ()
    prepared_target_proofs: tuple[DeferredSessionExactTargetProof, ...] = ()
    member_digest: str = ""
    target_proof_digest: str = ""
    frozen_latest_network_observations_uid: str = ""
    frozen_latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
    frozen_latest_network_plan: NetworkTransactionPlan | None = None
    observation_deltas: tuple[_ActionCohortObservationDelta, ...] = ()
    prepared_observation_updates: tuple[_ActionCohortPreparedObservationCluster, ...] | None = None
    prepared_binary_counts: Counter[str] | None = None
    prepared_latest_network_observations_uid: str = ""
    prepared_latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
    prepared_latest_network_plan: NetworkTransactionPlan | None = None
    intent_ledger: IntentExecutionLedger | None = None
    intent_request: IntentExecutionBatchRequest | None = None
    intent_token: IntentExecutionBatchToken | None = None
    intent_claim_context: AbstractContextManager[PreparedIntentExecutionBatch] | None = None
    intent_claimed: PreparedIntentExecutionBatch | None = None
    expected_intent_receipt: IntentExecutionBatchReceipt | None = None
    intent_claim_closed: bool = False
    observation_committed: bool = False
    dispatcher_ledgers_committed: bool = False
    state: str = "prepared"
    active_thread_id: int | None = None
    materialization_receipt_shell: object | None = None
    materialization_receipt_shell_digest: str = ""
    materialization_receipt: object | None = None
    publication_receipt: DeferredSessionPublicationReceipt | None = None
    publication_result: DeferredSessionPublicationResult | None = None
    exact_recovery: _ExactProjectionRecoveryRecord | None = None
    receipt_eviction_id: int | None = None
    recovery_capacity_reserved: bool = False
    receipt_capacity_reserved: bool = False
    precommit: DeferredSessionPublicationPrecommit | None = None


def expand_formats(formats: list[str] | set[str]) -> set[str]:
    """Expand format group names (e.g., 'zeek') to individual emitter names."""
    expanded: set[str] = set()
    for fmt in formats:
        if fmt in FORMAT_GROUPS:
            expanded.update(FORMAT_GROUPS[fmt])
        else:
            expanded.add(fmt)
    return expanded


def _virtual_kernel_binary(
    image: str,
    platform: Platform,
) -> VirtualKernelBinaryIdentity | None:
    """Classify explicit non-file kernel images without inventing content."""

    normalized = image.strip()
    if platform == "windows" and normalized.casefold() in {"idle", "registry", "system"}:
        return VirtualKernelBinaryIdentity(platform=platform, artifact_name=normalized)
    if platform in {"linux", "macos"} and normalized.startswith("[") and normalized.endswith("]"):
        return VirtualKernelBinaryIdentity(platform=platform, artifact_name=normalized)
    return None


def _is_successful_remote_interactive_transport(event: CanonicalOccurrence) -> bool:
    """Return whether a network event is an established SSH/RDP session transport."""

    network = event.network
    if network is None:
        return False
    if str(network.protocol or "").lower() != "tcp" or network.dst_port not in {22, 3389}:
        return False
    state = str(network.conn_state or "").upper()
    if state and state != "SF":
        return False
    if event.firewall is not None and event.firewall.action == "deny":
        return False
    service = str(network.service or "").lower()
    if service and service not in {"ssh", "rdp"}:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _PersistentSmbTopologyPreparation:
    """Detached weak target-generation snapshot awaiting a group reservation."""

    configuration_digest: str
    base_registry: dict[int, tuple[ReferenceType[object], str]]
    target_generations: dict[int, tuple[ReferenceType[object], str]]
    next_target_generation: int
    target_generation_semantic_bytes: int
    target_generation_table_backing_bytes: int
    projection_targets: tuple[_PersistentSmbProjectionTargetSnapshot, ...]


@dataclass(frozen=True, slots=True)
class _PersistentSmbProjectionTargetSnapshot:
    """One weak, generation-bound projection target retained for a group."""

    format_name: str
    target_ref: ReferenceType[object]
    target_generation: str


@dataclass(frozen=True, slots=True)
class _PersistentSmbGroupTopologySnapshot:
    """Private exact target-generation truth retained for one open group."""

    group_id: int
    generation_id: str
    configuration_digest: str
    targets: tuple[_PersistentSmbProjectionTargetSnapshot, ...]
    semantic_bytes: int


@dataclass(frozen=True, slots=True)
class _PersistentSmbStateCloseProofAuthenticator:
    """Dispatcher-private authenticator for one exact State-owned SMB close."""

    state_manager: object
    state_result: object
    binding_id: str
    close_facts_digest: str

    def authenticates_persistent_smb_close_proof(
        self,
        proof: object,
        binding_id: str,
        close_facts_digest: str,
    ) -> bool:
        """Authenticate the retained State result and exact final traffic digest."""

        if proof is not self.state_result:
            return False
        authenticates = getattr(
            self.state_manager,
            "authenticates_smb_connection_finalization_result",
            None,
        )
        return (
            callable(authenticates)
            and authenticates(self.state_result) is True
            and hmac.compare_digest(binding_id, self.binding_id)
            and hmac.compare_digest(close_facts_digest, self.close_facts_digest)
        )


class EventDispatcher:
    """Routes sealed canonical occurrences to state and matching emitters."""

    def __init__(
        self,
        state_manager: StateManager,
        emitters: dict[str, LogEmitter],
        visibility_engine: NetworkVisibilityEngine | None = None,
        output_start_time: datetime | None = None,
        output_end_time: datetime | None = None,
        observation_policy: ObservationPolicy | None = None,
        intent_execution_ledger: IntentExecutionLedger | None = None,
        timing_runtime: TimingRuntime | None = None,
        source_timing_planner: SourceTimingPlanner | None = None,
        deployment_registry: DeploymentContentRegistry | None = None,
        local_artifact_registry: LocalArtifactVersionRegistry | None = None,
        lifecycle_shadow: LifecycleShadow | None = None,
        collection_deployment: CompiledCollectionDeployment | None = None,
        enforce_lifecycle_authority: bool = False,
        enforce_binary_identity: bool = False,
        action_cohort_preparation_capacity: int = (_DEFAULT_ACTION_COHORT_PREPARATION_CAPACITY),
        action_cohort_member_capacity: int = _DEFAULT_ACTION_COHORT_MEMBER_CAPACITY,
        action_cohort_byte_capacity: int = _DEFAULT_ACTION_COHORT_BYTE_CAPACITY,
        action_cohort_receipt_capacity: int = _DEFAULT_ACTION_COHORT_RECEIPT_CAPACITY,
        persistent_smb_group_capacity: int = 1_024,
        persistent_smb_member_capacity: int = 65_536,
        persistent_smb_receipt_capacity: int = 65_536,
        persistent_smb_byte_capacity: int = 64 * 1024 * 1024,
    ) -> None:
        if enforce_lifecycle_authority and lifecycle_shadow is None:
            raise ValueError(
                "Production lifecycle authority enforcement requires a LifecycleShadow"
            )
        for name, value in (
            ("action_cohort_preparation_capacity", action_cohort_preparation_capacity),
            ("action_cohort_member_capacity", action_cohort_member_capacity),
            ("action_cohort_byte_capacity", action_cohort_byte_capacity),
            ("action_cohort_receipt_capacity", action_cohort_receipt_capacity),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive exact int")
        for name, value in (
            ("persistent_smb_group_capacity", persistent_smb_group_capacity),
            ("persistent_smb_member_capacity", persistent_smb_member_capacity),
            ("persistent_smb_receipt_capacity", persistent_smb_receipt_capacity),
            ("persistent_smb_byte_capacity", persistent_smb_byte_capacity),
        ):
            if type(value) is not int:
                raise ValueError(f"{name} must be a positive exact int")
            if value <= 0 or value > (1 << 63) - 1:
                raise ValueError(f"{name} must fit the positive signed 63-bit range")
        self.state_manager = state_manager
        self.emitters = emitters
        self.visibility_engine = visibility_engine
        self.output_start_time = output_start_time
        self.output_end_time = output_end_time
        self.observation_policy = observation_policy or ObservationPolicy("complete")
        self._source_evidence_lock = Lock()
        self._publication_ledger_lock = RLock()
        self._source_evidence_version = 0
        self._source_evidence_status: dict[str, dict[str, ObservationSummary]] = {}
        self._latest_network_uid = ""
        self._latest_network_identifiers_by_format: dict[str, str] = {}
        self._latest_network_observations_uid = ""
        self._latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
        self._latest_network_plan: NetworkTransactionPlan | None = None
        self._contract_violation_counts: Counter[str] = Counter()
        self._contract_violations_by_event: Counter[tuple[str, str]] = Counter()
        self._prepared_dispatch_secret = secrets.token_bytes(32)
        self._action_cohort_dispatcher_id = secrets.token_hex(16)
        self._action_cohort_lock = Lock()
        self._action_cohort_preparation_capacity = action_cohort_preparation_capacity
        self._action_cohort_member_capacity = action_cohort_member_capacity
        self._action_cohort_byte_capacity = action_cohort_byte_capacity
        self._action_cohort_receipt_capacity = action_cohort_receipt_capacity
        self._next_action_cohort_projection_id = 1
        self._next_action_cohort_batch_id = 1
        self._next_action_cohort_cleanup_id = 1
        self._action_cohort_projections: dict[
            int,
            _PreparedActionCohortProjectionRecord,
        ] = {}
        self._action_cohort_projection_locators: dict[int, int] = {}
        self._action_cohort_projection_groups: dict[int, set[int]] = {}
        self._action_cohort_projection_retained_bytes = 0
        self._action_cohort_batches: dict[int, _PreparedActionCohortBatchRecord] = {}
        self._action_cohort_prepare_cleanups: dict[
            int,
            _ActionCohortPreparationCleanupRecord,
        ] = {}
        self._action_cohort_batch_locators: dict[int, int] = {}
        self._action_cohort_capability_locators: dict[int, int] = {}
        self._action_cohort_retained_members = 0
        self._action_cohort_retained_bytes = 0
        self._action_cohort_claimed_batches = 0
        self._action_cohort_receipts: dict[int, ActionCohortPublicationReceipt] = {}
        self._action_cohort_committed_receipts = 0
        from evidenceforge.generation.emitters.base import ExactPublicationAuthority

        self._exact_publication_authority = ExactPublicationAuthority(
            capacity=action_cohort_preparation_capacity,
            row_capacity=4 * action_cohort_member_capacity,
            byte_capacity=action_cohort_byte_capacity,
        )
        self._exact_projection_recovery_capacity = action_cohort_preparation_capacity
        self._exact_projection_recoveries: dict[int, _ExactProjectionRecoveryRecord] = {}
        self._exact_projection_recovery_reservations = 0
        self._exact_projection_active_recoveries = 0
        self._exact_projection_recovery_high_water = 0
        self._state_neutral_projection_receipts: dict[
            int,
            StateNeutralProjectionPublicationReceipt,
        ] = {}
        self._state_neutral_projection_committed_receipts = 0
        self._network_dependent_batch_lock = Lock()
        self._network_dependent_batches: dict[
            int,
            _PreparedNetworkDependentBatchCapability,
        ] = {}
        self._deferred_session_publication_dispatcher_id = secrets.token_hex(16)
        self._deferred_session_publication_lock = Lock()
        self._next_deferred_session_publication_batch_id = 1
        self._deferred_session_publication_batches: dict[
            int,
            _PreparedDeferredSessionPublicationRecord,
        ] = {}
        self._deferred_session_publication_locators: dict[int, int] = {}
        self._deferred_session_publication_precommit_locators: dict[int, int] = {}
        self._deferred_session_publication_retained_members = 0
        self._deferred_session_publication_retained_bytes = 0
        self._deferred_session_publication_receipts: dict[
            int,
            DeferredSessionPublicationReceipt,
        ] = {}
        self._deferred_session_publication_pending_receipts: dict[
            int,
            DeferredSessionPublicationReceipt,
        ] = {}
        self._deferred_session_publication_committed_receipts = 0
        self._deferred_session_publication_receipt_reservations = 0
        self._deferred_session_publication_receipt_eviction_reservations: set[int] = set()
        self.storyline_cluster_id: str | None = None
        self.authored_intent_id: str | None = None
        self.intent_execution_ledger = intent_execution_ledger
        self._execution_effect_audit: ExecutionEffectAuditCounter | None = None
        self.deployment_registry = deployment_registry
        self.local_artifact_registry = local_artifact_registry
        self._binary_identity_counts: Counter[str] = Counter()
        self._enforce_binary_identity = enforce_binary_identity
        self._lifecycle_shadow = lifecycle_shadow
        self._lifecycle_authority: GeneratorLifecycleAuthority | None = None
        self._enforce_lifecycle_authority = enforce_lifecycle_authority
        self._lifecycle_strict_predicate: Callable[[CanonicalOccurrence], bool] | None = None
        self.collection_deployment = collection_deployment
        from evidenceforge.generation.timing import TimingRuntime

        planner_runtime = (
            getattr(source_timing_planner, "timing_runtime", None)
            if source_timing_planner is not None
            else None
        )
        if timing_runtime is None:
            timing_runtime = (
                planner_runtime
                if isinstance(planner_runtime, TimingRuntime)
                else TimingRuntime.compatibility_default()
            )
        elif isinstance(planner_runtime, TimingRuntime) and planner_runtime is not timing_runtime:
            raise ValueError("dispatcher and source timing planner must share one TimingRuntime")
        self.timing_runtime = timing_runtime
        from evidenceforge.generation.source_timing import SourceTimingPlanner

        self.source_timing_planner = source_timing_planner or SourceTimingPlanner(
            clock_profile_name=self.observation_policy.profile_name,
            timing_runtime=timing_runtime,
        )
        from evidenceforge.generation.network_observation import NetworkObservationPlanner

        self.network_observation_planner = NetworkObservationPlanner(
            visibility_engine,
            output_end_time=output_end_time,
            timing_runtime=self.timing_runtime,
        )
        from evidenceforge.generation.identity_lifecycle import IdentityLifecyclePlanner
        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionGroupAuthority,
        )

        self.identity_lifecycle_planner = IdentityLifecyclePlanner(state_manager)
        self._persistent_smb_projection_authority = PersistentSmbProjectionGroupAuthority(
            group_capacity=persistent_smb_group_capacity,
            member_capacity=persistent_smb_member_capacity,
            receipt_capacity=persistent_smb_receipt_capacity,
            byte_capacity=persistent_smb_byte_capacity,
        )
        self._persistent_smb_group_lock = Lock()
        self._persistent_smb_topology_lock = Lock()
        self._persistent_smb_target_generations: dict[
            int,
            tuple[ReferenceType[object], str],
        ] = {}
        self._persistent_smb_group_topologies: dict[
            int,
            _PersistentSmbGroupTopologySnapshot,
        ] = {}
        self._persistent_smb_next_target_generation = 1
        self._persistent_smb_target_generation_capacity = 16_385
        self._persistent_smb_target_generation_semantic_bytes = 0
        self._persistent_smb_target_generation_table_backing_bytes = sys.getsizeof(
            self._persistent_smb_target_generations
        ) + sys.getsizeof(self._persistent_smb_group_topologies)
        self._persistent_smb_group_topology_semantic_bytes = 0
        self._persistent_smb_high_water_target_generations = 0
        self._persistent_smb_high_water_target_generation_table_backing_bytes = (
            self._persistent_smb_target_generation_table_backing_bytes
        )
        self._persistent_smb_source_publication_lock = Lock()
        self._persistent_smb_source_publication_capacity = action_cohort_preparation_capacity
        self._next_persistent_smb_source_publication_id = 1
        self._persistent_smb_source_publications: dict[
            int,
            _PersistentSmbSourcePublicationRecord,
        ] = {}
        self._persistent_smb_source_publication_locators: dict[int, int] = {}
        self._persistent_smb_source_publication_keys: dict[tuple[int, str], int] = {}
        self._persistent_smb_source_retained_rows = 0
        self._persistent_smb_source_retained_bytes = 0

    @staticmethod
    def _persistent_smb_sha256_digest(value: object, field_name: str) -> str:
        """Validate one exact lowercase SHA-256 digest."""

        if type(value) is not str or len(value) != 64:
            raise EventContractError(f"{field_name} must be one exact SHA-256 digest")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise EventContractError(f"{field_name} must be one exact SHA-256 digest") from error
        if any(byte not in b"0123456789abcdef" for byte in encoded):
            raise EventContractError(f"{field_name} must be one exact SHA-256 digest")
        return value

    @staticmethod
    def _persistent_smb_bounded_utf8(
        value: object,
        field_name: str,
        *,
        maximum: int = 4_096,
    ) -> bytes:
        """Return bounded exact UTF-8 bytes without coercion callbacks."""

        if type(value) is not str or not value:
            raise EventContractError(f"{field_name} must be one non-empty exact string")
        if len(value) > maximum:
            raise EventContractError(f"{field_name} exceeds {maximum} UTF-8 bytes")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise EventContractError(f"{field_name} must contain valid UTF-8 text") from error
        if len(encoded) > maximum:
            raise EventContractError(f"{field_name} exceeds {maximum} UTF-8 bytes")
        return encoded

    @staticmethod
    def _persistent_smb_target_generation_is_valid(generation: object) -> bool:
        """Validate a target-generation scalar without conversion callbacks."""

        if type(generation) is not str or len(generation) != 64:
            return False
        try:
            encoded = generation.encode("ascii")
        except UnicodeEncodeError:
            return False
        return not any(byte not in b"0123456789abcdef" for byte in encoded)

    @staticmethod
    def _persistent_smb_target_type_identity(
        target: object,
        field_prefix: str,
    ) -> tuple[bytes, bytes]:
        """Read one target's class-owned identity without metaclass dispatch."""

        target_type = type(target)
        module_descriptor = type.__dict__["__module__"]
        qualified_name_descriptor = type.__dict__["__qualname__"]
        module_name = module_descriptor.__get__(target_type, type(target_type))
        qualified_name = qualified_name_descriptor.__get__(target_type, type(target_type))
        return (
            EventDispatcher._persistent_smb_bounded_utf8(
                module_name,
                f"{field_prefix} module name",
            ),
            EventDispatcher._persistent_smb_bounded_utf8(
                qualified_name,
                f"{field_prefix} qualified name",
            ),
        )

    def _persistent_smb_target_generation(self, counter: int) -> str:
        """Prepare one monotonic, nonce-bound target-generation digest."""

        if type(counter) is not int or counter < 1 or counter > (1 << 63) - 1:
            raise EventContractError("Persistent SMB target generation capacity is exhausted")
        nonce = secrets.token_hex(16)
        if type(nonce) is not str or len(nonce) != 32:
            raise EventContractError("Persistent SMB target generation returned a malformed scalar")
        try:
            nonce_bytes = nonce.encode("ascii")
        except UnicodeEncodeError as error:
            raise EventContractError(
                "Persistent SMB target generation returned a malformed scalar"
            ) from error
        if any(byte not in b"0123456789abcdef" for byte in nonce_bytes):
            raise EventContractError("Persistent SMB target generation returned a malformed scalar")
        values = (
            b"persistent-smb-target-generation-v1",
            self._persistent_smb_projection_authority.dispatcher_id.encode("ascii"),
            counter.to_bytes(8, "big"),
            nonce_bytes,
        )
        framed = b"".join(len(value).to_bytes(8, "big") + value for value in values)
        return hashlib.sha256(framed).hexdigest()

    @staticmethod
    def _persistent_smb_target_generation_entry_bytes(
        identity: int,
        row: tuple[ReferenceType[object], str],
    ) -> int:
        """Return exact shallow semantic backing for one trusted registry row."""

        return (
            sys.getsizeof(identity)
            + sys.getsizeof(row)
            + sys.getsizeof(row[0])
            + sys.getsizeof(row[1])
        )

    def _persistent_smb_prepare_projection_configuration(
        self,
        *,
        route_generation_digest: str,
    ) -> tuple[_PersistentSmbTopologyPreparation, tuple[object, ...]]:
        """Prepare a weak target topology and compiled route generation.

        Caller-reachable targets and class facts are snapshotted before the
        dispatcher group lock. No registry or generation counter changes until
        a group reserve succeeds. The staged registry contains only exact weak
        locators; the separate strong snapshot is released after all locks.
        """

        route_digest = self._persistent_smb_sha256_digest(
            route_generation_digest,
            "persistent SMB route generation digest",
        )
        emitter_map = object.__getattribute__(self, "emitters")
        if type(emitter_map) is not dict:
            raise EventContractError("Persistent SMB projection requires an exact emitter map")
        emitter_count = dict.__len__(emitter_map)
        if emitter_count > 16_384:
            raise EventContractError("Persistent SMB projection has too many emitter targets")
        try:
            emitter_items = tuple(dict.items(emitter_map))
        except RuntimeError as error:
            raise EventContractError(
                "Persistent SMB projection emitter map changed during snapshot"
            ) from error
        if len(emitter_items) != emitter_count or dict.__len__(emitter_map) != emitter_count:
            raise EventContractError(
                "Persistent SMB projection emitter map changed during snapshot"
            )
        if any(type(format_name) is not str for format_name, _emitter in emitter_items):
            raise EventContractError(
                "Persistent SMB projection emitter names require exact strings"
            )
        if any(len(format_name) > 4_096 for format_name, _emitter in emitter_items):
            raise EventContractError("persistent SMB emitter name exceeds 4096 UTF-8 bytes")
        target_rows: list[tuple[bytes, object, ReferenceType[object], bytes, bytes]] = []
        encoded_work = 0
        for format_name, emitter in emitter_items:
            format_bytes = self._persistent_smb_bounded_utf8(
                format_name,
                "persistent SMB emitter name",
            )
            module_bytes, qualified_bytes = self._persistent_smb_target_type_identity(
                emitter,
                "persistent SMB emitter",
            )
            try:
                emitter_ref = ref(emitter)
            except TypeError as error:
                raise EventContractError(
                    "Persistent SMB projection targets require weak-reference support"
                ) from error
            encoded_work += len(format_bytes) + len(module_bytes) + len(qualified_bytes) + 32
            if encoded_work > 16 * 1024 * 1024:
                raise EventContractError(
                    "Persistent SMB projection target topology exceeds its byte budget"
                )
            target_rows.append((format_bytes, emitter, emitter_ref, module_bytes, qualified_bytes))
        target_rows.sort(key=lambda row: row[0])

        deployment_digest = "0" * 64
        deployment = self.collection_deployment
        if deployment is not None:
            from evidenceforge.generation.collection_deployment import (
                CompiledCollectionDeployment,
            )

            if type(deployment) is not CompiledCollectionDeployment:
                raise EventContractError(
                    "Persistent SMB projection requires an exact compiled deployment"
                )
            deployment_digest = self._persistent_smb_sha256_digest(
                object.__getattribute__(deployment, "content_digest"),
                "persistent SMB compiled deployment digest",
            )

        profile_bytes = self._persistent_smb_bounded_utf8(
            object.__getattribute__(self.observation_policy, "profile_name"),
            "persistent SMB observation profile name",
        )
        visibility = self.visibility_engine
        visibility_type_bytes: tuple[bytes, bytes] | None = None
        visibility_ref: ReferenceType[object] | None = None
        if visibility is not None:
            visibility_type_bytes = self._persistent_smb_target_type_identity(
                visibility,
                "persistent SMB visibility",
            )
            try:
                visibility_ref = ref(visibility)
            except TypeError as error:
                raise EventContractError(
                    "Persistent SMB projection targets require weak-reference support"
                ) from error

        active_targets = tuple((row[1], row[2]) for row in target_rows) + (
            () if visibility is None else ((visibility, visibility_ref),)
        )
        unique_target_count = len({id(target) for target, _target_ref in active_targets})
        if unique_target_count > self._persistent_smb_target_generation_capacity:
            raise EventContractError("Persistent SMB target-generation capacity is exhausted")
        target_generations: dict[int, str] = {}
        with self._persistent_smb_topology_lock:
            base_registry = self._persistent_smb_target_generations
            base_snapshot = dict.copy(base_registry)
            next_generation = self._persistent_smb_next_target_generation
        staged_registry: dict[int, tuple[ReferenceType[object], str]] = {}
        for target, target_ref in active_targets:
            assert target_ref is not None
            identity = id(target)
            located = base_snapshot.get(identity)
            if (
                type(located) is not tuple
                or len(located) != 2
                or type(located[0]) is not ReferenceType
                or located[0]() is not target
                or not self._persistent_smb_target_generation_is_valid(located[1])
            ):
                located = staged_registry.get(identity)
                if (
                    type(located) is not tuple
                    or len(located) != 2
                    or type(located[0]) is not ReferenceType
                    or located[0]() is not target
                ):
                    located = (
                        target_ref,
                        self._persistent_smb_target_generation(next_generation),
                    )
                    next_generation += 1
            staged_registry[identity] = located
            target_generations[identity] = located[1]
        target_semantic_bytes = sum(
            self._persistent_smb_target_generation_entry_bytes(identity, row)
            for identity, row in staged_registry.items()
        )
        target_table_backing_bytes = sys.getsizeof(staged_registry)

        digest = hashlib.sha256()

        def update(value: bytes) -> None:
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

        update(b"persistent-smb-dispatcher-configuration-v2")
        update(self._persistent_smb_projection_authority.dispatcher_id.encode("ascii"))
        update(route_digest.encode("ascii"))
        update(deployment_digest.encode("ascii"))
        update(profile_bytes)
        update(len(target_rows).to_bytes(8, "big"))
        for format_bytes, emitter, _emitter_ref, module_bytes, qualified_bytes in target_rows:
            update(b"emitter")
            update(format_bytes)
            update(module_bytes)
            update(qualified_bytes)
            update(target_generations[id(emitter)].encode("ascii"))
        if visibility is None:
            update(b"visibility-none")
        else:
            assert visibility_type_bytes is not None
            update(b"visibility")
            update(visibility_type_bytes[0])
            update(visibility_type_bytes[1])
            update(target_generations[id(visibility)].encode("ascii"))
        retained_targets = tuple(target for target, _target_ref in active_targets)
        projection_targets = tuple(
            _PersistentSmbProjectionTargetSnapshot(
                format_name=format_bytes.decode("utf-8"),
                target_ref=emitter_ref,
                target_generation=target_generations[id(emitter)],
            )
            for format_bytes, emitter, emitter_ref, _module_bytes, _qualified_bytes in target_rows
            if format_bytes.decode("utf-8") in _PERSISTENT_SMB_PROJECTION_TARGET_ORDER
        )
        return (
            _PersistentSmbTopologyPreparation(
                configuration_digest=digest.hexdigest(),
                base_registry=base_registry,
                target_generations=staged_registry,
                next_target_generation=next_generation,
                target_generation_semantic_bytes=target_semantic_bytes,
                target_generation_table_backing_bytes=target_table_backing_bytes,
                projection_targets=projection_targets,
            ),
            retained_targets,
        )

    def _persistent_smb_commit_projection_configuration(
        self,
        preparation: _PersistentSmbTopologyPreparation,
        group: PersistentSmbProjectionGroupToken,
    ) -> None:
        """Install staged global and per-group weak topology snapshots."""

        group_id = object.__getattribute__(group, "group_id")
        generation_id = object.__getattribute__(group, "generation_id")
        configuration_digest = object.__getattribute__(
            group,
            "projection_configuration_digest",
        )
        if (
            type(group_id) is not int
            or group_id < 1
            or not self._persistent_smb_target_generation_is_valid(generation_id)
            or configuration_digest != preparation.configuration_digest
        ):
            raise EventContractError("Persistent SMB group topology carrier is malformed")
        targets = preparation.projection_targets
        semantic_bytes = sum(
            sys.getsizeof(target)
            + sys.getsizeof(target.format_name)
            + sys.getsizeof(target.target_ref)
            + sys.getsizeof(target.target_generation)
            for target in targets
        )
        group_topology = _PersistentSmbGroupTopologySnapshot(
            group_id=group_id,
            generation_id=generation_id,
            configuration_digest=configuration_digest,
            targets=targets,
            semantic_bytes=semantic_bytes,
        )

        with self._persistent_smb_topology_lock:
            if self._persistent_smb_target_generations is not preparation.base_registry:
                raise EventContractError("Persistent SMB topology changed before reservation")
            staged_group_topologies = dict.copy(self._persistent_smb_group_topologies)
            if group_id in staged_group_topologies:
                raise EventContractError("Persistent SMB group topology identity was reused")
            staged_group_topologies[group_id] = group_topology
            released_registry: dict[int, tuple[ReferenceType[object], str]] = (
                self._persistent_smb_target_generations
            )
            released_group_topologies = self._persistent_smb_group_topologies
            self._persistent_smb_target_generations = preparation.target_generations
            self._persistent_smb_group_topologies = staged_group_topologies
            self._persistent_smb_next_target_generation = preparation.next_target_generation
            retained_target_generations = len(preparation.target_generations)
            self._persistent_smb_target_generation_semantic_bytes = (
                preparation.target_generation_semantic_bytes
            )
            self._persistent_smb_group_topology_semantic_bytes += semantic_bytes
            self._persistent_smb_target_generation_table_backing_bytes = (
                preparation.target_generation_table_backing_bytes
                + sys.getsizeof(staged_group_topologies)
            )
            self._persistent_smb_high_water_target_generations = max(
                self._persistent_smb_high_water_target_generations,
                retained_target_generations,
            )
            self._persistent_smb_high_water_target_generation_table_backing_bytes = max(
                self._persistent_smb_high_water_target_generation_table_backing_bytes,
                self._persistent_smb_target_generation_table_backing_bytes,
            )
        released_registry.clear()
        released_group_topologies.clear()

    def _persistent_smb_retire_group_topology(self, group_id: int) -> None:
        """Release one exact group's private target-generation snapshot."""

        with self._persistent_smb_topology_lock:
            topology = self._persistent_smb_group_topologies.pop(group_id, None)
            if topology is None:
                raise EventContractError("Persistent SMB group topology is missing or stale")
            self._persistent_smb_group_topology_semantic_bytes -= topology.semantic_bytes
            if not self._persistent_smb_group_topologies:
                self._persistent_smb_group_topologies.clear()
            self._persistent_smb_target_generation_table_backing_bytes = sys.getsizeof(
                self._persistent_smb_target_generations
            ) + sys.getsizeof(self._persistent_smb_group_topologies)

    def _persistent_smb_retire_projection_topology(self) -> None:
        """Drop every weak topology row after the last group is reclaimed."""

        empty_registry: dict[int, tuple[ReferenceType[object], str]] = {}
        empty_group_topologies: dict[int, _PersistentSmbGroupTopologySnapshot] = {}
        with self._persistent_smb_topology_lock:
            released_registry: dict[int, tuple[ReferenceType[object], str]] = (
                self._persistent_smb_target_generations
            )
            released_group_topologies = self._persistent_smb_group_topologies
            self._persistent_smb_target_generations = empty_registry
            self._persistent_smb_group_topologies = empty_group_topologies
            self._persistent_smb_target_generation_semantic_bytes = 0
            self._persistent_smb_group_topology_semantic_bytes = 0
            self._persistent_smb_target_generation_table_backing_bytes = sys.getsizeof(
                empty_registry
            ) + sys.getsizeof(empty_group_topologies)
        released_registry.clear()
        released_group_topologies.clear()

    @staticmethod
    def _persistent_smb_projection_target_types() -> dict[str, type[object]]:
        """Return the closed exact source-type allowlist for SMB projections."""

        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.windows import WindowsEventEmitter
        from evidenceforge.generation.emitters.zeek import ZeekEmitter
        from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
        from evidenceforge.generation.emitters.zeek_smb import (
            ZeekSmbFilesEmitter,
            ZeekSmbMappingEmitter,
        )

        return {
            "zeek_conn": ZeekEmitter,
            "zeek_smb_mapping": ZeekSmbMappingEmitter,
            "zeek_smb_files": ZeekSmbFilesEmitter,
            "zeek_files": ZeekFilesEmitter,
            "ecar": EcarEmitter,
            "windows_event_security": WindowsEventEmitter,
        }

    def _persistent_smb_projection_target_intent(
        self,
        *,
        group_id: int,
        generation_id: str,
        target_formats: object,
    ) -> tuple[tuple[str, ...], str]:
        """Authenticate exact live targets and derive private topology truth."""

        if type(group_id) is not int or group_id < 1:
            raise EventContractError("Persistent SMB target topology group is malformed")
        group_generation = self._persistent_smb_sha256_digest(
            generation_id,
            "persistent SMB target topology generation",
        )
        if type(target_formats) is not tuple:
            raise EventContractError("Persistent SMB target formats require an exact tuple")
        if not target_formats or len(target_formats) > len(_PERSISTENT_SMB_PROJECTION_TARGET_ORDER):
            raise EventContractError("Persistent SMB target formats exceed their non-empty bound")
        selected: set[str] = set()
        for target_format in target_formats:
            if type(target_format) is not str:
                raise EventContractError("Persistent SMB target formats require exact strings")
            if target_format not in _PERSISTENT_SMB_PROJECTION_TARGET_ORDER:
                raise EventContractError(
                    f"Persistent SMB unsupported target format: {target_format}"
                )
            if target_format in selected:
                raise EventContractError("Persistent SMB target formats must be unique")
            selected.add(target_format)
        canonical_targets = tuple(
            target for target in _PERSISTENT_SMB_PROJECTION_TARGET_ORDER if target in selected
        )
        expected_types = self._persistent_smb_projection_target_types()
        emitter_map = object.__getattribute__(self, "emitters")
        if type(emitter_map) is not dict:
            raise EventContractError("Persistent SMB projection requires an exact emitter map")

        with self._persistent_smb_topology_lock:
            topology = self._persistent_smb_group_topologies.get(group_id)
            if topology is None or topology.generation_id != group_generation:
                raise EventContractError("Persistent SMB topology generation is foreign or stale")
            retained_targets = {target.format_name: target for target in topology.targets}
            emitter_count = dict.__len__(emitter_map)
            target_generations: list[str] = []
            for target_format in canonical_targets:
                retained = retained_targets.get(target_format)
                current_target = dict.get(emitter_map, target_format)
                if (
                    retained is None
                    or current_target is None
                    or retained.target_ref() is not current_target
                ):
                    raise EventContractError(
                        "Persistent SMB topology generation changed after reservation"
                    )
                if type(current_target) is not expected_types[target_format]:
                    raise EventContractError(
                        "Persistent SMB projection target requires its exact target type"
                    )
                target_generations.append(retained.target_generation)
            if dict.__len__(emitter_map) != emitter_count:
                raise EventContractError(
                    "Persistent SMB projection emitter map changed during target validation"
                )
            configuration_digest = topology.configuration_digest

        digest = hashlib.sha256()

        def update(value: bytes) -> None:
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

        update(b"persistent-smb-projection-target-intent-v1")
        update(self._persistent_smb_projection_authority.dispatcher_id.encode("ascii"))
        update(group_id.to_bytes(8, "big"))
        update(group_generation.encode("ascii"))
        update(configuration_digest.encode("ascii"))
        update(len(canonical_targets).to_bytes(8, "big"))
        for target_format, target_generation in zip(
            canonical_targets,
            target_generations,
            strict=True,
        ):
            update(target_format.encode("ascii"))
            update(target_generation.encode("ascii"))
        return canonical_targets, digest.hexdigest()

    def persistent_smb_configured_projection_targets(self) -> tuple[str, ...]:
        """Return the exact supported SMB targets in this dispatcher's configured plan."""

        emitter_map = object.__getattribute__(self, "emitters")
        if type(emitter_map) is not dict:
            raise EventContractError("Persistent SMB projection requires an exact emitter map")
        expected_types = self._persistent_smb_projection_target_types()
        configured: list[str] = []
        for format_name in _PERSISTENT_SMB_PROJECTION_TARGET_ORDER:
            emitter = dict.get(emitter_map, format_name)
            if emitter is None:
                continue
            if type(emitter) is not expected_types[format_name]:
                raise EventContractError(
                    f"Persistent SMB projection target {format_name!r} requires its exact type"
                )
            configured.append(format_name)
        if not configured:
            raise EventContractError(
                "Persistent SMB production requires at least one configured supported source target"
            )
        return tuple(configured)

    def reserve_persistent_smb_projection_group(
        self,
        *,
        route_generation_digest: str,
        member_budget: int,
        byte_budget: int,
        required_target_formats: tuple[str, ...] | None = None,
    ) -> PersistentSmbProjectionGroupToken:
        """Reserve one empty detached group before canonical SMB open mutation."""

        while True:
            members, retained_bytes = (
                self._persistent_smb_projection_authority._preflight_group_reservation(
                    member_budget=member_budget,
                    byte_budget=byte_budget,
                )
            )
            topology, retained_targets = self._persistent_smb_prepare_projection_configuration(
                route_generation_digest=route_generation_digest,
            )
            try:
                with self._persistent_smb_group_lock:
                    members, retained_bytes = (
                        self._persistent_smb_projection_authority._preflight_group_reservation(
                            member_budget=members,
                            byte_budget=retained_bytes,
                        )
                    )
                    with self._persistent_smb_topology_lock:
                        topology_is_current = (
                            self._persistent_smb_target_generations is topology.base_registry
                        )
                    if not topology_is_current:
                        continue
                    group = self._persistent_smb_projection_authority.reserve_group(
                        projection_configuration_digest=topology.configuration_digest,
                        member_budget=members,
                        byte_budget=retained_bytes,
                    )
                    topology_installed = False
                    try:
                        self._persistent_smb_commit_projection_configuration(topology, group)
                        topology_installed = True
                        if required_target_formats is not None:
                            self._persistent_smb_projection_target_intent(
                                group_id=group.group_id,
                                generation_id=group.generation_id,
                                target_formats=required_target_formats,
                            )
                    except BaseException:
                        self._persistent_smb_projection_authority.cancel_empty_group(group)
                        if topology_installed:
                            self._persistent_smb_retire_group_topology(group.group_id)
                        if self._persistent_smb_projection_authority.census().retained_groups == 0:
                            self._persistent_smb_retire_projection_topology()
                        raise
                    return group
            finally:
                del retained_targets

    def prepare_persistent_smb_projection_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        phase: PersistentSmbProjectionPhase,
        operation_id: str,
        operation_binding_digest: str,
        projection_capsule: bytes,
        timing_preparation: SourceTimingPreparation,
    ) -> PersistentSmbProjectionMemberToken:
        """Preinstall one deeply frozen inactive member before owner mutation."""

        return self._persistent_smb_projection_authority.prepare_member(
            group,
            phase=phase,
            operation_id=operation_id,
            operation_binding_digest=operation_binding_digest,
            projection_capsule=projection_capsule,
            timing_planner=self.source_timing_planner,
            timing_preparation=timing_preparation,
        )

    def certify_persistent_smb_projection_member(
        self,
        token: PersistentSmbProjectionMemberToken,
        *,
        target_formats: tuple[str, ...],
        lifecycle_binding_digest: str,
        lifecycle_binding_generation: int,
        network_binding_digest: str,
        network_binding_generation: int,
        traffic_binding_digest: str,
        traffic_binding_generation: int,
        expected_timing_receipt: SourceTimingPreparationReceipt,
    ) -> PersistentSmbProjectionMemberCertification:
        """Certify exact coordinator intent without invoking projection targets."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionMemberToken,
        )

        if type(token) is not PersistentSmbProjectionMemberToken:
            raise EventContractError("Persistent SMB member is foreign, copied, or stale")
        try:
            group_id = object.__getattribute__(token, "group_id")
            generation_id = object.__getattribute__(token, "generation_id")
        except AttributeError as error:
            raise EventContractError(
                "Persistent SMB member is foreign, copied, or stale"
            ) from error
        canonical_targets, topology_digest = self._persistent_smb_projection_target_intent(
            group_id=group_id,
            generation_id=generation_id,
            target_formats=target_formats,
        )
        return self._persistent_smb_projection_authority.certify_member(
            token,
            target_formats=canonical_targets,
            lifecycle_binding_digest=lifecycle_binding_digest,
            lifecycle_binding_generation=lifecycle_binding_generation,
            network_binding_digest=network_binding_digest,
            network_binding_generation=network_binding_generation,
            traffic_binding_digest=traffic_binding_digest,
            traffic_binding_generation=traffic_binding_generation,
            topology_generation_digest=topology_digest,
            timing_planner=self.source_timing_planner,
            expected_timing_receipt=expected_timing_receipt,
        )

    def commit_persistent_smb_projection_member(
        self,
        certification: PersistentSmbProjectionMemberCertification,
    ) -> PersistentSmbProjectionMemberCommitReceipt:
        """Commit one certified member without invoking projection targets."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionMemberCertification,
        )

        if type(certification) is not PersistentSmbProjectionMemberCertification:
            raise EventContractError(
                "Persistent SMB certification is copied, foreign, tampered, or stale"
            )
        try:
            group_id = object.__getattribute__(certification, "group_id")
            generation_id = object.__getattribute__(certification, "generation_id")
            target_formats = object.__getattribute__(certification, "target_formats")
            certified_topology = object.__getattribute__(
                certification,
                "topology_generation_digest",
            )
            _targets, current_topology = self._persistent_smb_projection_target_intent(
                group_id=group_id,
                generation_id=generation_id,
                target_formats=target_formats,
            )
        except (AttributeError, EventContractError) as error:
            raise EventContractError(
                "Persistent SMB certification is copied, foreign, tampered, or stale"
            ) from error
        if type(certified_topology) is not str or not hmac.compare_digest(
            certified_topology, current_topology
        ):
            raise EventContractError("Persistent SMB certification topology is stale")
        return self._persistent_smb_projection_authority.commit_member(
            certification,
            timing_planner=self.source_timing_planner,
        )

    def recover_committed_persistent_smb_projection_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        operation_id: str,
        operation_binding_digest: str,
    ) -> PersistentSmbProjectionCommittedMemberRecovery:
        """Recover one exact committed-but-unacknowledged member receipt."""

        recovery = self._persistent_smb_projection_authority.recover_committed_member(
            group,
            operation_id=operation_id,
            operation_binding_digest=operation_binding_digest,
            timing_planner=self.source_timing_planner,
        )
        receipt = recovery.commit_receipt
        _targets, current_topology = self._persistent_smb_projection_target_intent(
            group_id=receipt.group_id,
            generation_id=receipt.generation_id,
            target_formats=receipt.target_formats,
        )
        if not hmac.compare_digest(receipt.topology_generation_digest, current_topology):
            raise EventContractError("Persistent SMB committed recovery topology is stale")
        return recovery

    def acknowledge_persistent_smb_projection_member(
        self,
        receipt: PersistentSmbProjectionMemberCommitReceipt,
        *,
        expected_generation_id: str,
    ) -> bool:
        """Generation-CAS acknowledge a future coordinator's durable handoff."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionMemberCommitReceipt,
        )

        if type(receipt) is not PersistentSmbProjectionMemberCommitReceipt:
            return False
        try:
            group_id = object.__getattribute__(receipt, "group_id")
            generation_id = object.__getattribute__(receipt, "generation_id")
            target_formats = object.__getattribute__(receipt, "target_formats")
            receipt_topology = object.__getattribute__(
                receipt,
                "topology_generation_digest",
            )
            _targets, current_topology = self._persistent_smb_projection_target_intent(
                group_id=group_id,
                generation_id=generation_id,
                target_formats=target_formats,
            )
        except (AttributeError, EventContractError):
            return False
        if type(receipt_topology) is not str or not hmac.compare_digest(
            receipt_topology, current_topology
        ):
            return False
        return self._persistent_smb_projection_authority.acknowledge_member(
            receipt,
            expected_generation_id=expected_generation_id,
            timing_planner=self.source_timing_planner,
        )

    def recover_inactive_persistent_smb_projection_member(
        self,
        group: PersistentSmbProjectionGroupToken,
        *,
        operation_id: str,
        operation_binding_digest: str,
    ) -> PersistentSmbProjectionMemberRecovery:
        """Resolve one exact same-operation append lost return in O(1)."""

        return self._persistent_smb_projection_authority.recover_inactive_member(
            group,
            operation_id=operation_id,
            operation_binding_digest=operation_binding_digest,
            timing_planner=self.source_timing_planner,
        )

    def cancel_persistent_smb_projection_member(
        self,
        token: PersistentSmbProjectionMemberToken,
    ) -> None:
        """Cancel one inactive member and reclaim its complete reservation."""

        self._persistent_smb_projection_authority.cancel_member(
            token,
            timing_planner=self.source_timing_planner,
        )

    def cancel_empty_persistent_smb_projection_group(
        self,
        group: PersistentSmbProjectionGroupToken,
    ) -> None:
        """Cancel one empty group before canonical open ownership exists."""

        try:
            group_id = object.__getattribute__(group, "group_id")
        except AttributeError as error:
            raise EventContractError(
                "Persistent SMB projection group is foreign, copied, or stale"
            ) from error
        with self._persistent_smb_group_lock:
            self._persistent_smb_projection_authority.cancel_empty_group(group)
            self._persistent_smb_retire_group_topology(group_id)
            if self._persistent_smb_projection_authority.census().retained_groups == 0:
                self._persistent_smb_retire_projection_topology()

    def persistent_smb_projection_group_census(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> PersistentSmbProjectionGroupCensus:
        """Return constant-time detached group and inactive-capacity counts."""

        if type(estimate_bytes) is not bool:
            raise EventContractError("estimate_bytes requires an exact bool")
        with self._persistent_smb_group_lock:
            with self._persistent_smb_topology_lock:
                retained_target_generations = len(self._persistent_smb_target_generations)
                target_semantic_bytes = (
                    self._persistent_smb_target_generation_semantic_bytes
                    + self._persistent_smb_group_topology_semantic_bytes
                    if estimate_bytes
                    else 0
                )
                target_table_backing_bytes = (
                    self._persistent_smb_target_generation_table_backing_bytes
                    if estimate_bytes
                    else 0
                )
                high_water_target_generations = self._persistent_smb_high_water_target_generations
                high_water_target_table_backing_bytes = (
                    self._persistent_smb_high_water_target_generation_table_backing_bytes
                )
            authority_census = self._persistent_smb_projection_authority.census(
                estimate_bytes=estimate_bytes,
            )
        return replace(
            authority_census,
            retained_target_generations=retained_target_generations,
            target_generation_capacity=self._persistent_smb_target_generation_capacity,
            high_water_target_generations=high_water_target_generations,
            target_generation_semantic_bytes=target_semantic_bytes,
            target_generation_table_backing_bytes=target_table_backing_bytes,
            high_water_target_generation_table_backing_bytes=(
                high_water_target_table_backing_bytes
            ),
            entry_semantic_bytes=(authority_census.entry_semantic_bytes + target_semantic_bytes),
            table_backing_bytes=(authority_census.table_backing_bytes + target_table_backing_bytes),
            estimated_bytes=(
                authority_census.estimated_bytes
                + target_semantic_bytes
                + target_table_backing_bytes
            ),
        )

    def _persistent_smb_source_publication_integrity(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
        record: _PersistentSmbSourcePublicationRecord,
    ) -> str:
        """Bind one opaque source-publication carrier to retained primitive facts."""

        payload = repr(
            (
                "persistent-smb-source-publication-v1",
                id(carrier),
                record.publication_id,
                record.group_id,
                record.generation_id,
                record.publication_key,
                record.publication_binding_digest,
                record.target_formats,
                tuple((digest, size) for _row, digest, size in record.row_facts),
                record.state,
                record.acknowledge_cursor,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _active_persistent_smb_source_publication_locked(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
    ) -> _PersistentSmbSourcePublicationRecord:
        """Resolve one intact exact source-publication carrier."""

        if type(carrier) is not PreparedPersistentSmbSourcePublication:
            raise EventContractError(
                "Persistent SMB source publication requires its exact opaque carrier"
            )
        publication_id = self._persistent_smb_source_publication_locators.get(id(carrier))
        record = (
            self._persistent_smb_source_publications.get(publication_id)
            if publication_id is not None
            else None
        )
        if record is None or record.carrier_ref() is not carrier:
            raise EventContractError("Persistent SMB source publication is stale")
        expected = self._persistent_smb_source_publication_integrity(carrier, record)
        if (
            carrier._dispatcher_token != id(self)
            or carrier._publication_id != record.publication_id
            or carrier._consumed
            or not hmac.compare_digest(carrier._integrity_token, expected)
            or not hmac.compare_digest(record.integrity_token, expected)
        ):
            raise EventContractError("Persistent SMB source publication integrity failed")
        return record

    def _acknowledged_persistent_smb_source_publication_locked(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
        result: PersistentSmbSourcePublicationResult,
    ) -> _PersistentSmbSourcePublicationRecord:
        """Resolve one exact acknowledged source terminal retained for its coordinator."""

        if (
            type(carrier) is not PreparedPersistentSmbSourcePublication
            or type(result) is not PersistentSmbSourcePublicationResult
        ):
            raise EventContractError(
                "Persistent SMB source terminal proof requires exact carrier and result types"
            )
        publication_id = self._persistent_smb_source_publication_locators.get(id(carrier))
        record = (
            self._persistent_smb_source_publications.get(publication_id)
            if publication_id is not None
            else None
        )
        if (
            record is None
            or record.carrier_ref() is not carrier
            or record.result is not result
            or record.state != "acknowledged"
            or record.active_thread_id is not None
            or not carrier._consumed
            or record.acknowledge_cursor != len(record.commit_receipts)
            or not record.exact_publication_batch.released
            or result._integrity != self._persistent_smb_source_result_integrity(result)
        ):
            raise EventContractError(
                "Persistent SMB source terminal proof is foreign, copied, incomplete, or stale"
            )
        expected = self._persistent_smb_source_publication_integrity(carrier, record)
        if (
            carrier._dispatcher_token != id(self)
            or carrier._publication_id != record.publication_id
            or not hmac.compare_digest(carrier._integrity_token, expected)
            or not hmac.compare_digest(record.integrity_token, expected)
        ):
            raise EventContractError("Persistent SMB source terminal proof integrity failed")
        return record

    def authenticates_acknowledged_persistent_smb_source_publication(
        self,
        carrier: object,
        result: object,
    ) -> bool:
        """Return whether this dispatcher retains the exact acknowledged source proof."""

        with self._persistent_smb_source_publication_lock:
            try:
                self._acknowledged_persistent_smb_source_publication_locked(carrier, result)
            except (AttributeError, EventContractError, TypeError, ValueError):
                return False
            return True

    def release_acknowledged_persistent_smb_source_publication_no_fail(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
        result: PersistentSmbSourcePublicationResult,
    ) -> None:
        """Release one exact terminal proof after its action continuation completes."""

        with self._persistent_smb_source_publication_lock:
            record = self._acknowledged_persistent_smb_source_publication_locked(carrier, result)
            self._persistent_smb_source_publications.pop(record.publication_id)
            self._persistent_smb_source_publication_locators.pop(record.carrier_id, None)
            self._persistent_smb_source_publication_keys.pop(
                (record.group_id, record.publication_key),
                None,
            )
            record.state = "released"

    def _persistent_smb_exact_projection_participants(
        self,
        projections: tuple[_PreparedProjection, ...],
        target_formats: tuple[str, ...],
    ) -> tuple[LogEmitter, ...]:
        """Require only exact closed SMB target types before staging any row."""

        expected_types = self._persistent_smb_projection_target_types()
        allowed = frozenset(target_formats)
        emitter_map = object.__getattribute__(self, "emitters")
        participants: list[LogEmitter] = []
        seen: set[int] = set()
        for target_format in target_formats:
            emitter = dict.get(emitter_map, target_format)
            if emitter is None or type(emitter) is not expected_types[target_format]:
                raise EventContractError(
                    f"Persistent SMB exact target {target_format!r} is absent or unsupported"
                )
            if id(emitter) not in seen:
                seen.add(id(emitter))
                participants.append(emitter)
        for projection in projections:
            for format_name, emitter in self._exact_projection_targets(projection):
                if (
                    format_name not in allowed
                    or type(emitter) is not expected_types.get(format_name)
                    or dict.get(emitter_map, format_name) is not emitter
                ):
                    raise EventContractError(
                        f"Persistent SMB projection leaked unsupported target {format_name!r}"
                    )
        return tuple(participants)

    def prepare_persistent_smb_source_publication(
        self,
        group: PersistentSmbProjectionGroupToken,
        projections: tuple[PreparedActionCohortProjection, ...],
        *,
        target_formats: tuple[str, ...],
        publication_key: str,
        publication_binding_digest: str,
    ) -> PreparedPersistentSmbSourcePublication:
        """Stage immutable filtered SMB rows without writing any public sink."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionGroupToken,
        )

        if type(group) is not PersistentSmbProjectionGroupToken:
            raise EventContractError("Persistent SMB source publication requires its exact group")
        if type(projections) is not tuple or not projections or len(projections) > 16:
            raise EventContractError(
                "Persistent SMB source publication requires a bounded non-empty projection tuple"
            )
        if any(type(item) is not PreparedActionCohortProjection for item in projections):
            raise EventContractError("Persistent SMB source projections require exact carriers")
        key = self._persistent_smb_bounded_utf8(
            publication_key,
            "persistent SMB source publication key",
            maximum=512,
        ).decode("utf-8")
        binding_digest = self._persistent_smb_sha256_digest(
            publication_binding_digest,
            "persistent SMB source publication binding digest",
        )
        if not self._persistent_smb_projection_authority.authenticates_group(group):
            raise EventContractError("Persistent SMB source publication group is foreign or stale")
        canonical_targets, _topology = self._persistent_smb_projection_target_intent(
            group_id=group.group_id,
            generation_id=group.generation_id,
            target_formats=target_formats,
        )
        with self._persistent_smb_source_publication_lock:
            existing_id = self._persistent_smb_source_publication_keys.get((group.group_id, key))
            existing = (
                self._persistent_smb_source_publications.get(existing_id)
                if existing_id is not None
                else None
            )
            if existing is not None:
                carrier = existing.carrier_ref()
                if (
                    carrier is not None
                    and existing.publication_binding_digest == binding_digest
                    and existing.target_formats == canonical_targets
                ):
                    self._active_persistent_smb_source_publication_locked(carrier)
                    return carrier
                raise EventContractError(
                    "Persistent SMB publication key names different retained source facts"
                )
            if (
                len(self._persistent_smb_source_publications)
                >= self._persistent_smb_source_publication_capacity
            ):
                raise EventContractError("Persistent SMB source publication capacity is exhausted")

        with self._action_cohort_lock:
            records = tuple(
                self._active_action_cohort_projection_locked(item) for item in projections
            )
        for record in records:
            if not self._action_cohort_projection_record_authenticates(record):
                raise EventContractError("Persistent SMB source projection failed authentication")
        trusted_projections = tuple(record.projection for record in records)
        participants = self._persistent_smb_exact_projection_participants(
            trusted_projections,
            canonical_targets,
        )
        batch = self._exact_publication_authority.issue_batch()
        try:
            batch.reserve_participants(cast(tuple[object, ...], participants))
            prepared = batch.prepare(
                lambda: tuple(
                    tuple(sorted(self._publish_action_cohort_projection(projection).items()))
                    for projection in trusted_projections
                )
            )
            if (
                type(prepared) is not tuple
                or len(prepared) != len(trusted_projections)
                or any(type(items) is not tuple for items in prepared)
                or any(
                    type(item) is not tuple
                    or len(item) != 2
                    or type(item[0]) is not str
                    or type(item[1]) is not str
                    for items in prepared
                    for item in items
                )
            ):
                raise EventContractError("Persistent SMB exact projection returned malformed IDs")
            projection_identifiers = cast(
                tuple[tuple[tuple[str, str], ...], ...],
                prepared,
            )
            row_facts = batch._prepared_row_facts()
            retained_bytes = sum(size for _row, _digest, size in row_facts)

            with self._action_cohort_lock:
                for carrier, record in zip(projections, records, strict=True):
                    if self._active_action_cohort_projection_locked(carrier) is not record:
                        raise EventContractError(
                            "Persistent SMB source projection changed during exact staging"
                        )
                timing_preparations = {
                    id(record.source_timing_preparation): record.source_timing_preparation
                    for record in records
                }
                if len(timing_preparations) != 1:
                    raise EventContractError(
                        "Persistent SMB source projections require one shared timing owner"
                    )
                timing_preparation = next(iter(timing_preparations.values()))
                expected_preparation_ids = {record.preparation_id for record in records}
                if (
                    self._action_cohort_projection_groups.get(id(timing_preparation))
                    != expected_preparation_ids
                ):
                    raise EventContractError(
                        "Persistent SMB source projection timing group is incomplete"
                    )
                with self._persistent_smb_source_publication_lock:
                    if (group.group_id, key) in self._persistent_smb_source_publication_keys:
                        raise EventContractError(
                            "Persistent SMB source publication was installed concurrently"
                        )
                    publication_id = self._next_persistent_smb_source_publication_id
                    self._next_persistent_smb_source_publication_id += 1
                    carrier = PreparedPersistentSmbSourcePublication(
                        dispatcher_token=id(self),
                        publication_id=publication_id,
                        integrity_token="",
                    )
                    publication = _PersistentSmbSourcePublicationRecord(
                        publication_id=publication_id,
                        carrier_id=id(carrier),
                        carrier_ref=ref(carrier),
                        group=group,
                        group_id=group.group_id,
                        generation_id=group.generation_id,
                        publication_key=key,
                        publication_binding_digest=binding_digest,
                        target_formats=canonical_targets,
                        exact_publication_batch=batch,
                        projections=trusted_projections,
                        projection_identifiers=projection_identifiers,
                        row_facts=row_facts,
                        retained_bytes=retained_bytes,
                        integrity_token="",
                    )
                    integrity = self._persistent_smb_source_publication_integrity(
                        carrier,
                        publication,
                    )
                    publication.integrity_token = integrity
                    carrier._integrity_token = integrity
                    self._persistent_smb_source_publications[publication_id] = publication
                    self._persistent_smb_source_publication_locators[id(carrier)] = publication_id
                    self._persistent_smb_source_publication_keys[(group.group_id, key)] = (
                        publication_id
                    )
                    self._persistent_smb_source_retained_rows += len(row_facts)
                    self._persistent_smb_source_retained_bytes += retained_bytes
                    detached = self._detach_action_cohort_projection_group_locked(
                        timing_preparation,
                        terminal_state="persistent_smb_bound",
                    )
                    if {record.preparation_id for record in detached} != expected_preparation_ids:
                        raise EventContractError(
                            "Persistent SMB source projection timing group changed during binding"
                        )
                    return carrier
        except BaseException:
            if batch.state in {"issued", "ready"}:
                batch.cancel()
            raise

    def _persistent_smb_commit_receipts(
        self,
        record: _PersistentSmbSourcePublicationRecord,
        receipts: tuple[PersistentSmbProjectionMemberCommitReceipt, ...],
    ) -> tuple[PersistentSmbProjectionMemberCommitReceipt, ...]:
        """Authenticate one complete ordered committed-member receipt tuple."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionMemberCommitReceipt,
        )

        if type(receipts) is not tuple or not receipts or len(receipts) > 16:
            raise EventContractError(
                "Persistent SMB publication requires committed member receipts"
            )
        if any(
            type(receipt) is not PersistentSmbProjectionMemberCommitReceipt for receipt in receipts
        ):
            raise EventContractError("Persistent SMB committed member receipts require exact types")
        ordered = tuple(sorted(receipts, key=lambda receipt: receipt.member_ordinal))
        if len({receipt.member_ordinal for receipt in ordered}) != len(ordered):
            raise EventContractError("Persistent SMB committed member ordinals must be unique")
        for receipt in ordered:
            if (
                receipt.group_id != record.group_id
                or receipt.generation_id != record.generation_id
                or receipt.target_formats != record.target_formats
            ):
                raise EventContractError(
                    "Persistent SMB committed member disagrees with source batch"
                )
            recovery = self.recover_committed_persistent_smb_projection_member(
                record.group,
                operation_id=receipt.operation_id,
                operation_binding_digest=receipt.operation_binding_digest,
            )
            if recovery.commit_receipt is not receipt:
                raise EventContractError("Persistent SMB committed member receipt is not canonical")
        return ordered

    def _persistent_smb_source_result_integrity(
        self,
        result: PersistentSmbSourcePublicationResult,
    ) -> str:
        payload = repr(
            (
                "persistent-smb-source-result-v1",
                id(result),
                result.group_id,
                result.generation_id,
                result.publication_key,
                result.publication_binding_digest,
                result.target_formats,
                result.member_operation_ids,
                tuple((digest, size) for _row, digest, size in result.row_facts),
                result.projection_identifiers,
                result.publication_digest,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def publish_persistent_smb_source_publication(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
        *,
        commit_receipts: tuple[PersistentSmbProjectionMemberCommitReceipt, ...],
    ) -> PersistentSmbSourcePublicationResult:
        """Resume exact sink admission after every group member is committed."""

        owner_thread = get_ident()
        with self._persistent_smb_source_publication_lock:
            record = self._active_persistent_smb_source_publication_locked(carrier)
            if record.active_thread_id is not None:
                raise EventContractError("Persistent SMB source publication is already active")
            canonical_receipts = self._persistent_smb_commit_receipts(record, commit_receipts)
            if record.commit_receipts and record.commit_receipts != canonical_receipts:
                raise EventContractError("Persistent SMB source publication receipt tuple changed")
            if record.result is None:
                publication_digest = hashlib.sha256(
                    repr(
                        (
                            record.group_id,
                            record.generation_id,
                            record.publication_binding_digest,
                            record.target_formats,
                            tuple(
                                receipt.operation_binding_digest for receipt in canonical_receipts
                            ),
                            tuple((digest, size) for _row, digest, size in record.row_facts),
                        )
                    ).encode("utf-8")
                ).hexdigest()
                result = PersistentSmbSourcePublicationResult(
                    group_id=record.group_id,
                    generation_id=record.generation_id,
                    publication_key=record.publication_key,
                    publication_binding_digest=record.publication_binding_digest,
                    target_formats=record.target_formats,
                    member_operation_ids=tuple(
                        receipt.operation_id for receipt in canonical_receipts
                    ),
                    row_facts=record.row_facts,
                    projection_identifiers=record.projection_identifiers,
                    publication_digest=publication_digest,
                )
                object.__setattr__(
                    result,
                    "_integrity",
                    self._persistent_smb_source_result_integrity(result),
                )
                record.result = result
                record.commit_receipts = canonical_receipts
            record.active_thread_id = owner_thread
            record.state = "publishing"
            integrity = self._persistent_smb_source_publication_integrity(carrier, record)
            record.integrity_token = integrity
            carrier._integrity_token = integrity
            result = record.result
        assert result is not None
        try:
            record.exact_publication_batch.commit()
            with self._persistent_smb_source_publication_lock:
                if self._active_persistent_smb_source_publication_locked(carrier) is not record:
                    raise EventContractError("Persistent SMB source ownership changed after commit")
                record.state = "published"
                record.active_thread_id = None
                integrity = self._persistent_smb_source_publication_integrity(carrier, record)
                record.integrity_token = integrity
                carrier._integrity_token = integrity
            return result
        except BaseException:
            with self._persistent_smb_source_publication_lock:
                if record.active_thread_id == owner_thread:
                    record.active_thread_id = None
                    record.state = (
                        "published"
                        if record.exact_publication_batch.state == "committed"
                        else "prepared"
                    )
                    integrity = self._persistent_smb_source_publication_integrity(carrier, record)
                    record.integrity_token = integrity
                    carrier._integrity_token = integrity
            raise

    def authenticates_published_persistent_smb_source_publication(
        self,
        carrier: object,
        result: object,
    ) -> bool:
        """Return whether the exact source result is published and awaits acknowledgement."""

        with self._persistent_smb_source_publication_lock:
            try:
                record = self._active_persistent_smb_source_publication_locked(carrier)
            except (AttributeError, EventContractError, TypeError, ValueError):
                return False
            return bool(
                type(result) is PersistentSmbSourcePublicationResult
                and record.state == "published"
                and record.result is result
                and result._integrity == self._persistent_smb_source_result_integrity(result)
                and record.exact_publication_batch.state == "committed"
            )

    def acknowledge_persistent_smb_source_publication(
        self,
        carrier: PreparedPersistentSmbSourcePublication,
        result: PersistentSmbSourcePublicationResult,
    ) -> bool:
        """Release exact rows, generation-CAS acknowledge members, and retire the group."""

        with self._persistent_smb_source_publication_lock:
            try:
                record = self._active_persistent_smb_source_publication_locked(carrier)
            except EventContractError:
                return False
            if (
                record.state != "published"
                or record.result is not result
                or result._integrity != self._persistent_smb_source_result_integrity(result)
                or record.exact_publication_batch.state != "committed"
            ):
                raise EventContractError(
                    "Persistent SMB source acknowledgement requires its exact published result"
                )
            receipts = record.commit_receipts
        try:
            record.exact_publication_batch.release_no_fail()
        except BaseException:
            if not record.exact_publication_batch.released:
                raise
        while record.acknowledge_cursor < len(receipts):
            receipt = receipts[record.acknowledge_cursor]
            acknowledged = False
            try:
                acknowledged = self.acknowledge_persistent_smb_projection_member(
                    receipt,
                    expected_generation_id=record.generation_id,
                )
            except BaseException:
                try:
                    recovery = self.recover_committed_persistent_smb_projection_member(
                        record.group,
                        operation_id=receipt.operation_id,
                        operation_binding_digest=receipt.operation_binding_digest,
                    )
                except EventContractError:
                    acknowledged = True
                else:
                    if recovery.commit_receipt is receipt:
                        raise
            if not acknowledged:
                try:
                    self.recover_committed_persistent_smb_projection_member(
                        record.group,
                        operation_id=receipt.operation_id,
                        operation_binding_digest=receipt.operation_binding_digest,
                    )
                except EventContractError:
                    acknowledged = True
            if not acknowledged:
                raise EventContractError("Persistent SMB member acknowledgement did not commit")
            record.acknowledge_cursor += 1
            with self._persistent_smb_source_publication_lock:
                integrity = self._persistent_smb_source_publication_integrity(carrier, record)
                record.integrity_token = integrity
                carrier._integrity_token = integrity
        try:
            self.cancel_empty_persistent_smb_projection_group(record.group)
        except BaseException:
            if self._persistent_smb_projection_authority.authenticates_group(record.group):
                raise
        with self._persistent_smb_source_publication_lock:
            if self._persistent_smb_source_publications.get(record.publication_id) is not record:
                return False
            self._persistent_smb_source_retained_rows -= len(record.row_facts)
            self._persistent_smb_source_retained_bytes -= record.retained_bytes
            record.state = "acknowledged"
            carrier._consumed = True
            integrity = self._persistent_smb_source_publication_integrity(carrier, record)
            record.integrity_token = integrity
            carrier._integrity_token = integrity
        return True

    def persistent_smb_source_publication_census(
        self,
    ) -> PersistentSmbSourcePublicationCensus:
        """Return constant-time exact-source retention counts."""

        with self._persistent_smb_source_publication_lock:
            records = tuple(self._persistent_smb_source_publications.values())
            return PersistentSmbSourcePublicationCensus(
                active_publications=sum(record.active_thread_id is not None for record in records),
                prepared_publications=sum(record.state == "prepared" for record in records),
                published_unacknowledged=sum(
                    record.state in {"publishing", "published"} for record in records
                ),
                acknowledged_terminal_proofs=sum(
                    record.state == "acknowledged" for record in records
                ),
                retained_rows=self._persistent_smb_source_retained_rows,
                retained_bytes=self._persistent_smb_source_retained_bytes,
                capacity=self._persistent_smb_source_publication_capacity,
            )

    @property
    def source_evidence_status(self) -> dict[str, dict[str, dict[str, int]]]:
        """Return source evidence status summaries for ground truth generation."""
        with self._source_evidence_lock:
            return {
                cluster_id: {
                    source: summary.as_dict()
                    for source, summary in sorted(source_summaries.items())
                    if summary.as_dict()
                }
                for cluster_id, source_summaries in sorted(self._source_evidence_status.items())
            }

    @property
    def contract_violation_counts(self) -> dict[str, int]:
        """Return shadow contract discrepancies without enabling enforcement."""

        return dict(sorted(self._contract_violation_counts.items()))

    @property
    def contract_violations_by_event(self) -> dict[str, dict[str, int]]:
        """Return shadow discrepancies grouped by event kind and stable violation code."""

        result: dict[str, dict[str, int]] = {}
        for (event_type, code), count in sorted(self._contract_violations_by_event.items()):
            result.setdefault(event_type, {})[code] = count
        return result

    @property
    def lifecycle_shadow_violation_summary(self) -> LifecycleShadowViolationSummary:
        """Return bounded lifecycle parity diagnostics for manifests and ground truth."""

        if self._lifecycle_shadow is None:
            return {"total": 0, "by_code": {}, "by_event": {}}
        return self._lifecycle_shadow.violation_summary

    @property
    def lifecycle_shadow(self) -> LifecycleShadow | None:
        """Return the bound lifecycle adapter before mutable state is rendered."""

        return self._lifecycle_shadow

    @property
    def enforces_lifecycle_authority(self) -> bool:
        """Return whether every lifecycle occurrence is a pre-apply hard gate."""

        return self._enforce_lifecycle_authority

    def bind_lifecycle_shadow(self, lifecycle_shadow: LifecycleShadow) -> None:
        """Bind one shared lifecycle adapter before the first dispatch."""

        if self._lifecycle_shadow is not None and self._lifecycle_shadow is not lifecycle_shadow:
            raise ValueError("EventDispatcher already owns a different LifecycleShadow")
        self._lifecycle_shadow = lifecycle_shadow

    def bind_lifecycle_authority(self, authority: GeneratorLifecycleAuthority) -> None:
        """Bind the sole keyed verifier for externally materialized start receipts."""

        if self._lifecycle_authority is not None and self._lifecycle_authority is not authority:
            raise ValueError("EventDispatcher already owns a different lifecycle authority")
        if (
            self._lifecycle_shadow is not None
            and authority.registry is not self._lifecycle_shadow.registry
        ):
            raise ValueError("EventDispatcher lifecycle authority must share its registry")
        self._lifecycle_authority = authority

    def authenticates_lifecycle_authority_owner(self, authority: object) -> bool:
        """Return whether ``authority`` is this dispatcher's exact receipt verifier."""

        return self._lifecycle_authority is authority

    def bind_execution_effect_audit(self, audit: ExecutionEffectAuditCounter) -> None:
        """Bind the generator-owned bounded publication/reconciliation denominator."""

        if self._execution_effect_audit is not None and self._execution_effect_audit is not audit:
            raise ValueError("EventDispatcher already owns a different execution-effect audit")
        self._execution_effect_audit = audit

    def bind_lifecycle_strict_predicate(
        self,
        predicate: Callable[[CanonicalOccurrence], bool],
    ) -> None:
        """Enable hard lifecycle gates only for explicitly migrated identities."""

        if (
            self._lifecycle_strict_predicate is not None
            and self._lifecycle_strict_predicate is not predicate
        ):
            raise ValueError("EventDispatcher lifecycle strict predicate is already bound")
        self._lifecycle_strict_predicate = predicate

    def network_identifier_for_format(
        self,
        canonical_uid: str,
        format_name: str,
    ) -> str | None:
        """Return the latest sensor-local UID, blank if suppressed, or None if unavailable."""

        with self._publication_ledger_lock:
            if canonical_uid != self._latest_network_uid:
                return None
            return self._latest_network_identifiers_by_format.get(format_name)

    def publish_network_identifiers(
        self,
        canonical_uid: str,
        identifiers_by_format: dict[str, str],
    ) -> None:
        """Publish one completed connection's observation identifiers for its caller."""

        with self._publication_ledger_lock:
            self._latest_network_uid = canonical_uid
            self._latest_network_identifiers_by_format = identifiers_by_format

    def network_observations_for(
        self,
        canonical_uid: str,
    ) -> tuple[NetworkSensorObservation, ...]:
        """Return the latest transport's frozen sensor observations.

        Higher-level protocol bundles call this immediately after creating their
        canonical transport. Reusing the transport observation prevents each
        application phase from independently jittering the same connection.
        """

        with self._publication_ledger_lock:
            if canonical_uid != self._latest_network_observations_uid:
                return ()
            return self._latest_network_observations

    @staticmethod
    def _publishes_network_sensor_observations(event: CanonicalOccurrence) -> bool:
        """Return whether this occurrence owns the transport's sensor projection.

        Endpoint companions such as WFP 5156 reuse the canonical network plan, but
        they do not own the sensor observation. Letting those companions publish an
        empty plan erases the exact UID/clock projection before an application bundle
        can consume it.
        """

        return bool(
            event.network is not None
            and not event.network.application_layer_only
            and event.event_type in _NETWORK_SENSOR_TRANSPORT_EVENT_TYPES
        )

    def network_plan_for(self, canonical_uid: str) -> NetworkTransactionPlan | None:
        """Return the latest canonical transport plan for immediate composition."""

        with self._publication_ledger_lock:
            plan = self._latest_network_plan
            if plan is None or plan.zeek_uid != canonical_uid:
                return None
            return plan

    def record_filtered_network_observation(self) -> None:
        """Record that a storyline network event was filtered before emitter dispatch.

        Some caller paths skip unobservable network connections before building a
        full OccurrenceBuilder. The manifest still needs a source-status entry so
        eval can distinguish expected sensor-placement loss from missing evidence.
        """
        for format_name in self.emitters:
            if format_name in _NETWORK_FORMATS:
                self._record_cluster_observation(format_name, "filtered")

    def _is_suppressed(self, timestamp: datetime) -> bool:
        """Return True if the event falls before the output window (warm-up period)."""
        if self.output_start_time is None:
            return False
        # Normalize tz-awareness to avoid naive/aware comparison errors
        ts = timestamp
        gate = self.output_start_time
        if ts.tzinfo is not None and gate.tzinfo is None:
            ts = ts.replace(tzinfo=None)
        elif ts.tzinfo is None and gate.tzinfo is not None:
            gate = gate.replace(tzinfo=None)
        return ts < gate

    def dispatch_builder(self, event: OccurrenceBuilder) -> dict[str, str]:
        """Prepare then immediately publish one builder through the compatibility path."""

        return self.publish_prepared(self.prepare_builder(event, _defer_projection=True))

    def _freeze_authored_intent_id(
        self,
        value: object = _CURRENT_AUTHORED_INTENT,
    ) -> str | None:
        """Return one exact intent attribution snapshot for prepared publication."""

        candidate = self.authored_intent_id if value is _CURRENT_AUTHORED_INTENT else value
        if candidate is None or type(candidate) is str:
            return candidate or None
        raise EventContractError(
            "Prepared dispatch authored intent ID must be an exact str or None"
        )

    def prepare_builder(
        self,
        event: OccurrenceBuilder,
        *,
        expected_state_version: int | None = None,
        state_intent: PreparedDispatchStateIntent = PreparedDispatchStateIntent.APPLY,
        lifecycle_ticket: object | None = None,
        artifact_publications: tuple[LocalArtifactPublishToken, ...] = (),
        source_timing_preparation: SourceTimingPreparation | None = None,
        _defer_projection: bool = False,
    ) -> PreparedDispatch:
        """Freeze one exact dispatch without mutating canonical publication truth.

        ``source_timing_preparation`` must be the active preparation of this
        dispatcher's planner. Its projection writes remain staged until an outer
        State/Lifecycle coordinator commits that preparation.
        """

        authored_intent_id = self._freeze_authored_intent_id()
        artifact_publications = tuple(artifact_publications)
        if self.storyline_cluster_id and event.storyline_cluster_id is None:
            event.storyline_cluster_id = self.storyline_cluster_id
        self._finalize_network_routing(event)
        prepared_binary = self._bind_artifact_publications(event, artifact_publications)
        binary_identity_kind = self._attach_process_binary_identity(
            event,
            prepared_binary=prepared_binary,
        )
        self._attach_image_load_binary_identity(event)
        self.identity_lifecycle_planner.plan(event)
        if event.occurrence_key is None:
            event.occurrence_key = self._derive_occurrence_key(
                event,
                authored_intent_id=authored_intent_id,
            )
        event.contract_seal = shadow_seal(event)
        if event.contract_seal.violations:
            details = "; ".join(violation.message for violation in event.contract_seal.violations)
            raise EventContractError(f"Cannot dispatch invalid canonical event: {details}")
        return self.prepare_occurrence(
            event.seal(),
            expected_state_version=expected_state_version,
            state_intent=state_intent,
            lifecycle_ticket=lifecycle_ticket,
            binary_identity_kind=binary_identity_kind,
            artifact_publications=artifact_publications,
            source_timing_preparation=source_timing_preparation,
            _authored_intent_id=authored_intent_id,
            _defer_projection=_defer_projection,
        )

    @staticmethod
    def _action_cohort_projection_retained_size(
        occurrence: CanonicalOccurrence,
        projection: _PreparedProjection,
        facts: ActionCohortProjectionFacts,
    ) -> int:
        """Charge the complete retained canonical, projection, and facts payload."""

        retained_payload = (
            repr(occurrence).encode("utf-8"),
            repr(EventDispatcher._prepared_projection_signature(projection)).encode("utf-8"),
            repr(facts).encode("utf-8"),
        )
        return 1_024 + sum(len(item) for item in retained_payload)

    @staticmethod
    def _action_cohort_occurrence_digest(occurrence: CanonicalOccurrence) -> str:
        """Return a closed digest of one exact canonical occurrence."""

        if type(occurrence) is not CanonicalOccurrence:
            raise EventContractError("Action-cohort occurrence must be exact and sealed")
        return hashlib.sha256(repr(occurrence).encode("utf-8")).hexdigest()

    def _action_cohort_projection_digest(self, projection: _PreparedProjection) -> str:
        """Return a closed digest of every frozen projection member."""

        if type(projection) is not _PreparedProjection:
            raise EventContractError("Action-cohort projection plan must be exact")
        signature = self._prepared_projection_signature(projection)
        return hashlib.sha256(repr(signature).encode("utf-8")).hexdigest()

    @staticmethod
    def _action_cohort_timing_digest(
        preparation: SourceTimingPreparation,
    ) -> str:
        """Return a closed digest of the exact timing owner token."""

        token = preparation.binding_token
        signature = (
            type(token).__module__,
            type(token).__qualname__,
            getattr(token, "preparation_id", None),
            getattr(token, "base_state_digest", None),
            getattr(token, "_integrity", None),
        )
        return hashlib.sha256(repr(signature).encode("utf-8")).hexdigest()

    def _action_cohort_compiled_projection_status(
        self,
        occurrence: CanonicalOccurrence,
        target: _ProjectionTarget,
    ) -> ObservationStatus:
        """Return the already-determined terminal status of one compiled target."""

        envelope = target.envelope
        if envelope is None:
            return "filtered"
        if not envelope.admitted:
            return (
                "out_of_window"
                if envelope.admission is ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW
                else "filtered"
            )
        if not target.topology_visible:
            return "filtered"
        decision = target.decision
        if decision is None or decision.status == "dropped":
            return "dropped"
        if target.source_timing is None or target.projected_timestamp is None:
            raise EventContractError("Admitted action-cohort source timing is incomplete")
        target_occurrence = replace(
            occurrence,
            timestamp=target.projected_timestamp,
            source_timing=target.source_timing,
            network_observations=(
                target.network_observations
                if target.network_observations is not None
                else occurrence.network_observations
            ),
        )
        if not self._admit_projection_target(target_occurrence, target):
            return "out_of_window"
        return "delayed" if decision.delay.total_seconds() > 0 else "visible"

    @staticmethod
    def _action_cohort_finalized_times(
        occurrence: CanonicalOccurrence | None,
    ) -> tuple[tuple[str, datetime], ...]:
        """Copy exact finalized render-key times into an immutable ordered tuple."""

        timing = None if occurrence is None else occurrence.source_timing
        if timing is None:
            return ()
        items = tuple(timing.finalized_times.items())
        if any(type(key) is not str or type(value) is not datetime for key, value in items):
            raise EventContractError("Action-cohort source timing facts are malformed")
        return tuple(sorted(items))

    def _action_cohort_projection_facts(
        self,
        occurrence: CanonicalOccurrence,
        projection: _PreparedProjection,
    ) -> ActionCohortProjectionFacts:
        """Build a detached immutable view without exposing projection internals."""

        sources: list[ActionCohortSourceProjectionFacts] = []
        if projection.mode == "legacy":
            for source_ordinal, target in enumerate(projection.legacy_targets):
                target_occurrence = target.occurrence
                sources.append(
                    ActionCohortSourceProjectionFacts(
                        format_name=target.format_name,
                        source_ordinal=source_ordinal,
                        status=target.status,
                        projected_timestamp=(
                            None if target_occurrence is None else target_occurrence.timestamp
                        ),
                        finalized_times=self._action_cohort_finalized_times(target_occurrence),
                    )
                )
        elif projection.mode == "compiled":
            for target in projection.compiled_targets:
                target_occurrence = (
                    None
                    if target.source_timing is None
                    else replace(
                        projection.occurrence,
                        timestamp=target.projected_timestamp or projection.occurrence.timestamp,
                        source_timing=target.source_timing,
                    )
                )
                sources.append(
                    ActionCohortSourceProjectionFacts(
                        format_name=target.format_name,
                        source_ordinal=target.source_ordinal,
                        status=self._action_cohort_compiled_projection_status(
                            projection.occurrence,
                            target,
                        ),
                        projected_timestamp=target.projected_timestamp,
                        finalized_times=self._action_cohort_finalized_times(target_occurrence),
                    )
                )
        elif projection.mode != "suppressed":
            raise EventContractError("Action-cohort projection mode is unsupported")
        return ActionCohortProjectionFacts(
            occurrence=occurrence,
            initial_statuses=tuple(projection.initial_statuses),
            sources=tuple(sources),
            disposition=(
                ActionCohortProjectionDisposition.EXACT_WARMUP_SUPPRESSED
                if self._projection_is_exact_warmup_suppressed(projection)
                else ActionCohortProjectionDisposition.SOURCE_FRONTIERS_REQUIRED
            ),
        )

    def _action_cohort_admitted_source_events(
        self,
        projection: _PreparedProjection,
    ) -> tuple[tuple[CanonicalOccurrence, str], ...]:
        """Return exact source events whose timing effects must stage before seal."""

        admitted: list[tuple[CanonicalOccurrence, str]] = []
        if projection.mode == "legacy":
            admitted.extend(
                (target.occurrence, target.format_name)
                for target in projection.legacy_targets
                if target.occurrence is not None
            )
            return tuple(admitted)
        if projection.mode == "suppressed":
            return ()
        if projection.mode != "compiled":
            raise EventContractError("Action-cohort projection mode is unsupported")
        event = projection.occurrence
        for target in projection.compiled_targets:
            envelope = target.envelope
            decision = target.decision
            if (
                envelope is None
                or not envelope.admitted
                or not target.topology_visible
                or decision is None
                or decision.status == "dropped"
                or target.source_timing is None
                or target.projected_timestamp is None
            ):
                continue
            event_to_emit = replace(
                event,
                timestamp=target.projected_timestamp,
                source_timing=target.source_timing,
                network_observations=(
                    target.network_observations
                    if target.network_observations is not None
                    else event.network_observations
                ),
            )
            if not self._admit_projection_target(event_to_emit, target):
                continue
            status: ObservationStatus = (
                "delayed" if decision.delay.total_seconds() > 0 else "visible"
            )
            admitted.append(
                (
                    replace(
                        event_to_emit,
                        _source_observation_status=status,
                        _projection_envelope=envelope,
                    ),
                    target.format_name,
                )
            )
        return tuple(admitted)

    def _stage_action_cohort_projection_timing(
        self,
        projection: _PreparedProjection,
        preparation: SourceTimingPreparation,
    ) -> None:
        """Stage admitted-source indexes in the timing owner's private overlay."""

        for source_event, format_name in self._action_cohort_admitted_source_events(projection):
            preparation.record_admitted_source_event(source_event, format_name)

    def _action_cohort_projection_observation_deltas(
        self,
        projection: _PreparedProjection,
    ) -> tuple[_ActionCohortObservationDelta, ...]:
        """Derive the exact legacy-compatible summary order before publication."""

        event = projection.occurrence
        cluster_id = event.storyline_cluster_id
        if not cluster_id:
            return ()
        deltas: list[_ActionCohortObservationDelta] = [
            _ActionCohortObservationDelta(
                cluster_id=cluster_id,
                source=source_family_for_format(format_name),
                status=status,
                timestamp=event.timestamp,
            )
            for format_name, status in projection.initial_statuses
        ]
        if projection.mode == "suppressed":
            return tuple(deltas)
        if projection.mode == "legacy":
            deltas.extend(
                _ActionCohortObservationDelta(
                    cluster_id=cluster_id,
                    source=source_family_for_format(target.format_name),
                    status=target.status,
                    timestamp=event.timestamp,
                )
                for target in projection.legacy_targets
            )
            return tuple(deltas)
        if projection.mode != "compiled":
            raise EventContractError("Action-cohort projection mode is unsupported")
        statuses: dict[str, ObservationStatus] = {}
        for target in projection.compiled_targets:
            self._merge_projection_status(
                statuses,
                target.format_name,
                self._action_cohort_compiled_projection_status(event, target),
            )
        deltas.extend(
            _ActionCohortObservationDelta(
                cluster_id=cluster_id,
                source=source_family_for_format(format_name),
                status=status,
                timestamp=event.timestamp,
            )
            for format_name, status in statuses.items()
        )
        return tuple(deltas)

    @staticmethod
    def _action_cohort_observation_digest(
        deltas: tuple[_ActionCohortObservationDelta, ...],
    ) -> str:
        """Bind the complete ordered summary/intent observation delta."""

        payload = tuple(
            (delta.cluster_id, delta.source, delta.status, delta.timestamp) for delta in deltas
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _action_cohort_facts_digest(facts: ActionCohortProjectionFacts) -> str:
        """Return a closed digest of a detached projection-facts view."""

        return hashlib.sha256(repr(facts).encode("utf-8")).hexdigest()

    def _action_cohort_projection_integrity(
        self,
        carrier: PreparedActionCohortProjection,
        record: _PreparedActionCohortProjectionRecord,
    ) -> str:
        """Bind one exact carrier object to callback-free canonical digests."""

        payload = repr(
            (
                "prepared-action-cohort-projection-v2",
                id(carrier),
                record.preparation_id,
                record.owner_thread_id,
                record.authored_intent_id,
                record.binary_identity_kind,
                record.occurrence_digest,
                record.projection_digest,
                record.facts_digest,
                record.timing_digest,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def prepare_action_cohort_projection(
        self,
        event: OccurrenceBuilder,
        *,
        source_timing_preparation: SourceTimingPreparation,
        _persistent_smb_target_formats: tuple[str, ...] | None = None,
    ) -> PreparedActionCohortProjection:
        """Freeze one State-neutral projection for later exact cohort-plan binding.

        The returned carrier exposes no mutable builder.  Its immutable occurrence may be
        inspected through :meth:`action_cohort_projection_occurrence` solely to derive State
        metadata such as a source-ready frontier before the State cohort is sealed.
        """

        from evidenceforge.generation.source_timing import SourceTimingPreparation

        if type(event) is not OccurrenceBuilder:
            raise TypeError("Action-cohort projection preflight requires an OccurrenceBuilder")
        if type(source_timing_preparation) is not SourceTimingPreparation:
            raise EventContractError("Action-cohort projection requires exact source timing")
        if not self.source_timing_planner.is_active_preparation(source_timing_preparation):
            raise EventContractError(
                "Action-cohort projection source timing must be the active preparation"
            )

        with self._action_cohort_lock:
            active_preparations = (
                len(self._action_cohort_batches)
                + len(self._action_cohort_prepare_cleanups)
                + len(self._action_cohort_projections)
            )
            if active_preparations >= self._action_cohort_preparation_capacity:
                raise EventContractError(
                    "Action-cohort projection preparation capacity is exhausted"
                )
            if (
                self._action_cohort_retained_members + len(self._action_cohort_projections) + 1
                > self._action_cohort_member_capacity
            ):
                raise EventContractError("Action-cohort projection member capacity is exhausted")

        try:
            authored_intent_id = self._freeze_authored_intent_id()
            if self.storyline_cluster_id and event.storyline_cluster_id is None:
                event.storyline_cluster_id = self.storyline_cluster_id
            self._finalize_network_routing(event)
            binary_identity_kind = self._attach_process_binary_identity(event)
            self._attach_image_load_binary_identity(event)
            self.identity_lifecycle_planner.plan(event)
            if event.occurrence_key is None:
                event.occurrence_key = self._derive_occurrence_key(
                    event,
                    authored_intent_id=authored_intent_id,
                )
            event.contract_seal = shadow_seal(event)
            if event.contract_seal.violations:
                details = "; ".join(
                    violation.message for violation in event.contract_seal.violations
                )
                raise EventContractError(f"Cannot preflight invalid canonical event: {details}")
            occurrence = event.seal()
            allowed_formats = (
                None
                if _persistent_smb_target_formats is None
                else frozenset(_persistent_smb_target_formats)
            )
            projection = self._prepare_projection(
                occurrence,
                allowed_formats=allowed_formats,
            )
            self._stage_action_cohort_projection_timing(
                projection,
                source_timing_preparation,
            )
            facts = self._action_cohort_projection_facts(occurrence, projection)
            occurrence_digest = self._action_cohort_occurrence_digest(occurrence)
            projection_digest = self._action_cohort_projection_digest(projection)
            facts_digest = self._action_cohort_facts_digest(facts)
            timing_digest = self._action_cohort_timing_digest(source_timing_preparation)
            retained_bytes = self._action_cohort_projection_retained_size(
                occurrence,
                projection,
                facts,
            )
            with self._action_cohort_lock:
                active_preparations = (
                    len(self._action_cohort_batches)
                    + len(self._action_cohort_prepare_cleanups)
                    + len(self._action_cohort_projections)
                )
                if active_preparations >= self._action_cohort_preparation_capacity:
                    raise EventContractError(
                        "Action-cohort projection preparation capacity is exhausted"
                    )
                if (
                    self._action_cohort_retained_members + len(self._action_cohort_projections) + 1
                    > self._action_cohort_member_capacity
                ):
                    raise EventContractError(
                        "Action-cohort projection member capacity is exhausted"
                    )
                if (
                    self._action_cohort_projection_retained_bytes
                    + self._action_cohort_retained_bytes
                    + retained_bytes
                    > self._action_cohort_byte_capacity
                ):
                    raise EventContractError(
                        "Action-cohort projection retained-byte capacity is exhausted"
                    )
                preparation_id = self._next_action_cohort_projection_id
                self._next_action_cohort_projection_id += 1
                carrier = PreparedActionCohortProjection(
                    dispatcher_token=id(self),
                    preparation_id=preparation_id,
                    integrity_token="",
                )
                record = _PreparedActionCohortProjectionRecord(
                    preparation_id=preparation_id,
                    carrier_id=id(carrier),
                    carrier_ref=ref(carrier),
                    owner_thread_id=get_ident(),
                    occurrence=occurrence,
                    projection=projection,
                    source_timing_preparation=source_timing_preparation,
                    authored_intent_id=authored_intent_id,
                    binary_identity_kind=binary_identity_kind,
                    facts=facts,
                    occurrence_digest=occurrence_digest,
                    projection_digest=projection_digest,
                    facts_digest=facts_digest,
                    timing_digest=timing_digest,
                    integrity_token="",
                    retained_bytes=retained_bytes,
                )
                integrity = self._action_cohort_projection_integrity(carrier, record)
                record.integrity_token = integrity
                carrier._integrity_token = integrity
                if (
                    type(self._action_cohort_projections) is not dict
                    or type(self._action_cohort_projection_locators) is not dict
                    or type(self._action_cohort_projection_groups) is not dict
                ):
                    raise EventContractError("Action-cohort projection registries are malformed")
                try:
                    self._action_cohort_projections[preparation_id] = record
                    self._action_cohort_projection_locators[id(carrier)] = preparation_id
                    group = self._action_cohort_projection_groups.setdefault(
                        id(source_timing_preparation),
                        set(),
                    )
                    if type(group) is not set:
                        raise EventContractError(
                            "Action-cohort projection timing group is malformed"
                        )
                    group.add(preparation_id)
                    self._action_cohort_projection_retained_bytes += retained_bytes
                except BaseException:
                    self._action_cohort_projections.pop(preparation_id, None)
                    self._action_cohort_projection_locators.pop(id(carrier), None)
                    group = self._action_cohort_projection_groups.get(id(source_timing_preparation))
                    if type(group) is set:
                        group.discard(preparation_id)
                        if not group:
                            self._action_cohort_projection_groups.pop(
                                id(source_timing_preparation),
                                None,
                            )
                    self._action_cohort_projection_retained_bytes = sum(
                        active.retained_bytes for active in self._action_cohort_projections.values()
                    )
                    raise
                return carrier
        except BaseException as primary:
            cleanup_failures: list[BaseException] = []
            try:
                with self._action_cohort_lock:
                    has_registered_group = bool(
                        self._action_cohort_projection_groups.get(id(source_timing_preparation))
                    )
                if has_registered_group:
                    self._cancel_action_cohort_projection_group(source_timing_preparation)
                elif not source_timing_preparation.committed:
                    source_timing_preparation.cancel()
            except BaseException as exc:
                cleanup_failures.append(exc)
            self._add_action_cohort_cleanup_notes(primary, tuple(cleanup_failures))
            raise

    def prepare_persistent_smb_source_projection(
        self,
        group: PersistentSmbProjectionGroupToken,
        event: OccurrenceBuilder,
        *,
        source_timing_preparation: SourceTimingPreparation,
        target_formats: tuple[str, ...],
    ) -> PreparedActionCohortProjection:
        """Freeze one group-bound projection limited to configured SMB source targets."""

        from evidenceforge.generation.persistent_smb_projection import (
            PersistentSmbProjectionGroupToken,
        )

        if type(group) is not PersistentSmbProjectionGroupToken:
            raise EventContractError("Persistent SMB source projection requires its exact group")
        if not self._persistent_smb_projection_authority.authenticates_group(group):
            raise EventContractError("Persistent SMB source projection group is foreign or stale")
        canonical_targets, _topology = self._persistent_smb_projection_target_intent(
            group_id=group.group_id,
            generation_id=group.generation_id,
            target_formats=target_formats,
        )
        return self.prepare_action_cohort_projection(
            event,
            source_timing_preparation=source_timing_preparation,
            _persistent_smb_target_formats=canonical_targets,
        )

    def _active_action_cohort_projection_locked(
        self,
        carrier: PreparedActionCohortProjection,
    ) -> _PreparedActionCohortProjectionRecord:
        """Return one intact exact preflight or reject copied/foreign/stale carriers."""

        if type(carrier) is not PreparedActionCohortProjection:
            raise EventContractError("Action-cohort projection must be the exact opaque type")
        preparation_id = self._action_cohort_projection_locators.get(id(carrier))
        record = (
            self._action_cohort_projections.get(preparation_id)
            if preparation_id is not None
            else None
        )
        if record is None or record.carrier_ref() is not carrier:
            raise EventContractError("Action-cohort projection is stale or already bound")
        dispatcher_token = carrier._dispatcher_token
        carrier_preparation_id = carrier._preparation_id
        consumed = carrier._consumed
        carrier_integrity = carrier._integrity_token
        if (
            type(dispatcher_token) is not int
            or type(carrier_preparation_id) is not int
            or type(consumed) is not bool
            or type(carrier_integrity) is not str
        ):
            raise EventContractError("Action-cohort projection carrier shape is malformed")
        expected = self._action_cohort_projection_integrity(carrier, record)
        if (
            dispatcher_token != id(self)
            or carrier_preparation_id != record.preparation_id
            or consumed
            or record.state != "prepared"
            or not hmac.compare_digest(carrier_integrity, expected)
            or not hmac.compare_digest(record.integrity_token, expected)
        ):
            raise EventContractError("Action-cohort projection integrity validation failed")
        return record

    def _action_cohort_projection_record_authenticates(
        self,
        record: _PreparedActionCohortProjectionRecord,
    ) -> bool:
        """Recompute fallible nested integrity outside the dispatcher lock."""

        occurrence_digest = self._action_cohort_occurrence_digest(record.occurrence)
        projection_digest = self._action_cohort_projection_digest(record.projection)
        timing_digest = self._action_cohort_timing_digest(record.source_timing_preparation)
        derived_facts = self._action_cohort_projection_facts(
            record.occurrence,
            record.projection,
        )
        derived_facts_digest = self._action_cohort_facts_digest(derived_facts)
        retained_facts_digest = self._action_cohort_facts_digest(record.facts)
        return bool(
            hmac.compare_digest(record.occurrence_digest, occurrence_digest)
            and hmac.compare_digest(record.projection_digest, projection_digest)
            and hmac.compare_digest(record.timing_digest, timing_digest)
            and hmac.compare_digest(record.facts_digest, derived_facts_digest)
            and hmac.compare_digest(record.facts_digest, retained_facts_digest)
        )

    def authenticates_prepared_action_cohort_projection(self, carrier: object) -> bool:
        """Totally authenticate one exact unbound projection carrier."""

        if type(carrier) is not PreparedActionCohortProjection:
            return False
        try:
            with self._action_cohort_lock:
                record = self._active_action_cohort_projection_locked(carrier)
                timing_preparation = record.source_timing_preparation
            if not self._action_cohort_projection_record_authenticates(record):
                return False
            timing_authentic = self.source_timing_planner.is_active_preparation(
                timing_preparation
            ) or self.source_timing_planner.authenticates_preparation(timing_preparation)
            if not timing_authentic:
                return False
            with self._action_cohort_lock:
                return self._active_action_cohort_projection_locked(carrier) is record
        except BaseException:
            return False

    def action_cohort_projection_facts(
        self,
        carrier: PreparedActionCohortProjection,
    ) -> ActionCohortProjectionFacts:
        """Return detached canonical and source-native facts for State metadata."""

        with self._action_cohort_lock:
            record = self._active_action_cohort_projection_locked(carrier)
            if record.owner_thread_id != get_ident():
                raise EventContractError(
                    "Action-cohort projection view is bound to its preparing thread"
                )
            facts = record.facts
        if not self._action_cohort_projection_record_authenticates(record):
            raise EventContractError("Action-cohort projection facts failed authentication")
        with self._action_cohort_lock:
            if self._active_action_cohort_projection_locked(carrier) is not record:
                raise EventContractError("Action-cohort projection changed during facts access")
        return replace(facts)

    def action_cohort_projection_occurrence(
        self,
        carrier: PreparedActionCohortProjection,
    ) -> CanonicalOccurrence:
        """Compatibility accessor for the detached canonical preflight occurrence."""

        return self.action_cohort_projection_facts(carrier).occurrence

    def _detach_action_cohort_projection_group_locked(
        self,
        timing_preparation: SourceTimingPreparation,
        *,
        terminal_state: str = "cancelled",
    ) -> tuple[_PreparedActionCohortProjectionRecord, ...]:
        """Remove every unbound preflight sharing one all-or-none timing overlay."""

        preparation_ids = self._action_cohort_projection_groups.pop(
            id(timing_preparation),
            set(),
        )
        records: list[_PreparedActionCohortProjectionRecord] = []
        for preparation_id in preparation_ids:
            record = self._action_cohort_projections.pop(preparation_id, None)
            if record is None:
                continue
            record.state = terminal_state
            records.append(record)
            self._action_cohort_projection_locators.pop(record.carrier_id, None)
            self._action_cohort_projection_retained_bytes -= record.retained_bytes
            carrier = record.carrier_ref()
            if carrier is not None:
                carrier._consumed = True
        return tuple(records)

    def _begin_action_cohort_projection_cleanup_locked(
        self,
        timing_preparation: SourceTimingPreparation,
        *,
        allow_binding: bool = False,
    ) -> tuple[_PreparedActionCohortProjectionRecord, ...]:
        """Retain a trusted projection group until its timing owner cancels cleanly."""

        preparation_ids = self._action_cohort_projection_groups.get(
            id(timing_preparation),
            set(),
        )
        records = tuple(
            record
            for preparation_id in preparation_ids
            if (record := self._action_cohort_projections.get(preparation_id)) is not None
        )
        allowed_states = {"prepared", "cleanup_pending"}
        if allow_binding:
            allowed_states.update({"binding", "publishing"})
        if any(record.state not in allowed_states for record in records):
            raise EventContractError(
                "Binding action-cohort projection cannot be cancelled concurrently"
            )
        for record in records:
            record.state = "cleanup_pending"
        return records

    def _cancel_action_cohort_projection_group(
        self,
        timing_preparation: SourceTimingPreparation,
        *,
        allow_binding: bool = False,
        terminal_state: str = "cancelled",
    ) -> tuple[_PreparedActionCohortProjectionRecord, ...]:
        """Cancel timing first, detaching trusted locators only after confirmed success."""

        with self._action_cohort_lock:
            records = self._begin_action_cohort_projection_cleanup_locked(
                timing_preparation,
                allow_binding=allow_binding,
            )
        if not timing_preparation.committed:
            timing_preparation.cancel()
        with self._action_cohort_lock:
            active_ids = self._action_cohort_projection_groups.get(
                id(timing_preparation),
                set(),
            )
            if any(
                all(
                    self._action_cohort_projections.get(preparation_id) is not record
                    for record in records
                )
                for preparation_id in active_ids
            ):
                raise EventContractError(
                    "Action-cohort projection cleanup group changed during cancellation"
                )
            return self._detach_action_cohort_projection_group_locked(
                timing_preparation,
                terminal_state=terminal_state,
            )

    def cancel_prepared_action_cohort_projection(
        self,
        carrier: PreparedActionCohortProjection,
    ) -> bool:
        """Cancel an entire unbound timing/projection group through trusted locators."""

        if type(carrier) is not PreparedActionCohortProjection:
            raise TypeError("Projection cancellation requires the exact opaque type")
        with self._action_cohort_lock:
            preparation_id = self._action_cohort_projection_locators.get(id(carrier))
            record = (
                self._action_cohort_projections.get(preparation_id)
                if preparation_id is not None
                else None
            )
            if record is None or record.carrier_ref() is not carrier:
                return False
            if record.state not in {"prepared", "cleanup_pending"}:
                raise EventContractError(
                    "Binding action-cohort projection cannot be cancelled concurrently"
                )
            timing_preparation = record.source_timing_preparation
        records = self._cancel_action_cohort_projection_group(timing_preparation)
        return bool(records)

    def prune_prepared_action_cohort_projections(self) -> int:
        """Release weak-ownerless projection groups without scanning canonical state."""

        with self._action_cohort_lock:
            unique: dict[int, SourceTimingPreparation] = {}
            for record in self._action_cohort_projections.values():
                if record.carrier_ref() is None and record.state in {
                    "prepared",
                    "cleanup_pending",
                }:
                    unique[id(record.source_timing_preparation)] = record.source_timing_preparation
        removed = 0
        failures: list[BaseException] = []
        for preparation in unique.values():
            try:
                removed += len(
                    self._cancel_action_cohort_projection_group(
                        preparation,
                        terminal_state="pruned",
                    )
                )
            except BaseException as exc:
                failures.append(exc)
        if failures:
            error = EventContractError("Action-cohort projection pruning cleanup failed")
            self._add_action_cohort_cleanup_notes(error, tuple(failures))
            raise error
        return removed

    def bind_action_cohort_projection(
        self,
        carrier: PreparedActionCohortProjection,
        *,
        state_plan: ActionCohortMaterializationPlan,
    ) -> PreparedDispatch:
        """Bind one frozen projection exactly once to one sealed State cohort plan."""

        from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan

        timing_preparation: SourceTimingPreparation | None = None
        try:
            with self._action_cohort_lock:
                record = self._active_action_cohort_projection_locked(carrier)
                timing_preparation = record.source_timing_preparation
                if record.owner_thread_id != get_ident():
                    raise EventContractError(
                        "Action-cohort projection must bind on its preparing thread"
                    )
                record.state = "binding"
            if not self._action_cohort_projection_record_authenticates(record):
                raise EventContractError(
                    "Action-cohort projection nested integrity validation failed"
                )
            if type(state_plan) is not ActionCohortMaterializationPlan:
                raise EventContractError(
                    "Action-cohort projection requires an exact State cohort plan"
                )
            if not self.source_timing_planner.authenticates_preparation(timing_preparation):
                raise EventContractError(
                    "Action-cohort projection timing preparation is not sealed"
                )
            version = self._validate_external_action_cohort_binding(
                record.occurrence,
                state_plan,
            )
            prepared = PreparedDispatch(
                occurrence=record.occurrence,
                projection=record.projection,
                expected_state_version=version,
                state_intent=PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT,
                lifecycle_ticket=state_plan,
                binary_identity_kind=record.binary_identity_kind,
                artifact_publications=(),
                source_timing_preparation=timing_preparation,
                authored_intent_id=record.authored_intent_id,
                integrity_token="",
            )
            prepared._integrity_token = self._prepared_dispatch_integrity(prepared)
            with self._action_cohort_lock:
                active = self._action_cohort_projections.get(record.preparation_id)
                dispatcher_token = carrier._dispatcher_token
                carrier_preparation_id = carrier._preparation_id
                consumed = carrier._consumed
                carrier_integrity = carrier._integrity_token
                expected_integrity = self._action_cohort_projection_integrity(
                    carrier,
                    record,
                )
                if (
                    active is not record
                    or record.carrier_ref() is not carrier
                    or record.state != "binding"
                    or type(dispatcher_token) is not int
                    or dispatcher_token != id(self)
                    or type(carrier_preparation_id) is not int
                    or carrier_preparation_id != record.preparation_id
                    or type(consumed) is not bool
                    or consumed
                    or type(carrier_integrity) is not str
                    or not hmac.compare_digest(carrier_integrity, expected_integrity)
                    or not hmac.compare_digest(
                        record.integrity_token,
                        expected_integrity,
                    )
                ):
                    raise EventContractError(
                        "Action-cohort projection binding lost its trusted reservation"
                    )
                self._action_cohort_projections.pop(record.preparation_id, None)
                self._action_cohort_projection_locators.pop(record.carrier_id, None)
                group = self._action_cohort_projection_groups.get(id(timing_preparation))
                if group is not None:
                    group.discard(record.preparation_id)
                    if not group:
                        self._action_cohort_projection_groups.pop(id(timing_preparation), None)
                self._action_cohort_projection_retained_bytes -= record.retained_bytes
                carrier._consumed = True
                return prepared
        except BaseException as primary:
            if timing_preparation is not None:
                try:
                    self._cancel_action_cohort_projection_group(
                        timing_preparation,
                        allow_binding=True,
                    )
                except BaseException as exc:
                    self._add_action_cohort_cleanup_notes(primary, (exc,))
            raise

    def prepare_occurrence(
        self,
        event: CanonicalOccurrence,
        *,
        expected_state_version: int | None = None,
        state_intent: PreparedDispatchStateIntent = PreparedDispatchStateIntent.APPLY,
        lifecycle_ticket: object | None = None,
        binary_identity_kind: str = "",
        artifact_publications: tuple[LocalArtifactPublishToken, ...] = (),
        source_timing_preparation: SourceTimingPreparation | None = None,
        _authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
        _defer_projection: bool = False,
    ) -> PreparedDispatch:
        """Freeze source projection and an exact state/lifecycle publication intent."""

        authored_intent_id = self._freeze_authored_intent_id(_authored_intent_id)
        artifact_publications = tuple(artifact_publications)
        if not isinstance(event, CanonicalOccurrence):
            raise TypeError("prepare_occurrence() requires a sealed CanonicalOccurrence")
        if event.contract_seal is None or not event.contract_seal.valid:
            raise EventContractError("Prepared dispatch requires a valid canonical contract seal")
        if not isinstance(state_intent, PreparedDispatchStateIntent):
            raise EventContractError("Prepared dispatch requires a typed state intent")
        if state_intent is not PreparedDispatchStateIntent.APPLY and lifecycle_ticket is None:
            raise EventContractError(
                "Externally materialized dispatch requires an authority lifecycle ticket"
            )
        if state_intent is PreparedDispatchStateIntent.APPLY and lifecycle_ticket is not None:
            raise EventContractError("Compatibility dispatch cannot bind an external start plan")
        if _defer_projection and state_intent is not PreparedDispatchStateIntent.APPLY:
            raise EventContractError(
                "Only the immediate compatibility wrapper may defer source projection"
            )
        if state_intent is PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT:
            if source_timing_preparation is None:
                raise EventContractError(
                    "Prepared action-cohort member requires source timing authority"
                )
            version = self._validate_external_action_cohort_binding(
                event,
                lifecycle_ticket,
            )
            if expected_state_version is not None and expected_state_version != version:
                raise EventContractError(
                    "Prepared action-cohort member version contradicts its State plan"
                )
        elif state_intent is PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT:
            if source_timing_preparation is None:
                raise EventContractError(
                    "Prepared network dependent requires source timing authority"
                )
            version = self._validate_external_network_dependent_binding(
                event,
                lifecycle_ticket,
            )
            if expected_state_version is not None and expected_state_version != version:
                raise EventContractError(
                    "Prepared network dependent version contradicts its network root"
                )
        elif state_intent in {
            PreparedDispatchStateIntent.EXTERNAL_TRANSPORT,
            PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT,
        }:
            if source_timing_preparation is None:
                raise EventContractError(
                    "Prepared external transport requires source timing authority"
                )
            version = self._validate_external_transport_binding(
                event,
                lifecycle_ticket,
                allow_deferred_session=(
                    state_intent is PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT
                ),
            )
            if expected_state_version is not None and expected_state_version != version:
                raise EventContractError(
                    "Prepared dispatch version contradicts its external transport root"
                )
        elif state_intent is PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT:
            if source_timing_preparation is None:
                raise EventContractError(
                    "Prepared deferred-session dependent requires source timing authority"
                )
            event = self._rebind_external_deferred_dependent_identity(
                event,
                lifecycle_ticket,
            )
            version = self._validate_external_deferred_dependent_binding(
                event,
                lifecycle_ticket,
            )
            if expected_state_version is not None and expected_state_version != version:
                raise EventContractError(
                    "Prepared deferred-session dependent version contradicts its State member"
                )
        elif state_intent is not PreparedDispatchStateIntent.APPLY:
            ticket_version = getattr(lifecycle_ticket, "expected_version", None)
            publication_token = getattr(lifecycle_ticket, "publication_token", None)
            if (
                isinstance(ticket_version, bool)
                or not isinstance(ticket_version, int)
                or ticket_version < 0
                or not isinstance(publication_token, str)
                or not publication_token
            ):
                raise EventContractError(
                    "Externally materialized dispatch requires an authenticated state plan"
                )
            ticket_identity = getattr(lifecycle_ticket, "identity", None)
            identity_plan = event.identity_plan
            subject = identity_plan.subject if identity_plan is not None else None
            actor = identity_plan.actor if identity_plan is not None else None
            expected_object_id = getattr(ticket_identity, "object_id", None)
            bound_object_id = getattr(subject, "object_id", None)
            if state_intent is PreparedDispatchStateIntent.EXTERNAL_DEPENDENT:
                bound_object_id = getattr(actor, "object_id", None)
            if (
                ticket_identity is None
                or not expected_object_id
                or bound_object_id != expected_object_id
            ):
                role = (
                    "actor"
                    if state_intent is PreparedDispatchStateIntent.EXTERNAL_DEPENDENT
                    else "subject"
                )
                raise EventContractError(
                    f"Prepared occurrence {role} identity does not match its external state plan"
                )
            if expected_state_version is not None and expected_state_version != ticket_version:
                raise EventContractError(
                    "Prepared dispatch version contradicts its external state plan"
                )
            version = ticket_version
        else:
            version = (
                self._state_materialization_version()
                if expected_state_version is None
                else expected_state_version
            )
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise EventContractError("Prepared dispatch state version must be non-negative")
        if artifact_publications:
            self._bind_artifact_publications(
                event,
                artifact_publications,
                attach=False,
            )
        if source_timing_preparation is not None:
            from evidenceforge.generation.source_timing import SourceTimingPreparation

            if not isinstance(source_timing_preparation, SourceTimingPreparation):
                raise EventContractError("Prepared dispatch source timing capability must be typed")
            if not self.source_timing_planner.is_active_preparation(source_timing_preparation):
                raise EventContractError(
                    "Prepared dispatch source timing capability is not active for this planner"
                )
        projection = (
            _PreparedProjection(mode="deferred", occurrence=event)
            if _defer_projection
            else self._prepare_projection(event)
        )
        prepared = PreparedDispatch(
            occurrence=event,
            projection=projection,
            expected_state_version=version,
            state_intent=state_intent,
            lifecycle_ticket=lifecycle_ticket,
            binary_identity_kind=binary_identity_kind,
            artifact_publications=artifact_publications,
            source_timing_preparation=source_timing_preparation,
            authored_intent_id=authored_intent_id,
            integrity_token="",
        )
        prepared._integrity_token = self._prepared_dispatch_integrity(prepared)
        return prepared

    def _validate_external_action_cohort_binding(
        self,
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
    ) -> int:
        """Bind one member to an exact authentic State action-cohort identity set."""

        from evidenceforge.generation.state_manager import (
            ActionCohortMaterializationPlan,
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        if type(lifecycle_ticket) is not ActionCohortMaterializationPlan:
            raise EventContractError(
                "Prepared action-cohort member requires an exact State cohort plan"
            )
        plan = lifecycle_ticket
        if not self.state_manager.authenticates_action_cohort_plan(plan):
            raise EventContractError("Prepared action-cohort State plan failed authentication")
        identity_plan = event.identity_plan
        if identity_plan is None:
            raise EventContractError(
                "Prepared action-cohort member requires an exact canonical identity"
            )

        allowed_object_ids: set[str] = {
            member.identity.object_id for member in (*plan.sessions, *plan.processes)
        }
        for patch in (
            *plan.session_metadata_patches,
            *plan.process_activity_patches,
            *plan.session_activity_patches,
        ):
            target = patch.target
            identity = (
                target.identity
                if type(target) in {SessionMaterializationPlan, ProcessMaterializationPlan}
                else target
            )
            allowed_object_ids.add(identity.object_id)
        for patch in plan.live_session_process_role_patches:
            allowed_object_ids.add(patch.target.object_id)
            for process in (
                patch.winlogon_plan,
                patch.explorer_plan,
                patch.process_tree_root_plan,
            ):
                if process is not None:
                    allowed_object_ids.add(process.identity.object_id)
        allowed_object_ids.update(
            termination.identity.object_id for termination in plan.process_terminations
        )
        allowed_object_ids.update(
            terminalization.identity.object_id for terminalization in plan.session_terminalizations
        )
        bound_object_ids = {
            object_id
            for candidate in (
                identity_plan.subject,
                identity_plan.actor,
                identity_plan.target,
                identity_plan.session,
            )
            if type(object_id := getattr(candidate, "object_id", None)) is str and object_id
        }
        if not bound_object_ids.intersection(allowed_object_ids):
            raise EventContractError(
                "Prepared action-cohort member identity is outside its exact State plan"
            )
        version = plan.expected_version
        if type(version) is not int or version < 0:
            raise EventContractError(
                "Prepared action-cohort State version must be a non-negative exact int"
            )
        return version

    @staticmethod
    def _validate_external_transport_binding(
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
        *,
        allow_deferred_session: bool = False,
    ) -> int:
        """Validate exact canonical event/root semantics without consuming the root."""

        from evidenceforge.generation.network_runtime import (
            NetworkConnectionCommitResult,
            NetworkTransactionPreparationToken,
            PreparedNetworkTransactionRoot,
        )
        from evidenceforge.generation.state_manager import (
            ConnectionCompositeMaterializationPlan,
            ConnectionMaterializationMode,
        )

        if type(lifecycle_ticket) is not PreparedNetworkTransactionRoot:
            raise EventContractError(
                "Prepared external transport requires an exact prepared network root"
            )
        root = lifecycle_ticket
        plan = root.state_plan
        token = root.runtime_token
        result = root.result
        if (
            type(plan) is not ConnectionCompositeMaterializationPlan
            or type(token) is not NetworkTransactionPreparationToken
            or type(result) is not NetworkConnectionCommitResult
        ):
            raise EventContractError("Prepared external transport root is malformed")
        if event.event_type is not EventKind.CONNECTION or event.network is None:
            raise EventContractError(
                "Prepared external transport requires one canonical connection occurrence"
            )
        if allow_deferred_session:
            if token.lifecycle_mode != "deferred_session":
                raise EventContractError(
                    "Prepared deferred transport requires deferred-session lifecycle authority"
                )
        elif token.lifecycle_mode == "deferred_session":
            raise EventContractError("Deferred-session transport requires its session authority")
        elif token.lifecycle_mode not in {"network", "application_child"}:
            raise EventContractError("Prepared external transport lifecycle mode is unsupported")
        application_child = plan.mode is ConnectionMaterializationMode.APPLICATION_CHILD
        if plan.mode is ConnectionMaterializationMode.PHYSICAL:
            expected_mode = "deferred_session" if allow_deferred_session else "network"
            if token.lifecycle_mode != expected_mode or event.network.application_layer_only:
                raise EventContractError(
                    "Physical external transport root disagrees with its occurrence"
                )
        elif not application_child:
            raise EventContractError("Prepared external transport has no explicit State mode")
        elif (
            token.lifecycle_mode != "application_child" or not event.network.application_layer_only
        ):
            raise EventContractError(
                "Application-child external transport root disagrees with its occurrence"
            )
        if (
            root.transaction != plan.transaction
            or root.transaction != result.transaction
            or event.network != root.transaction
            or event.timestamp != root.transaction.started_at
            or event.network.dst_ip != result.effective_dst_ip
            or event.protocol.http != result.http
            or event.protocol.file_transfers != result.file_transfers
            or token.transaction_id != root.transaction.stable_id
            or token.state_publication_token != plan.publication_token
            or token.materialization_mode is not plan.mode
            or token.lifecycle_mode != result.lifecycle_mode
        ):
            raise EventContractError(
                "Prepared external transport event disagrees with its finalized root"
            )
        version = plan.expected_version
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version < 0
            or not isinstance(plan.publication_token, str)
            or not plan.publication_token
            or not isinstance(token.publication_token, str)
            or not token.publication_token
        ):
            raise EventContractError(
                "Prepared external transport requires authenticated State/runtime plans"
            )
        return version

    @staticmethod
    def _rebind_external_deferred_dependent_identity(
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
    ) -> CanonicalOccurrence:
        """Restore an immutable State identity copied by canonical sealing.

        ``OccurrenceBuilder.seal()`` intentionally deep-snapshots caller-owned
        values.  Deferred dependents, however, must ultimately pin the exact
        immutable identity owned by their authenticated State plan.  Rebind only
        roles that are already exact-type and value-equal to that identity; this
        preserves the sealed event's semantics while closing identity-by-value
        substitution at the publication boundary.
        """

        from evidenceforge.events.identity import EventIdentityPlan
        from evidenceforge.generation.state_manager import (
            ConnectionExistingSessionPatch,
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        if type(lifecycle_ticket) not in {
            ConnectionExistingSessionPatch,
            SessionMaterializationPlan,
            ProcessMaterializationPlan,
        }:
            return event
        exact_identity = (
            lifecycle_ticket.after.identity
            if type(lifecycle_ticket) is ConnectionExistingSessionPatch
            else lifecycle_ticket.identity
        )
        identity_plan = event.identity_plan
        if type(identity_plan) is not EventIdentityPlan:
            return event

        def rebind(candidate: object | None) -> object | None:
            if type(candidate) is type(exact_identity) and candidate == exact_identity:
                return exact_identity
            return candidate

        rebound = EventIdentityPlan(
            subject=cast("object", rebind(identity_plan.subject)),
            actor=cast("object", rebind(identity_plan.actor)),
            target=cast("object", rebind(identity_plan.target)),
            session=cast("object", rebind(identity_plan.session)),
        )
        if rebound == identity_plan:
            return replace(event, identity_plan=rebound)
        return event

    @staticmethod
    def _validate_external_deferred_dependent_binding(
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
    ) -> int:
        """Bind one State-neutral dependent to an exact staged session/process plan."""

        from evidenceforge.generation.state_manager import (
            ConnectionExistingSessionPatch,
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        if type(lifecycle_ticket) not in {
            ConnectionExistingSessionPatch,
            SessionMaterializationPlan,
            ProcessMaterializationPlan,
        }:
            raise EventContractError(
                "Prepared deferred-session dependent requires an exact State start plan"
            )
        exact_identity = (
            lifecycle_ticket.after.identity
            if type(lifecycle_ticket) is ConnectionExistingSessionPatch
            else lifecycle_ticket.identity
        )
        identity_plan = event.identity_plan
        if identity_plan is None:
            raise EventContractError(
                "Prepared deferred-session dependent requires a canonical identity plan"
            )
        bound_identities = (
            identity_plan.subject,
            identity_plan.actor,
            identity_plan.target,
            identity_plan.session,
        )
        if not any(candidate is exact_identity for candidate in bound_identities):
            raise EventContractError(
                "Prepared deferred-session dependent lost its exact State identity object"
            )
        if type(lifecycle_ticket) is SessionMaterializationPlan:
            if event.event_type not in {
                EventKind.LOGON,
                EventKind.SSH_SESSION,
                EventKind.SYSLOG,
            }:
                raise EventContractError(
                    "Prepared deferred-session session dependent has an unsupported event kind"
                )
            if identity_plan.session is not exact_identity:
                raise EventContractError(
                    "Prepared deferred-session session dependent lost its session identity"
                )
        elif type(lifecycle_ticket) is ProcessMaterializationPlan and event.event_type not in {
            EventKind.PROCESS_CREATE,
            EventKind.SYSTEM_PROCESS_CREATE,
        }:
            raise EventContractError(
                "Prepared deferred-session process dependent has an unsupported event kind"
            )
        elif type(lifecycle_ticket) is ConnectionExistingSessionPatch and (
            event.event_type is not EventKind.RDP_RECONNECT
            or identity_plan.session is not exact_identity
        ):
            raise EventContractError(
                "Prepared deferred-session live dependent is not an exact RDP reconnect"
            )
        version = (
            lifecycle_ticket._expected_version
            if type(lifecycle_ticket) is ConnectionExistingSessionPatch
            else lifecycle_ticket.expected_version
        )
        publication_token = (
            lifecycle_ticket._integrity_token
            if type(lifecycle_ticket) is ConnectionExistingSessionPatch
            else lifecycle_ticket.publication_token
        )
        if (
            type(version) is not int
            or version < 0
            or type(publication_token) is not str
            or not publication_token
        ):
            raise EventContractError(
                "Prepared deferred-session dependent requires an authenticated State plan"
            )
        return version

    @staticmethod
    def _validate_external_network_dependent_binding(
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
    ) -> int:
        """Bind one projection-only file read to an exact network-root activity patch."""

        from evidenceforge.events.identity import ProcessIdentity
        from evidenceforge.generation.network_runtime import (
            NetworkTransactionPreparationToken,
            PreparedNetworkTransactionRoot,
        )
        from evidenceforge.generation.state_manager import (
            ConnectionCompositeMaterializationPlan,
        )

        if type(lifecycle_ticket) is not PreparedNetworkTransactionRoot:
            raise EventContractError(
                "Prepared network dependent requires an exact prepared network root"
            )
        root = lifecycle_ticket
        state_plan = root.state_plan
        runtime_token = root.runtime_token
        if (
            type(state_plan) is not ConnectionCompositeMaterializationPlan
            or type(runtime_token) is not NetworkTransactionPreparationToken
            or root.transaction != state_plan.transaction
            or runtime_token.transaction_id != root.transaction.stable_id
            or runtime_token.state_publication_token != state_plan.publication_token
        ):
            raise EventContractError("Prepared network dependent root is malformed")
        provenance = event.effect_provenance
        if (
            event.event_type is not EventKind.FILE_READ
            or event.file is None
            or event.file.action != "read"
            or provenance is None
            or provenance.kind is not EffectOccurrenceKind.FILE
            or provenance.disposition is not EffectOccurrenceDisposition.OWNED_ROOT
            or provenance.owner is not EffectOccurrenceOwner.HTTP_MULTIPART_LOCAL_READ
            or provenance.root_action_id != root.transaction.stable_id
        ):
            raise EventContractError(
                "Prepared network dependent must be one owned HTTP multipart file read"
            )
        identity_plan = event.identity_plan
        actor = identity_plan.actor if identity_plan is not None else None
        if not isinstance(actor, ProcessIdentity):
            raise EventContractError(
                "Prepared network dependent requires an exact process actor identity"
            )
        matching_patches = tuple(
            patch for patch in state_plan.process_activity if patch.identity == actor
        )
        if len(matching_patches) != 1:
            raise EventContractError(
                "Prepared network dependent actor is not an exact root activity member"
            )
        patch = matching_patches[0]
        if event.timestamp < actor.started_at or event.timestamp > patch.activity_time:
            raise EventContractError(
                "Prepared network dependent timestamp lies outside its root activity frontier"
            )
        return state_plan.expected_version

    def _state_materialization_version(self) -> int:
        """Read the monotonic StateManager fence without changing allocation state."""

        version = getattr(self.state_manager, "materialization_version", None)
        if callable(version):
            version = version()
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            if type(self.state_manager).__module__ == "unittest.mock":
                return 0
            raise StateError("StateManager does not expose a valid materialization version")
        return version

    @staticmethod
    def _lifecycle_ticket_signature(ticket: object) -> tuple[object, ...]:
        """Return an exact signature while preserving every legacy plan preimage."""

        from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
        from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan

        if type(ticket) is ActionCohortMaterializationPlan:
            return (
                type(ticket).__module__,
                type(ticket).__qualname__,
                id(ticket),
                ticket.expected_version,
                ticket.publication_token,
                ticket.semantic_id,
                repr(ticket),
            )

        if type(ticket) is PreparedNetworkTransactionRoot:
            plan = ticket.state_plan
            token = ticket.runtime_token
            return (
                type(ticket).__module__,
                type(ticket).__qualname__,
                plan.expected_version,
                plan.publication_token,
                plan.mode,
                repr(plan.physical_transport_fingerprint),
                token.publication_token,
                token.transaction_id,
                token.action_group_id,
                token.materialization_mode,
                token.lifecycle_mode,
                token.linearization_time,
                token.overlay_digest,
                token.state_publication_token,
                token.cryptographic_publication_token,
                repr(ticket.transaction),
                repr(ticket.result),
            )
        return (
            type(ticket).__module__,
            type(ticket).__qualname__,
            getattr(ticket, "expected_version", None),
            getattr(ticket, "publication_token", None),
            getattr(
                getattr(ticket, "identity", None),
                "object_id",
                None,
            ),
        )

    def _prepared_dispatch_integrity(self, prepared: PreparedDispatch) -> str:
        """Authenticate every immutable occurrence/projection/publication field."""

        if type(prepared) is not PreparedDispatch:
            raise EventContractError("Prepared dispatch must be the exact opaque type")
        if prepared._authored_intent_id is not None and (
            type(prepared._authored_intent_id) is not str or not prepared._authored_intent_id
        ):
            raise EventContractError("Prepared dispatch authored intent binding is malformed")
        if prepared._action_cohort_batch_id is not None and (
            type(prepared._action_cohort_batch_id) is not int
            or prepared._action_cohort_batch_id <= 0
        ):
            raise EventContractError("Prepared dispatch action-cohort binding is malformed")
        if prepared._deferred_session_publication_batch_id is not None and (
            type(prepared._deferred_session_publication_batch_id) is not int
            or prepared._deferred_session_publication_batch_id <= 0
        ):
            raise EventContractError("Prepared dispatch deferred-session binding is malformed")

        projection_signature = self._prepared_projection_signature(prepared._projection)
        lifecycle_ticket_signature = self._lifecycle_ticket_signature(prepared._lifecycle_ticket)
        artifact_signatures = tuple(
            (
                repr(token.record),
                token.observed_at,
                token.retained_until,
                token.lease_owner,
                token.lease_until,
                getattr(token, "_registry_token", None),
                getattr(token, "_reservation_id", None),
                getattr(token, "_shard_id", None),
                getattr(token, "_existing_handle", None),
            )
            for token in prepared._artifact_publications
        )
        timing_preparation = prepared._source_timing_preparation
        timing_token = timing_preparation.binding_token if timing_preparation is not None else None
        timing_signature = (
            type(timing_token).__module__,
            type(timing_token).__qualname__,
            getattr(timing_token, "preparation_id", None),
            getattr(timing_token, "base_state_digest", None),
            getattr(timing_token, "_integrity", None),
        )
        payload = repr(
            (
                id(prepared),
                prepared._action_cohort_batch_id,
                prepared._authored_intent_id,
                prepared._expected_state_version,
                prepared._state_intent,
                lifecycle_ticket_signature,
                prepared._binary_identity_kind,
                artifact_signatures,
                timing_signature,
                repr(prepared._occurrence),
                projection_signature,
            )
        ).encode("utf-8")
        return hmac.new(
            self._prepared_dispatch_secret,
            payload,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _prepared_projection_signature(projection: _PreparedProjection) -> tuple[object, ...]:
        """Return the exact immutable projection preimage shared by both prepare stages."""

        legacy_signature = tuple(
            (
                target.format_name,
                id(target.emitter),
                target.status,
                repr(target.occurrence),
            )
            for target in projection.legacy_targets
        )
        compiled_signature = tuple(
            (
                target.format_name,
                id(target.emitter),
                target.source_ordinal,
                target.role,
                target.required_capabilities,
                target.optional_capabilities,
                repr(target.envelope),
                repr(target.decision),
                target.topology_visible,
                target.projected_timestamp,
                repr(target.source_timing),
                repr(target.network_observations),
            )
            for target in projection.compiled_targets
        )
        return (
            repr(projection.occurrence),
            projection.mode,
            projection.initial_statuses,
            legacy_signature,
            compiled_signature,
        )

    def bind_deployment_registry(self, registry: DeploymentContentRegistry) -> None:
        """Bind the immutable deployment registry before event publication starts."""

        if self.deployment_registry is not None and self.deployment_registry is not registry:
            raise RuntimeError("event dispatcher deployment registry is already bound")
        self.deployment_registry = registry

    def bind_local_artifact_registry(self, registry: LocalArtifactVersionRegistry) -> None:
        """Bind the engine-owned bounded runtime artifact registry once."""

        if (
            self.local_artifact_registry is not None
            and self.local_artifact_registry is not registry
        ):
            raise RuntimeError("event dispatcher local artifact registry is already bound")
        self.local_artifact_registry = registry

    def _bind_artifact_publications(
        self,
        event: OccurrenceBuilder | CanonicalOccurrence,
        artifact_publications: tuple[LocalArtifactPublishToken, ...],
        *,
        attach: bool = True,
    ) -> object | None:
        """Bind exact prepared artifact/content truth without publishing a version."""

        from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken

        publications = tuple(artifact_publications)
        if any(not isinstance(token, LocalArtifactPublishToken) for token in publications):
            raise EventContractError("Prepared dispatch artifact publications must be typed tokens")
        reservation_ids = tuple(getattr(token, "_reservation_id", 0) for token in publications)
        if len(reservation_ids) != len(set(reservation_ids)):
            raise EventContractError("Prepared dispatch cannot bind one artifact token twice")
        registry = self.local_artifact_registry
        if publications and registry is None:
            raise EventContractError(
                "Prepared artifact dispatch requires the engine-owned local artifact registry"
            )
        host = event.src_host or event.dst_host
        if host is None:
            if publications:
                raise EventContractError("Prepared artifact dispatch requires an exact host")
            return None
        platform_name = host.os_category.casefold()
        if platform_name not in {"windows", "linux", "macos"}:
            if publications:
                raise EventContractError("Prepared artifact dispatch requires a supported platform")
            return None
        platform = cast(Platform, platform_name)
        principal = (
            event.process.username
            if event.process is not None and event.process.username
            else (event.auth.username if event.auth is not None else "")
        )
        file_records = []
        binary_records = []
        for token in publications:
            record = token.record
            artifact = record.artifact
            if (
                artifact.hostname.casefold() != host.hostname.casefold()
                or artifact.principal.casefold() != principal.casefold()
                or artifact.platform != platform
            ):
                raise EventContractError(
                    "Prepared artifact publication owner drifted from its canonical occurrence"
                )
            file_match = bool(
                event.file is not None
                and canonical_native_path(event.file.path, platform)
                == canonical_native_path(artifact.native_path, platform)
            )
            binary_match = bool(
                event.process is not None
                and record.binary is not None
                and canonical_native_path(event.process.image, platform)
                == canonical_native_path(artifact.native_path, platform)
            )
            if not file_match and not binary_match:
                raise EventContractError(
                    "Prepared artifact publication path is unrelated to its canonical occurrence"
                )
            if file_match:
                file_records.append(record)
            if binary_match:
                binary_records.append(record)
        if len(file_records) > 1:
            raise EventContractError(
                "One file occurrence cannot publish multiple artifact versions"
            )
        if len(binary_records) > 1:
            raise EventContractError("One process occurrence cannot publish multiple binaries")

        file_record = file_records[0] if file_records else None
        if event.file is not None and file_record is None and registry is not None:
            file_record = registry.resolve_record_for_execution_path(
                host.hostname,
                principal,
                event.file.path,
                platform,
            )
        if event.file is not None and file_record is not None:
            if event.file.artifact_identity not in (None, file_record.artifact):
                raise EventContractError(
                    "File artifact identity conflicts with its exact retained publication"
                )
            if event.file.content_identity not in (None, file_record.content):
                raise EventContractError(
                    "File content identity conflicts with its exact retained publication"
                )
            if attach:
                event.file.artifact_identity = file_record.artifact
                event.file.content_identity = file_record.content
            elif (
                event.file.artifact_identity != file_record.artifact
                or event.file.content_identity != file_record.content
            ):
                raise EventContractError(
                    "Sealed file occurrence lacks its exact prepared artifact/content identity"
                )
        elif event.file is not None and (
            event.file.artifact_identity is not None or event.file.content_identity is not None
        ):
            raise EventContractError(
                "File artifact/content identity has no exact retained or prepared version"
            )

        binary_record = binary_records[0] if binary_records else None
        if binary_record is None:
            return None
        if event.process is None or binary_record.binary is None:  # pragma: no cover - invariant
            raise EventContractError("Prepared executable publication lost its process binding")
        if event.process.binary_identity not in (None, binary_record.binary):
            raise EventContractError(
                "Process binary identity conflicts with its prepared artifact publication"
            )
        if attach:
            event.process.binary_identity = binary_record.binary
        elif event.process.binary_identity != binary_record.binary:
            raise EventContractError(
                "Sealed process occurrence lacks its exact prepared binary identity"
            )
        return binary_record.binary

    @property
    def binary_identity_counts(self) -> dict[str, int]:
        """Return bounded process binary-resolution audit counters."""

        with self._publication_ledger_lock:
            return dict(sorted(self._binary_identity_counts.items()))

    def _attach_process_binary_identity(
        self,
        event: OccurrenceBuilder,
        *,
        prepared_binary: object | None = None,
    ) -> str:
        """Resolve exact binary content once at the mutable publication boundary."""

        process = event.process
        host = event.src_host or event.dst_host
        if process is None or host is None:
            return ""
        platform_name = host.os_category.casefold()
        if platform_name not in {"windows", "linux", "macos"}:
            return ""
        platform = cast(Platform, platform_name)
        principal = process.username or (event.auth.username if event.auth is not None else "")
        resolved = prepared_binary
        if resolved is None:
            resolved = self.resolve_process_binary_identity(
                host.hostname,
                principal,
                process.image,
                platform,
            )
        if resolved is None:
            return ""
        if process.binary_identity is not None:
            if process.binary_identity.canonical_key != resolved.canonical_key:
                raise EventContractError(
                    "Process binary identity conflicts with the exact host deployment binding "
                    f"for {host.hostname!r} and {process.image!r}"
                )
        else:
            process.binary_identity = resolved
        if self._enforce_binary_identity and isinstance(resolved, UnresolvedBinaryIdentity):
            raise EventContractError(
                "Production process binary has no exact deployed or runtime artifact identity for "
                f"{host.hostname!r} and {process.image!r}"
            )
        return resolved.identity_kind

    def resolve_process_binary_identity(
        self,
        hostname: str,
        principal: str,
        native_path: str,
        platform: Platform,
    ) -> ProcessBinaryIdentity | None:
        """Resolve deployed, retained, or virtual process binary truth without mutation."""

        registry = self.deployment_registry
        local_registry = self.local_artifact_registry
        resolved: ProcessBinaryIdentity | None = (
            registry.resolve_binary(
                hostname,
                native_path,
                platform,
                principal=principal,
            )
            if registry is not None
            else None
        )
        if resolved is None and local_registry is not None:
            resolved = local_registry.resolve_binary_for_path(
                hostname,
                principal,
                native_path,
                platform,
            )
        if resolved is None:
            resolved = _virtual_kernel_binary(native_path, platform)
        if resolved is None and (registry is not None or local_registry is not None):
            return UnresolvedBinaryIdentity(
                platform=platform,
                native_path=native_path,
                reason="no exact installed or retained local artifact binding",
            )
        return resolved

    def _attach_image_load_binary_identity(self, event: OccurrenceBuilder) -> None:
        """Resolve one exact deployed module or reject an undeployed image load."""

        image_load = event.image_load
        registry = self.deployment_registry
        host = event.src_host or event.dst_host
        if image_load is None or registry is None or host is None:
            return
        platform_name = host.os_category.casefold()
        if platform_name not in {"windows", "linux", "macos"}:
            return
        platform = cast(Platform, platform_name)
        process = event.process
        principal = (
            process.username
            if process is not None and process.username
            else (event.auth.username if event.auth is not None else "")
        )
        resolved = registry.resolve_binary(
            host.hostname,
            image_load.image_loaded,
            platform,
            principal=principal,
        )
        if (
            resolved is None
            or registry.host_module_handle(host.hostname, resolved.content_id) is None
        ):
            raise EventContractError(
                "Image-load binary is not an exact deployed module for "
                f"{host.hostname!r} and {image_load.image_loaded!r}"
            )
        if image_load.binary_identity is not None:
            if image_load.binary_identity.canonical_key != resolved.canonical_key:
                raise EventContractError(
                    "Image-load binary identity conflicts with the exact host deployment binding "
                    f"for {host.hostname!r} and {image_load.image_loaded!r}"
                )
            return
        image_load.binary_identity = resolved

    def dispatch(self, event: CanonicalOccurrence) -> dict[str, str]:
        """Prepare then publish an already sealed occurrence through the compatibility path."""

        return self.publish_prepared(self.prepare_occurrence(event, _defer_projection=True))

    def publish_prepared(
        self,
        prepared: PreparedDispatch,
        *,
        materialization_receipt: object | None = None,
    ) -> dict[str, str]:
        """Consume one exact prepared dispatch without re-planning or re-sampling it."""

        if not isinstance(prepared, PreparedDispatch):
            raise TypeError("publish_prepared() requires an opaque PreparedDispatch")
        if prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT:
            raise EventContractError(
                "Action-cohort dispatches require their claimed composite publication"
            )
        if prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT:
            raise EventContractError(
                "Network-dependent dispatches require their claimed ordered batch"
            )
        if prepared._state_intent in {
            PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT,
            PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT,
        }:
            raise StateError("Deferred-session dispatches require their claimed publication batch")
        if prepared._action_cohort_batch_id is not None:
            raise EventContractError("Action-cohort dispatches require their claimed ordered batch")
        if prepared._network_dependent_batch_id is not None:
            raise EventContractError("Prepared dispatch is claimed by a network-dependent batch")
        if prepared._deferred_session_publication_batch_id is not None:
            raise StateError("Prepared dispatch is claimed by a deferred-session batch")
        self.validate_prepared(prepared, before_materialization=False)
        timing_preparation = prepared._source_timing_preparation
        if timing_preparation is not None and (
            not timing_preparation.committed
            or timing_preparation.receipt is None
            or not self.source_timing_planner.authenticates_preparation_receipt(
                timing_preparation.receipt
            )
        ):
            raise EventContractError(
                "Prepared dispatch source timing capability has no authentic commit"
            )
        if prepared._state_intent is PreparedDispatchStateIntent.APPLY:
            if materialization_receipt is not None:
                raise EventContractError("Compatibility dispatch cannot consume a start receipt")
            current_version = self._state_materialization_version()
            if current_version != prepared._expected_state_version:
                raise StateError(
                    "Prepared dispatch state version is stale: "
                    f"expected {prepared._expected_state_version}, current {current_version}"
                )
        else:
            from evidenceforge.generation.lifecycle_authority import (
                LifecyclePreparedNetworkReceipt,
            )
            from evidenceforge.generation.network_runtime import (
                PreparedNetworkTransactionRoot,
            )
            from evidenceforge.generation.state_manager import (
                ProcessMaterializationPlan,
                ProcessTerminationMaterializationPlan,
                SessionMaterializationPlan,
            )

            plan = prepared._lifecycle_ticket
            if prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_TRANSPORT:
                if type(plan) is not PreparedNetworkTransactionRoot:
                    raise EventContractError(
                        "Externally materialized transport lost its prepared network root"
                    )
            elif prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE:
                if not isinstance(plan, ProcessTerminationMaterializationPlan):
                    raise EventContractError(
                        "Externally materialized close lost its opaque State plan"
                    )
            elif not isinstance(plan, (ProcessMaterializationPlan, SessionMaterializationPlan)):
                raise EventContractError(
                    "Externally materialized dispatch lost its opaque state plan"
                )
            authority = self._lifecycle_authority
            if authority is None:
                raise EventContractError(
                    "Externally materialized dispatch requires its bound lifecycle authority"
                )
            if prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_TRANSPORT:
                assert type(plan) is PreparedNetworkTransactionRoot
                timing_receipt = timing_preparation.receipt if timing_preparation else None
                receipt_authentic = (
                    type(materialization_receipt) is LifecyclePreparedNetworkReceipt
                    and timing_preparation is not None
                    and timing_receipt is not None
                    and materialization_receipt.timing_binding_token
                    == timing_preparation.binding_token
                    and materialization_receipt.timing_receipt == timing_receipt
                    and authority.authenticates_prepared_network_receipt(
                        plan,
                        materialization_receipt,
                    )
                )
                plan_version = plan.state_plan.expected_version
            else:
                receipt_authentic = (
                    authority.authenticates_process_service_closure_composite_receipt(
                        plan,
                        materialization_receipt,
                    )
                    if isinstance(plan, ProcessTerminationMaterializationPlan)
                    else authority.authenticates_materialization_receipt(
                        plan,
                        materialization_receipt,
                    )
                )
                plan_version = plan.expected_version
            if prepared._expected_state_version != plan_version or not receipt_authentic:
                raise EventContractError(
                    "Authority receipt does not authenticate the prepared dispatch plan"
                )
        if prepared._artifact_publications:
            registry = self.local_artifact_registry
            if registry is None:
                raise EventContractError(
                    "Prepared artifact publication lost its engine-owned registry"
                )
            for token in prepared._artifact_publications:
                if (
                    registry.resolve_version(token.record.artifact.artifact_version_id)
                    != token.record
                ):
                    raise EventContractError(
                        "Prepared artifact publication is not committed in canonical state"
                    )
        prepared._claim()
        event = prepared._occurrence
        if prepared._state_intent is PreparedDispatchStateIntent.APPLY:
            self._apply_prepared_state_and_lifecycle(event)
        elif prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_DEPENDENT:
            self.state_manager.apply(event)
        elif prepared._state_intent not in {
            PreparedDispatchStateIntent.EXTERNAL_TRANSPORT,
            PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_START,
            PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_CLOSE,
        }:
            raise EventContractError("Prepared dispatch contains an unknown state intent")
        if prepared._binary_identity_kind:
            with self._publication_ledger_lock:
                self._binary_identity_counts[prepared._binary_identity_kind] += 1
        self._record_effect_publication(event)
        self._record_intent_occurrence(
            event,
            authored_intent_id=prepared._authored_intent_id,
        )
        if event.network is not None and not event.network.application_layer_only:
            with self._publication_ledger_lock:
                self._latest_network_plan = event.network
        projection = prepared._projection
        if projection.mode == "deferred":
            if prepared._state_intent is not PreparedDispatchStateIntent.APPLY:
                raise EventContractError(
                    "Only a compatibility state publication may defer source projection"
                )
            projection = self._prepare_projection(event)
        return self._publish_prepared_projection(
            projection,
            authored_intent_id=prepared._authored_intent_id,
        )

    def validate_prepared(
        self,
        prepared: PreparedDispatch,
        *,
        before_materialization: bool = True,
    ) -> None:
        """Authenticate one prepared dispatch at the coordinator's precommit barrier."""

        if type(prepared) is not PreparedDispatch:
            raise TypeError("validate_prepared() requires an opaque PreparedDispatch")
        expected_integrity = self._prepared_dispatch_integrity(prepared)
        if not hmac.compare_digest(prepared._integrity_token, expected_integrity):
            raise EventContractError("Prepared dispatch integrity validation failed")
        timing_preparation = prepared._source_timing_preparation
        if (
            timing_preparation is not None
            and not self.source_timing_planner.authenticates_preparation(timing_preparation)
        ):
            raise EventContractError(
                "Prepared dispatch source timing capability failed authentication"
            )
        if before_materialization:
            current_version = self._state_materialization_version()
            if current_version != prepared._expected_state_version:
                raise StateError(
                    "Prepared dispatch state version is stale before materialization: "
                    f"expected {prepared._expected_state_version}, current {current_version}"
                )

    def persistent_smb_prepared_transport_facts(
        self,
        prepared: PreparedDispatch,
    ) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
        """Return the frozen transaction and sensor cohort for one deferred SMB root."""

        if type(prepared) is not PreparedDispatch:
            raise TypeError("Persistent SMB transport facts require an exact prepared dispatch")
        self.validate_prepared(prepared)
        return self._persistent_smb_prepared_transport_payload(prepared)

    @staticmethod
    def _persistent_smb_prepared_transport_payload(
        prepared: PreparedDispatch,
    ) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
        """Validate the frozen TCP/445 payload after dispatcher authentication."""

        occurrence = prepared._occurrence
        transaction = occurrence.network
        observations = occurrence.network_observations
        if (
            prepared._state_intent is not PreparedDispatchStateIntent.EXTERNAL_TRANSPORT
            or type(transaction) is not NetworkTransactionPlan
            or transaction.protocol != "tcp"
            or transaction.dst_port != 445
            or transaction.service != "smb"
            or transaction.conn_state != "SF"
            or transaction.closed_at is None
            or type(observations) is not tuple
            or any(type(item) is not NetworkSensorObservation for item in observations)
        ):
            raise EventContractError(
                "Persistent SMB transport facts require one successful physical TCP/445 root"
            )
        return transaction, observations

    def consume_persistent_smb_prepared_transport(
        self,
        prepared: PreparedDispatch,
        *,
        materialization_receipt: object,
    ) -> None:
        """Retire the deferred opening projection after exact close rows are frozen."""

        from evidenceforge.generation.lifecycle_authority import (
            LifecyclePreparedNetworkReceipt,
        )
        from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot

        if type(prepared) is not PreparedDispatch:
            raise TypeError("Persistent SMB transport consumption requires an exact dispatch")
        self.validate_prepared(prepared, before_materialization=False)
        timing_preparation = prepared._source_timing_preparation
        timing_receipt = timing_preparation.receipt if timing_preparation is not None else None
        root = prepared._lifecycle_ticket
        authority = self._lifecycle_authority
        if (
            prepared._state_intent is not PreparedDispatchStateIntent.EXTERNAL_TRANSPORT
            or type(root) is not PreparedNetworkTransactionRoot
            or type(materialization_receipt) is not LifecyclePreparedNetworkReceipt
            or timing_preparation is None
            or not timing_preparation.committed
            or timing_receipt is None
            or materialization_receipt.timing_binding_token != timing_preparation.binding_token
            or materialization_receipt.timing_receipt != timing_receipt
            or authority is None
            or prepared._expected_state_version != root.state_plan.expected_version
            or not authority.authenticates_prepared_network_receipt(
                root,
                materialization_receipt,
            )
        ):
            raise EventContractError(
                "Persistent SMB transport consumption requires its exact materialization receipt"
            )
        self._persistent_smb_prepared_transport_payload(prepared)
        prepared._claim()

    def rebind_persistent_smb_close(
        self,
        *,
        traffic_authority: object,
        binding: object,
        opening_transport: NetworkTransactionPlan,
        opening_observations: tuple[NetworkSensorObservation, ...],
        final_traffic: object,
        final_observation_traffic: tuple[object, ...],
        state_result: object,
    ) -> tuple[NetworkTransactionPlan, tuple[NetworkSensorObservation, ...]]:
        """Authenticate State's terminal SMB root and reconstruct its close traffic."""

        from evidenceforge.events.network import NetworkTrafficLedger
        from evidenceforge.generation.network_observation import (
            PersistentSmbTrafficRebindAuthority,
            PersistentSmbTrafficRebindBinding,
        )
        from evidenceforge.generation.state_manager import SmbConnectionFinalizationResult

        if type(traffic_authority) is not PersistentSmbTrafficRebindAuthority:
            raise EventContractError("Persistent SMB traffic authority has an invalid exact type")
        if type(binding) is not PersistentSmbTrafficRebindBinding:
            raise EventContractError("Persistent SMB traffic binding has an invalid exact type")
        if (
            type(opening_transport) is not NetworkTransactionPlan
            or type(opening_observations) is not tuple
        ):
            raise EventContractError("Persistent SMB opening cohort has invalid exact types")
        if any(type(item) is not NetworkSensorObservation for item in opening_observations):
            raise EventContractError("Persistent SMB opening observations have invalid exact types")
        if (
            type(final_traffic) is not NetworkTrafficLedger
            or type(final_observation_traffic) is not tuple
        ):
            raise EventContractError("Persistent SMB final traffic has invalid exact types")
        if any(type(item) is not NetworkTrafficLedger for item in final_observation_traffic):
            raise EventContractError("Persistent SMB final observations have invalid exact types")
        if (
            type(state_result) is not SmbConnectionFinalizationResult
            or not self.state_manager.authenticates_smb_connection_finalization_result(state_result)
            or state_result.final_transaction
            != replace(
                opening_transport,
                traffic=final_traffic,
            )
        ):
            raise EventContractError("Persistent SMB close lacks an exact State terminal proof")
        close_facts_digest = traffic_authority._prepare_close_proof_digest(
            binding,
            final_traffic,
            final_observation_traffic,
        )
        proof_authenticator = _PersistentSmbStateCloseProofAuthenticator(
            state_manager=self.state_manager,
            state_result=state_result,
            binding_id=binding.binding_id,
            close_facts_digest=close_facts_digest,
        )
        return traffic_authority._rebind_authenticated_close(
            binding,
            opening_transport,
            final_traffic,
            opening_observations,
            final_observation_traffic,
            state_result,
            proof_authenticator,
        )

    @staticmethod
    def _action_cohort_target_identity(target: object) -> object:
        """Return the exact identity carried by a State plan or live target."""

        from evidenceforge.generation.state_manager import (
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        if type(target) in {ProcessMaterializationPlan, SessionMaterializationPlan}:
            return target.identity
        return target

    def _validate_action_cohort_dispatch_coverage(
        self,
        state_plan: ActionCohortMaterializationPlan,
        dispatches: tuple[PreparedDispatch, ...],
    ) -> None:
        """Require all-and-only State starts/closes with causal projection ordering."""

        from evidenceforge.events.identity import ProcessIdentity, SessionIdentity

        session_starts = {plan.identity.object_id: plan.identity for plan in state_plan.sessions}
        process_starts = {plan.identity.object_id: plan.identity for plan in state_plan.processes}
        process_closes = {item.identity.object_id: item for item in state_plan.process_terminations}
        session_closes = {
            item.identity.object_id: item for item in state_plan.session_terminalizations
        }
        expected_starts = {
            *(("session", object_id) for object_id in session_starts),
            *(("process", object_id) for object_id in process_starts),
        }
        expected_closes = {
            *(("process", object_id) for object_id in process_closes),
            *(("session", object_id) for object_id in session_closes),
        }
        observed_starts: dict[tuple[str, str], int] = {}
        observed_closes: dict[tuple[str, str], int] = {}
        process_or_session_ids: set[str] = set()
        members_by_identity: dict[str, list[PreparedDispatch]] = {}

        for position, prepared in enumerate(dispatches):
            event = prepared._occurrence
            key = event.occurrence_key
            if type(key) is not SemanticOccurrenceKey:
                raise EventContractError(
                    "Action-cohort dispatch requires exact semantic occurrence identity"
                )
            identity_plan = event.identity_plan
            if identity_plan is None:
                raise EventContractError(
                    "Action-cohort dispatch requires an exact canonical identity plan"
                )
            identities = tuple(
                candidate
                for candidate in (
                    identity_plan.subject,
                    identity_plan.actor,
                    identity_plan.target,
                    identity_plan.session,
                )
                if type(candidate) in {ProcessIdentity, SessionIdentity}
            )
            if not identities:
                raise EventContractError(
                    "Action-cohort dispatch has no State process/session identity binding"
                )
            process_or_session_ids.update(identity.object_id for identity in identities)
            for identity in identities:
                members_by_identity.setdefault(identity.object_id, []).append(prepared)

            subject = identity_plan.subject
            marker: tuple[str, str] | None = None
            if event.event_type in {
                EventKind.LOGON,
                EventKind.MACHINE_LOGON,
                EventKind.SSH_SESSION,
            }:
                if type(subject) is not SessionIdentity:
                    raise EventContractError(
                        "Action-cohort session start requires an exact session subject"
                    )
                marker = ("session", subject.object_id)
                expected = session_starts.get(subject.object_id)
                if (
                    expected is None
                    or subject != expected
                    or event.timestamp != expected.started_at
                ):
                    raise EventContractError(
                        "Action-cohort session-start projection disagrees with its State plan"
                    )
                if marker in observed_starts:
                    raise EventContractError("Action-cohort repeats a session-start projection")
                observed_starts[marker] = position
            elif event.event_type in {EventKind.PROCESS_CREATE, EventKind.SYSTEM_PROCESS_CREATE}:
                if type(subject) is not ProcessIdentity:
                    raise EventContractError(
                        "Action-cohort process start requires an exact process subject"
                    )
                marker = ("process", subject.object_id)
                expected = process_starts.get(subject.object_id)
                if (
                    expected is None
                    or subject != expected
                    or event.timestamp != expected.started_at
                ):
                    raise EventContractError(
                        "Action-cohort process-start projection disagrees with its State plan"
                    )
                if marker in observed_starts:
                    raise EventContractError("Action-cohort repeats a process-start projection")
                observed_starts[marker] = position
            elif event.event_type is EventKind.PROCESS_TERMINATE:
                if type(subject) is not ProcessIdentity:
                    raise EventContractError(
                        "Action-cohort process close requires an exact process subject"
                    )
                marker = ("process", subject.object_id)
                expected = process_closes.get(subject.object_id)
                if (
                    expected is None
                    or subject != expected.identity
                    or event.timestamp != expected.end_time
                ):
                    raise EventContractError(
                        "Action-cohort process-close projection disagrees with its State plan"
                    )
                if marker in observed_closes:
                    raise EventContractError("Action-cohort repeats a process-close projection")
                observed_closes[marker] = position
            elif event.event_type is EventKind.LOGOFF:
                if type(subject) is not SessionIdentity:
                    raise EventContractError(
                        "Action-cohort session close requires an exact session subject"
                    )
                marker = ("session", subject.object_id)
                expected = session_closes.get(subject.object_id)
                if (
                    expected is None
                    or subject != expected.identity
                    or event.timestamp != expected.end_time
                ):
                    raise EventContractError(
                        "Action-cohort session-close projection disagrees with its State plan"
                    )
                if marker in observed_closes:
                    raise EventContractError("Action-cohort repeats a session-close projection")
                observed_closes[marker] = position
            elif event.lifecycle is not None and event.lifecycle.phase in {"start", "closure"}:
                raise EventContractError(
                    "Action-cohort lifecycle start/closure uses an unsupported event kind"
                )

        if set(observed_starts) != expected_starts:
            raise EventContractError(
                "Action-cohort dispatches do not cover every exact State start once"
            )
        if set(observed_closes) != expected_closes:
            raise EventContractError(
                "Action-cohort dispatches do not cover every exact State close once"
            )

        for marker, start_position in observed_starts.items():
            close_position = observed_closes.get(marker)
            if close_position is not None and close_position <= start_position:
                raise EventContractError(
                    "Action-cohort projection closes a State member before its start"
                )

        process_by_host_pid = {
            (plan.identity.hostname, plan.identity.pid): plan.identity
            for plan in state_plan.processes
        }
        session_by_host_logon = {
            (plan.identity.hostname, plan.identity.logon_id): plan.identity
            for plan in state_plan.sessions
        }
        for process in state_plan.processes:
            identity = process.identity
            child_start = observed_starts[("process", identity.object_id)]
            parent = process_by_host_pid.get((identity.hostname, identity.parent_pid))
            if parent is not None:
                parent_marker = ("process", parent.object_id)
                if observed_starts[parent_marker] >= child_start:
                    raise EventContractError(
                        "Action-cohort child projection precedes its staged parent"
                    )
                child_close = observed_closes.get(("process", identity.object_id))
                parent_close = observed_closes.get(parent_marker)
                if (
                    child_close is not None
                    and parent_close is not None
                    and child_close >= parent_close
                ):
                    raise EventContractError(
                        "Action-cohort parent projection closes before its staged child"
                    )
            session = session_by_host_logon.get((identity.hostname, identity.logon_id))
            if session is not None:
                session_marker = ("session", session.object_id)
                if observed_starts[session_marker] >= child_start:
                    raise EventContractError(
                        "Action-cohort member projection precedes its staged session"
                    )
                process_close = observed_closes.get(("process", identity.object_id))
                session_close = observed_closes.get(session_marker)
                if (
                    process_close is not None
                    and session_close is not None
                    and process_close >= session_close
                ):
                    raise EventContractError(
                        "Action-cohort session projection closes before its staged member"
                    )

        allowed_ids = {
            *(identity.object_id for identity in session_starts.values()),
            *(identity.object_id for identity in process_starts.values()),
            *(item.identity.object_id for item in state_plan.process_terminations),
            *(item.identity.object_id for item in state_plan.session_terminalizations),
            *(
                self._action_cohort_target_identity(patch.target).object_id
                for patch in (
                    *state_plan.session_metadata_patches,
                    *state_plan.process_activity_patches,
                    *state_plan.session_activity_patches,
                )
            ),
            *(patch.target.object_id for patch in state_plan.live_session_process_role_patches),
        }
        patch_target_ids = {
            self._action_cohort_target_identity(patch.target).object_id
            for patch in (
                *state_plan.session_metadata_patches,
                *state_plan.process_activity_patches,
                *state_plan.session_activity_patches,
            )
        }
        patch_target_ids.update(
            patch.target.object_id for patch in state_plan.live_session_process_role_patches
        )
        for process in state_plan.processes:
            if process._payload.parent_activity_time is None:
                continue
            parent = self.state_manager.get_process_identity(
                process.identity.hostname,
                process.identity.parent_pid,
            )
            if parent is not None:
                allowed_ids.add(parent.object_id)
        if not process_or_session_ids.issubset(allowed_ids):
            raise EventContractError(
                "Action-cohort projection references a process/session outside its State plan"
            )
        if not patch_target_ids.issubset(process_or_session_ids):
            raise EventContractError(
                "Action-cohort State patch target has no exact canonical member binding"
            )

        def exact_identity_members(identity: object) -> tuple[PreparedDispatch, ...]:
            return tuple(
                prepared
                for prepared in members_by_identity.get(identity.object_id, ())
                if prepared._occurrence.identity_plan is not None
                and any(
                    type(candidate) is type(identity) and candidate == identity
                    for candidate in (
                        prepared._occurrence.identity_plan.subject,
                        prepared._occurrence.identity_plan.actor,
                        prepared._occurrence.identity_plan.target,
                        prepared._occurrence.identity_plan.session,
                    )
                )
            )

        def visible_source_times(
            members: tuple[PreparedDispatch, ...],
        ) -> tuple[datetime, ...]:
            return tuple(
                timestamp
                for prepared in members
                for source in self._action_cohort_projection_facts(
                    prepared._occurrence,
                    prepared._projection,
                ).sources
                if source.status in {"visible", "delayed"}
                for _key, timestamp in source.finalized_times
            )

        def has_visible_member_at(
            members: tuple[PreparedDispatch, ...],
            timestamp: datetime,
        ) -> bool:
            return any(
                prepared._occurrence.timestamp == timestamp
                and any(
                    source.status in {"visible", "delayed"}
                    for source in self._action_cohort_projection_facts(
                        prepared._occurrence,
                        prepared._projection,
                    ).sources
                )
                for prepared in members
            )

        def has_canonical_member_at(
            members: tuple[PreparedDispatch, ...],
            timestamp: datetime,
        ) -> bool:
            """Return whether canonical cohort truth owns this exact activity frontier."""

            return any(prepared._occurrence.timestamp == timestamp for prepared in members)

        for patch in state_plan.session_metadata_patches:
            identity = self._action_cohort_target_identity(patch.target)
            members = exact_identity_members(identity)
            if not members:
                raise EventContractError(
                    "Action-cohort session metadata patch has no exact identity member"
                )
            source_times = visible_source_times(members)
            if (
                patch.after.source_ready_time is not None
                and patch.after.source_ready_time not in source_times
            ):
                raise EventContractError(
                    "Action-cohort session readiness is not a visible prepared source frontier"
                )
            if (
                patch.after.network_close_time is not None
                and patch.after.network_close_time
                not in {
                    *(prepared._occurrence.timestamp for prepared in members),
                    *source_times,
                }
            ):
                raise EventContractError(
                    "Action-cohort session network close has no exact prepared frontier"
                )
        for patch in state_plan.live_session_process_role_patches:
            if not exact_identity_members(patch.target):
                raise EventContractError(
                    "Action-cohort live-session role patch has no exact identity member"
                )
            staged_role_ids = {
                process.identity.object_id
                for process in (
                    patch.winlogon_plan,
                    patch.explorer_plan,
                    patch.process_tree_root_plan,
                )
                if process is not None
            }
            if not staged_role_ids.issubset(process_starts):
                raise EventContractError(
                    "Action-cohort live-session role patch references an unstaged process"
                )
        for patch in state_plan.process_activity_patches:
            identity = self._action_cohort_target_identity(patch.target)
            if not has_canonical_member_at(
                exact_identity_members(identity),
                patch.activity_time,
            ):
                raise EventContractError(
                    "Action-cohort process activity patch has no canonical exact-time member"
                )
        for patch in state_plan.session_activity_patches:
            identity = self._action_cohort_target_identity(patch.target)
            if not has_canonical_member_at(
                exact_identity_members(identity),
                patch.activity_time,
            ):
                raise EventContractError(
                    "Action-cohort session activity patch has no canonical exact-time member"
                )
        for process in state_plan.processes:
            parent_activity_time = process._payload.parent_activity_time
            if parent_activity_time is None:
                continue
            parent = self.state_manager.get_process_identity(
                process.identity.hostname,
                process.identity.parent_pid,
            )
            if parent is None or not has_canonical_member_at(
                exact_identity_members(parent),
                parent_activity_time,
            ):
                raise EventContractError(
                    "Action-cohort live-parent activity has no canonical exact prepared member"
                )

    @staticmethod
    def _action_cohort_effect_member_is_compatible(
        node: object,
        event: CanonicalOccurrence,
    ) -> bool:
        """Return finite intent/context/event compatibility for one realized member."""

        from evidenceforge.generation.actions.command_effects import (
            ChildProcessEffectIntent,
            FileEffectAction,
            FileEffectIntent,
            NetworkEffectIntent,
            RegistryEffectIntent,
            ScannerEffectIntent,
            ScheduledTaskEffectAction,
            ScheduledTaskEffectIntent,
            ServiceEffectAction,
            ServiceEffectIntent,
            SessionEffectAction,
            SessionEffectIntent,
            TransferEffectIntent,
            WindowsAuditEffectIntent,
            WindowsAuditEffectKind,
        )

        intent = node.intent
        key = event.occurrence_key
        if type(key) is not SemanticOccurrenceKey:
            return False
        if type(intent) is ChildProcessEffectIntent:
            if node.role is OccurrenceRole.CLOSURE:
                return bool(
                    event.event_type is EventKind.PROCESS_TERMINATE
                    and key.role is OccurrenceRole.CLOSURE
                    and event.process is not None
                )
            return bool(
                event.event_type in {EventKind.PROCESS_CREATE, EventKind.SYSTEM_PROCESS_CREATE}
                and key.role is OccurrenceRole.PRIMARY
                and event.process is not None
            )
        if type(intent) is FileEffectIntent:
            expected = {
                FileEffectAction.READ: EventKind.FILE_READ,
                FileEffectAction.CREATE: EventKind.FILE_CREATE,
                FileEffectAction.MODIFY: EventKind.FILE_MODIFY,
                FileEffectAction.DELETE: EventKind.FILE_DELETE,
            }[intent.action]
            return bool(
                event.event_type is expected and key.role is node.role and event.file is not None
            )
        if type(intent) is RegistryEffectIntent:
            return bool(
                event.event_type is EventKind.REGISTRY_MODIFY
                and key.role is node.role
                and event.registry is not None
            )
        if type(intent) in {NetworkEffectIntent, ScannerEffectIntent}:
            return bool(
                event.event_type is EventKind.CONNECTION
                and key.role is node.role
                and event.network is not None
            )
        if type(intent) is TransferEffectIntent:
            return bool(
                event.event_type
                in {EventKind.CONNECTION, EventKind.FILE_CREATE, EventKind.FILE_READ}
                and key.role is node.role
                and (event.network is not None or event.file is not None)
            )
        if type(intent) is ScheduledTaskEffectIntent:
            expected = {
                ScheduledTaskEffectAction.CREATE: EventKind.SCHEDULED_TASK_CREATED,
                ScheduledTaskEffectAction.DELETE: EventKind.SCHEDULED_TASK_DELETED,
                ScheduledTaskEffectAction.DISABLE: EventKind.SCHEDULED_TASK_DISABLED,
                ScheduledTaskEffectAction.ENABLE: EventKind.SCHEDULED_TASK_ENABLED,
            }[intent.action]
            return bool(
                event.event_type is expected
                and key.role is node.role
                and event.scheduled_task is not None
            )
        if type(intent) is ServiceEffectIntent:
            return bool(
                intent.action is ServiceEffectAction.INSTALL
                and event.event_type is EventKind.SERVICE_INSTALLED
                and key.role is node.role
                and event.service is not None
            )
        if type(intent) is SessionEffectIntent:
            if intent.action is SessionEffectAction.START:
                return bool(
                    event.event_type
                    in {EventKind.LOGON, EventKind.MACHINE_LOGON, EventKind.SSH_SESSION}
                    and key.role is OccurrenceRole.PRIMARY
                )
            return bool(
                intent.action is SessionEffectAction.CLOSE
                and event.event_type is EventKind.LOGOFF
                and key.role is OccurrenceRole.CLOSURE
            )
        if type(intent) is WindowsAuditEffectIntent:
            expected_by_kind: dict[WindowsAuditEffectKind, frozenset[EventKind]] = {
                WindowsAuditEffectKind.ACCOUNT_CREATED: frozenset({EventKind.ACCOUNT_CREATED}),
                WindowsAuditEffectKind.ACCOUNT_DELETED: frozenset({EventKind.ACCOUNT_DELETED}),
                WindowsAuditEffectKind.ACCOUNT_CHANGED: frozenset({EventKind.ACCOUNT_CHANGED}),
                WindowsAuditEffectKind.EXPLICIT_CREDENTIALS: frozenset(
                    {EventKind.EXPLICIT_CREDENTIALS}
                ),
                WindowsAuditEffectKind.GROUP_MEMBERSHIP_CHANGED: frozenset(
                    {
                        EventKind.GROUP_MEMBER_ADDED_GLOBAL,
                        EventKind.GROUP_MEMBER_ADDED_LOCAL,
                        EventKind.GROUP_MEMBER_ADDED_UNIVERSAL,
                        EventKind.GROUP_MEMBER_REMOVED_GLOBAL,
                        EventKind.GROUP_MEMBER_REMOVED_LOCAL,
                        EventKind.GROUP_MEMBER_REMOVED_UNIVERSAL,
                    }
                ),
                WindowsAuditEffectKind.LOG_CLEARED: frozenset({EventKind.LOG_CLEARED}),
            }
            return bool(
                event.event_type in expected_by_kind[intent.audit_kind] and key.role is node.role
            )
        return False

    def _validate_action_cohort_effect_member_bindings(
        self,
        *,
        root_action_id: str,
        state_plan: ActionCohortMaterializationPlan,
        dispatches: tuple[PreparedDispatch, ...],
        audit_entries: tuple[ExecutionEffectAuditCohortEntry, ...],
        bindings: tuple[ActionCohortEffectMemberBinding, ...],
        external_links: tuple[ActionCohortExternalEffectLink, ...],
        owned_effect_plans: tuple[OwnedEffectOccurrencePlan, ...],
    ) -> None:
        """Require a bijection from every realized effect ordinal to an exact member."""

        from evidenceforge.generation.actions.command_effects import (
            ChildProcessEffectIntent,
            EffectOutcomeStatus,
            FileEffectIntent,
            RegistryEffectIntent,
            SessionEffectIntent,
        )

        dispatch_ids = {id(dispatch): dispatch for dispatch in dispatches}
        dispatch_positions = {
            id(dispatch): position for position, dispatch in enumerate(dispatches)
        }
        expected: dict[tuple[int, str, int], tuple[object, object, object]] = {}
        expected_links: dict[tuple[int, str], tuple[object, object]] = {}
        for entry_ordinal, entry in enumerate(audit_entries):
            nodes = {node.node_id: node for node in entry.plan.nodes}
            for outcome in entry.reconciliation.outcomes:
                node = nodes.get(outcome.node_id)
                if node is None:
                    raise EventContractError(
                        "Action-cohort audit outcome has no exact planned node"
                    )
                if outcome.status is not EffectOutcomeStatus.REALIZED:
                    if outcome.status is EffectOutcomeStatus.LINKED:
                        expected_links[(entry_ordinal, node.node_id)] = (node, outcome)
                    continue
                cardinality = node.intent.occurrence_cardinality
                if outcome.canonical_occurrence_count != cardinality:
                    raise EventContractError(
                        "Action-cohort realized effect cardinality changed after reconciliation"
                    )
                if cardinality != 1 and type(node.intent) not in {
                    FileEffectIntent,
                    RegistryEffectIntent,
                }:
                    raise EventContractError(
                        "Multi-occurrence action cohorts require a typed per-ordinal "
                        "State/lifecycle authority"
                    )
                for occurrence_ordinal in range(cardinality):
                    expected[(entry_ordinal, node.node_id, occurrence_ordinal)] = (
                        entry,
                        node,
                        outcome,
                    )

        observed: dict[tuple[int, str, int], ActionCohortEffectMemberBinding] = {}
        bound_member_ids: set[int] = set()
        for binding in bindings:
            key = (binding.entry_ordinal, binding.node_id, binding.occurrence_ordinal)
            if key in observed or id(binding.member) in bound_member_ids:
                raise EventContractError(
                    "Action-cohort effect bindings repeat a node ordinal or member"
                )
            pair = expected.get(key)
            if pair is None or dispatch_ids.get(id(binding.member)) is not binding.member:
                raise EventContractError(
                    "Action-cohort effect binding is extra or references a foreign member"
                )
            entry, node, outcome = pair
            event = binding.member._occurrence
            occurrence_key = event.occurrence_key
            lifecycle = event.lifecycle
            expected_action_id = stable_uuid(
                "canonical-action",
                lifecycle.group_id if lifecycle is not None else "",
            )
            if (
                type(occurrence_key) is not SemanticOccurrenceKey
                or not outcome.child_action_id
                or occurrence_key.action_id != expected_action_id
                or lifecycle is None
                or outcome.child_action_id != lifecycle.group_id
                or not self._action_cohort_effect_member_is_compatible(node, event)
            ):
                raise EventContractError(
                    "Action-cohort effect binding disagrees with action, time, role, or kind"
                )
            context_kind = (
                EffectOccurrenceKind.FILE
                if event.file is not None
                else EffectOccurrenceKind.REGISTRY
                if event.registry is not None
                else None
            )
            if context_kind is not None:
                provenance = event.effect_provenance
                if (
                    type(provenance) is not EffectOccurrenceProvenance
                    or provenance.kind is not context_kind
                    or provenance.disposition is not EffectOccurrenceDisposition.PLANNED
                    or provenance.root_action_id != root_action_id
                    or provenance.plan_action_id != entry.plan.action_id
                    or provenance.node_id != node.node_id
                    or provenance.occurrence_ordinal != binding.occurrence_ordinal
                    or occurrence_key.instance_key
                    != stable_uuid(
                        "endpoint-effect-occurrence",
                        entry.plan.action_id,
                        node.node_id,
                        binding.occurrence_ordinal,
                        event.timestamp.isoformat(),
                    )
                ):
                    raise EventContractError(
                        "Action-cohort endpoint effect provenance disagrees with its binding"
                    )
            observed[key] = binding
            bound_member_ids.add(id(binding.member))

        if set(observed) != set(expected):
            raise EventContractError(
                "Action-cohort effect bindings do not cover every realized ordinal exactly"
            )
        from evidenceforge.events.identity import ProcessIdentity, SessionIdentity

        realized_groups = {
            (entry_ordinal, node_id) for entry_ordinal, node_id, _occurrence_ordinal in expected
        }
        for entry_ordinal, node_id in realized_groups:
            members = tuple(
                observed[(entry_ordinal, node_id, occurrence_ordinal)].member
                for occurrence_ordinal in range(
                    len(
                        tuple(
                            key for key in expected if key[0] == entry_ordinal and key[1] == node_id
                        )
                    )
                )
            )
            outcome = expected[(entry_ordinal, node_id, 0)][2]
            timestamps = tuple(member._occurrence.timestamp for member in members)
            if len(members) == 1:
                valid_completion = outcome.completed_at == timestamps[0]
            else:
                member_positions = tuple(dispatch_positions[id(member)] for member in members)
                actors = tuple(
                    member._occurrence.identity_plan.actor
                    if member._occurrence.identity_plan is not None
                    else None
                    for member in members
                )
                lifecycles = tuple(member._occurrence.lifecycle for member in members)
                actor = actors[0]
                has_covering_activity_patch = bool(
                    type(actor) is ProcessIdentity
                    and any(
                        self._action_cohort_target_identity(patch.target) == actor
                        and patch.activity_time >= timestamps[-1]
                        for patch in state_plan.process_activity_patches
                    )
                )
                valid_completion = bool(
                    type(actor) is ProcessIdentity
                    and all(candidate == actor for candidate in actors)
                    and all(
                        lifecycle is not None
                        and lifecycle.group_id == actor.lifecycle_group_id
                        and lifecycle.canonical_start == actor.started_at
                        for lifecycle in lifecycles
                    )
                    and member_positions == tuple(sorted(member_positions))
                    and timestamps == tuple(sorted(timestamps))
                    and outcome.completed_at == timestamps[-1]
                    and has_covering_activity_patch
                )
            if not valid_completion:
                raise EventContractError(
                    "Action-cohort realized effect completion or per-ordinal authority "
                    "disagrees with its members"
                )

        from evidenceforge.generation.state_manager import (
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        staged_identity_ids = {
            *(plan.identity.object_id for plan in state_plan.sessions),
            *(plan.identity.object_id for plan in state_plan.processes),
        }
        state_owned_identities = tuple(
            identity
            for identity in (
                *(patch.target for patch in state_plan.live_session_process_role_patches),
                *(
                    patch.target
                    for patch in (
                        *state_plan.session_metadata_patches,
                        *state_plan.process_activity_patches,
                        *state_plan.session_activity_patches,
                    )
                    if type(patch.target)
                    not in {
                        ProcessMaterializationPlan,
                        SessionMaterializationPlan,
                    }
                ),
                *(
                    item.target
                    for item in (
                        *state_plan.process_terminations,
                        *state_plan.session_terminalizations,
                    )
                    if type(item.target)
                    not in {
                        ProcessMaterializationPlan,
                        SessionMaterializationPlan,
                    }
                ),
            )
            if type(identity) in {ProcessIdentity, SessionIdentity}
            and identity.object_id not in staged_identity_ids
        )
        observed_links: set[tuple[int, str]] = set()
        for link in external_links:
            link_key = (link.entry_ordinal, link.node_id)
            pair = expected_links.get(link_key)
            if link_key in observed_links or pair is None:
                raise EventContractError("Action-cohort external-effect link is duplicate or extra")
            node, outcome = pair
            owner = next(
                (identity for identity in state_owned_identities if identity is link.owner),
                None,
            )
            owner_type_is_compatible = bool(
                (type(node.intent) is ChildProcessEffectIntent and type(owner) is ProcessIdentity)
                or (type(node.intent) is SessionEffectIntent and type(owner) is SessionIdentity)
            )
            live_owner = None
            if owner_type_is_compatible and type(owner) is ProcessIdentity:
                live_owner = self.state_manager.get_process_identity_by_object_id(owner.object_id)
            elif owner_type_is_compatible and type(owner) is SessionIdentity:
                live_session = self.state_manager.get_session(owner.logon_id)
                live_owner = (
                    self.state_manager.get_session_identity(owner.logon_id)
                    if live_session is not None
                    else None
                )
            if (
                owner is None
                or not owner_type_is_compatible
                or type(live_owner) is not type(owner)
                or live_owner != owner
                or getattr(owner, "lifecycle_group_id", None) != outcome.child_action_id
            ):
                raise EventContractError(
                    "Action-cohort linked effect has no exact State-owned external identity"
                )
            observed_links.add(link_key)
        if observed_links != set(expected_links):
            raise EventContractError(
                "Action-cohort external-effect links do not cover every linked node exactly"
            )

        owned_keys = {
            (plan.plan_action_id, plan.node_id, occurrence_ordinal)
            for plan in owned_effect_plans
            for occurrence_ordinal in range(plan.occurrence_count)
        }
        if len(owned_keys) != sum(plan.occurrence_count for plan in owned_effect_plans):
            raise EventContractError("Action-cohort owned effect plans repeat an exact ordinal")
        bootstrap_kinds = {
            EventKind.LOGON,
            EventKind.MACHINE_LOGON,
            EventKind.SSH_SESSION,
            EventKind.PROCESS_CREATE,
            EventKind.SYSTEM_PROCESS_CREATE,
            EventKind.PROCESS_TERMINATE,
            EventKind.LOGOFF,
        }
        observed_owned_keys: set[tuple[str, str, int]] = set()
        for prepared in dispatches:
            if id(prepared) in bound_member_ids:
                continue
            event = prepared._occurrence
            provenance = event.effect_provenance
            owned = bool(
                type(provenance) is EffectOccurrenceProvenance
                and provenance.disposition is EffectOccurrenceDisposition.OWNED_ROOT
                and provenance.root_action_id == root_action_id
                and (
                    provenance.plan_action_id,
                    provenance.node_id,
                    provenance.occurrence_ordinal,
                )
                in owned_keys
            )
            if owned:
                observed_owned_keys.add(
                    (
                        provenance.plan_action_id,
                        provenance.node_id,
                        provenance.occurrence_ordinal,
                    )
                )
            if event.event_type not in bootstrap_kinds and not owned:
                raise EventContractError(
                    "Unbound action-cohort member is not a finite State bootstrap or owned root"
                )
        if observed_owned_keys != owned_keys:
            raise EventContractError(
                "Action-cohort owned effect plans do not cover every exact ordinal"
            )

    @staticmethod
    def _action_cohort_batch_retained_size(
        state_plan: ActionCohortMaterializationPlan,
        dispatches: tuple[PreparedDispatch, ...],
        artifact_publications: tuple[LocalArtifactPublishToken, ...],
        lifecycle_request: LifecycleActionCohortRequest,
        audit_entries: tuple[ExecutionEffectAuditCohortEntry, ...],
        effect_member_bindings: tuple[ActionCohortEffectMemberBinding, ...],
        external_effect_links: tuple[ActionCohortExternalEffectLink, ...],
        owned_effect_plans: tuple[OwnedEffectOccurrencePlan, ...],
        published_provenances: tuple[EffectOccurrenceProvenance, ...],
        observation_deltas: tuple[_ActionCohortObservationDelta, ...],
        intent_request: IntentExecutionBatchRequest | None,
    ) -> int:
        """Charge every complete variable-size value retained by one batch."""

        member_payloads = tuple(
            repr(
                (
                    prepared._occurrence,
                    EventDispatcher._prepared_projection_signature(prepared._projection),
                )
            ).encode("utf-8")
            for prepared in dispatches
        )
        owner_payloads = (
            repr(state_plan).encode("utf-8"),
            repr(artifact_publications).encode("utf-8"),
            repr(lifecycle_request).encode("utf-8"),
            repr(audit_entries).encode("utf-8"),
            repr(effect_member_bindings).encode("utf-8"),
            repr(external_effect_links).encode("utf-8"),
            repr(owned_effect_plans).encode("utf-8"),
            repr(published_provenances).encode("utf-8"),
            repr(observation_deltas).encode("utf-8"),
            repr(intent_request).encode("utf-8"),
        )
        return 2_048 + sum(len(payload) for payload in (*member_payloads, *owner_payloads))

    def _action_cohort_member_integrity_digest(
        self,
        dispatches: tuple[PreparedDispatch, ...],
    ) -> str:
        """Bind exact member object identity, order, and complete prepared integrity."""

        payload = tuple(
            (
                id(prepared),
                prepared.occurrence_id,
                prepared._integrity_token,
                self._prepared_dispatch_integrity(prepared),
                prepared._expected_state_version,
                prepared._authored_intent_id,
            )
            for prepared in dispatches
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _freeze_action_cohort_projection(projection: _PreparedProjection) -> _PreparedProjection:
        """Detach the source-render plan from caller-reachable projection carriers."""

        return _PreparedProjection(
            mode=projection.mode,
            occurrence=projection.occurrence,
            initial_statuses=tuple(projection.initial_statuses),
            legacy_targets=tuple(replace(target) for target in projection.legacy_targets),
            compiled_targets=tuple(replace(target) for target in projection.compiled_targets),
        )

    @staticmethod
    def _action_cohort_effect_binding_digest(
        bindings: tuple[ActionCohortEffectMemberBinding, ...],
        external_links: tuple[ActionCohortExternalEffectLink, ...],
    ) -> str:
        """Bind exact binding order, keys, member identity, and occurrence truth."""

        payload = (
            tuple(
                (
                    binding.entry_ordinal,
                    binding.node_id,
                    binding.occurrence_ordinal,
                    id(binding.member),
                    binding.member.occurrence_id,
                    repr(binding.member._occurrence.occurrence_key),
                    binding.member._occurrence.timestamp,
                )
                for binding in bindings
            ),
            tuple(
                (
                    link.entry_ordinal,
                    link.node_id,
                    id(link.owner),
                    repr(link.owner),
                )
                for link in external_links
            ),
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _action_cohort_nested_token_digest(
        *,
        timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleActionCohortAdmissionToken,
        audit_preparation: PreparedExecutionEffectAuditCommit,
        intent_token: IntentExecutionBatchToken | None,
    ) -> str:
        """Return ordered primitive proof fields for every prepared nested owner."""

        timing = timing_preparation.binding_token
        audit = audit_preparation.binding_token
        signature = (
            (
                "timing",
                getattr(timing, "preparation_id", None),
                getattr(timing, "base_state_digest", None),
                getattr(timing, "_integrity", None),
            ),
            (
                "audit",
                id(audit),
                getattr(audit, "_owner_id", None),
                getattr(audit, "_preparation_id", None),
                getattr(audit, "_cohort_digest", None),
                getattr(audit, "_identity_digest", None),
                getattr(audit, "_delta_digest", None),
                getattr(audit, "_integrity", None),
            ),
            (
                "intent",
                id(intent_token) if intent_token is not None else None,
                getattr(intent_token, "ledger_id", None),
                getattr(intent_token, "preparation_id", None),
                getattr(intent_token, "plan_digest", None),
                getattr(intent_token, "_integrity", None),
            ),
            (
                "lifecycle",
                id(lifecycle_token),
                lifecycle_token.registry_id,
                lifecycle_token.preparation_id,
                lifecycle_token.plan_digest,
                lifecycle_token.publication_token,
            ),
        )
        return hashlib.sha256(repr(signature).encode("utf-8")).hexdigest()

    def _action_cohort_batch_integrity(
        self,
        carrier: PreparedActionCohortBatch,
        record: _PreparedActionCohortBatchRecord,
    ) -> str:
        """Authenticate the exact outer object and every ordered nested capability."""

        payload = repr(
            (
                "prepared-action-cohort-batch-v2",
                id(carrier),
                record.batch_id,
                record.root_action_id,
                id(record.state_plan),
                record.state_plan_digest,
                record.member_integrity_digest,
                record.effect_binding_digest,
                record.observation_digest,
                record.nested_token_digest,
                record.exact_projection,
                record.exact_projection_kind,
                record.exact_all_suppressed,
                id(record.exact_publication_batch),
                record.exact_prepared_identifiers,
                record.exact_prepared_row_count,
                tuple(
                    (
                        id(token),
                        token.publication_token,
                        token.record.artifact.artifact_version_id,
                    )
                    for token in record.artifact_publications
                ),
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _action_cohort_claim_integrity(
        self,
        capability: PreparedActionCohortCapability,
        record: _PreparedActionCohortBatchRecord,
    ) -> str:
        """Bind one same-thread claim to its exact retained batch record."""

        payload = repr(
            (
                "claimed-action-cohort-v1",
                id(capability),
                id(self),
                record.batch_id,
                record.carrier_id,
                record.claim_thread_id,
                record.integrity_token,
                record.member_integrity_digest,
                record.nested_token_digest,
                id(record.expected_timing_receipt),
                id(record.expected_state_result),
                record.expected_state_result_publication_token,
                id(record.expected_lifecycle_receipt),
                id(record.expected_audit_receipt),
                id(record.expected_intent_receipt),
                id(record.publication_receipt),
                (
                    record.publication_receipt._integrity
                    if record.publication_receipt is not None
                    else ""
                ),
                id(record.publication_result),
                tuple(id(outcome) for outcome in record.projection_outcomes),
                id(record.exact_publication_batch),
                id(record.exact_recovery),
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _action_cohort_receipt_integrity(
        self,
        receipt: ActionCohortPublicationReceipt,
    ) -> str:
        """Authenticate one exact outer receipt using only closed primitive fields."""

        payload = repr(
            (
                "action-cohort-publication-receipt-v1",
                id(receipt),
                receipt.dispatcher_id,
                receipt.receipt_id,
                receipt.publication_token,
                receipt.root_action_id,
                receipt.state_semantic_id,
                receipt.expected_state_version,
                receipt.committed_state_version,
                receipt.occurrence_ids,
                receipt.member_integrity_digest,
                receipt.nested_publication_tokens,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _action_cohort_receipt_shape_is_valid(
        receipt: ActionCohortPublicationReceipt,
    ) -> bool:
        """Reject hostile receipt fields before equality, repr, or HMAC work."""

        return bool(
            type(receipt.dispatcher_id) is str
            and type(receipt.receipt_id) is str
            and type(receipt.publication_token) is str
            and type(receipt.root_action_id) is str
            and type(receipt.state_semantic_id) is str
            and type(receipt.expected_state_version) is int
            and type(receipt.committed_state_version) is int
            and type(receipt.occurrence_ids) is tuple
            and all(type(value) is str for value in receipt.occurrence_ids)
            and type(receipt.member_integrity_digest) is str
            and type(receipt.nested_publication_tokens) is tuple
            and all(
                type(item) is tuple
                and len(item) == 2
                and type(item[0]) is str
                and type(item[1]) is str
                for item in receipt.nested_publication_tokens
            )
            and type(receipt._integrity) is str
            and type(receipt._published) is bool
        )

    def _state_neutral_projection_receipt_integrity(
        self,
        receipt: StateNeutralProjectionPublicationReceipt,
    ) -> str:
        """Authenticate one honest non-State receipt through a distinct HMAC domain."""

        payload = repr(
            (
                "state-neutral-projection-publication-receipt-v1",
                id(receipt),
                receipt.dispatcher_id,
                receipt.receipt_id,
                receipt.publication_token,
                receipt.occurrence_ids,
                receipt.member_integrity_digest,
                receipt.timing_preparation_id,
                receipt.timing_overlay_digest,
                receipt.timing_publication_token,
                receipt.intent_publication_token,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _state_neutral_projection_receipt_shape_is_valid(
        receipt: StateNeutralProjectionPublicationReceipt,
    ) -> bool:
        """Reject hostile non-State receipt fields before HMAC or registry work."""

        return bool(
            type(receipt.dispatcher_id) is str
            and type(receipt.receipt_id) is str
            and type(receipt.publication_token) is str
            and type(receipt.occurrence_ids) is tuple
            and len(receipt.occurrence_ids) == 1
            and all(type(value) is str and value for value in receipt.occurrence_ids)
            and type(receipt.member_integrity_digest) is str
            and type(receipt.timing_preparation_id) is int
            and receipt.timing_preparation_id > 0
            and type(receipt.timing_overlay_digest) is str
            and type(receipt.timing_publication_token) is str
            and type(receipt.intent_publication_token) is str
            and type(receipt._integrity) is str
            and type(receipt._published) is bool
        )

    @staticmethod
    def _validate_exact_projection_identifiers(result: object) -> tuple[tuple[str, str], ...]:
        """Accept only the frozen bounded identifier shape rendered during preflight."""

        if type(result) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            for item in result
        ):
            raise EventContractError("Exact projection returned malformed identifiers")
        return cast(tuple[tuple[str, str], ...], result)

    def _action_cohort_expected_publications_authenticate(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> bool:
        """Authenticate every exact claim-local result before any primitive commit."""

        from evidenceforge.generation.actions.command_effects import (
            ExecutionEffectAuditCommitReceipt,
        )
        from evidenceforge.generation.deployment_registry import (
            LocalArtifactPublicationGroupReceipt,
        )
        from evidenceforge.generation.intent_ledger import IntentExecutionBatchReceipt
        from evidenceforge.generation.lifecycle_registry import LifecycleActionCohortReceipt
        from evidenceforge.generation.source_timing import SourceTimingPreparationReceipt
        from evidenceforge.generation.state_manager import ActionCohortMaterializationResult

        state_claimed = record.state_claimed
        lifecycle_claimed = record.lifecycle_claimed
        audit_claimed = record.audit_claimed
        timing_claimed = record.timing_claimed
        state_result = record.expected_state_result
        lifecycle_receipt = record.expected_lifecycle_receipt
        audit_receipt = record.expected_audit_receipt
        timing_receipt = record.expected_timing_receipt
        if (
            state_claimed is None
            or lifecycle_claimed is None
            or audit_claimed is None
            or timing_claimed is not record.source_timing_preparation
            or type(state_result) is not ActionCohortMaterializationResult
            or type(lifecycle_receipt) is not LifecycleActionCohortReceipt
            or type(audit_receipt) is not ExecutionEffectAuditCommitReceipt
            or type(timing_receipt) is not SourceTimingPreparationReceipt
        ):
            return False
        try:
            if (
                state_claimed.expected_result is not state_result
                or type(record.expected_state_result_publication_token) is not str
                or not record.expected_state_result_publication_token
                or state_claimed.expected_result_publication_token
                is not record.expected_state_result_publication_token
                or not self.state_manager.authenticates_expected_action_cohort_result(
                    state_result,
                    preparation=state_claimed,
                )
                or lifecycle_claimed.expected_receipt is not lifecycle_receipt
                or not cast(
                    "GeneratorLifecycleAuthority", self._lifecycle_authority
                ).registry.authenticates_expected_action_cohort_receipt(
                    lifecycle_receipt,
                    state_publication_token=record.state_plan.publication_token,
                )
                or audit_claimed.expected_receipt is not audit_receipt
                or not record.execution_effect_audit.authenticates_expected_action_cohort_receipt(
                    audit_receipt,
                    preparation=audit_claimed,
                )
                or timing_claimed.expected_receipt is not timing_receipt
                or not self.source_timing_planner.authenticates_expected_preparation_receipt(
                    timing_receipt,
                    preparation=timing_claimed,
                )
            ):
                return False
            if record.intent_claimed is None:
                if record.expected_intent_receipt is not None:
                    return False
            else:
                intent_receipt = record.expected_intent_receipt
                if (
                    type(intent_receipt) is not IntentExecutionBatchReceipt
                    or record.intent_ledger is None
                    or record.intent_request is None
                    or record.intent_claimed.expected_receipt is not intent_receipt
                    or not record.intent_ledger.authenticates_expected_batch_receipt(
                        intent_receipt,
                        preparation=record.intent_claimed,
                    )
                ):
                    return False
            if record.artifact_publications:
                artifact_receipt = record.expected_artifact_receipt
                if (
                    record.artifact_claimed is None
                    or record.artifact_registry is None
                    or type(artifact_receipt) is not LocalArtifactPublicationGroupReceipt
                    or record.artifact_claimed.expected_receipt is not artifact_receipt
                    or not record.artifact_registry.authenticates_publication_group_receipt(
                        artifact_receipt,
                        publication_tokens=tuple(
                            token.publication_token for token in record.artifact_publications
                        ),
                    )
                ):
                    return False
            elif (
                record.artifact_claimed is not None or record.expected_artifact_receipt is not None
            ):
                return False
            receipt = record.publication_receipt
            result = record.publication_result
            outcomes = record.projection_outcomes
            recovery = record.exact_recovery
            recovery_valid = (
                recovery is not None
                and recovery.kind == "action_cohort"
                and recovery.receipt is receipt
                and recovery.result is result
                and recovery.batch is record.exact_publication_batch
                and len(outcomes) == 1
                and recovery.outcome is outcomes[0]
                and recovery.occurrence_ids == record.member_occurrence_ids
                and hmac.compare_digest(
                    recovery.member_integrity_digest,
                    record.member_integrity_digest,
                )
                and recovery.identifiers == record.exact_prepared_identifiers
                and recovery.state == "reserved"
                and recovery.active_thread_id is None
                if record.exact_projection
                else recovery is None
            )
            return bool(
                type(receipt) is ActionCohortPublicationReceipt
                and not receipt._published
                and self._action_cohort_receipt_shape_is_valid(receipt)
                and hmac.compare_digest(
                    receipt._integrity,
                    self._action_cohort_receipt_integrity(receipt),
                )
                and type(result) is ActionCohortPublicationResult
                and result.receipt is receipt
                and result.state is state_result
                and result.lifecycle is lifecycle_receipt
                and result.audit is audit_receipt
                and result.artifacts is record.expected_artifact_receipt
                and result.intent is record.expected_intent_receipt
                and result.timing is timing_receipt
                and result.projections is outcomes
                and type(outcomes) is tuple
                and len(outcomes) == len(record.dispatches)
                and recovery_valid
                and all(
                    type(outcome) is ActionCohortProjectionOutcome
                    and type(outcome._occurrence_id) is str
                    and outcome._occurrence_id == occurrence_id
                    and outcome._status == "pending"
                    and outcome._identifiers == ()
                    and outcome._error is None
                    for outcome, occurrence_id in zip(
                        outcomes,
                        record.member_occurrence_ids,
                        strict=True,
                    )
                )
            )
        except BaseException:
            return False

    def _prepare_action_cohort_publication_objects(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Allocate and authenticate every nested and outer result before yielding."""

        state_claimed = cast("PreparedActionCohortMaterialization", record.state_claimed)
        lifecycle_claimed = cast("PreparedLifecycleActionCohort", record.lifecycle_claimed)
        audit_claimed = cast("PreparedExecutionEffectAuditCommit", record.audit_claimed)
        timing_claimed = cast("SourceTimingPreparation", record.timing_claimed)
        record.expected_state_result = state_claimed.expected_result
        record.expected_state_result_publication_token = (
            state_claimed.expected_result_publication_token
        )
        record.expected_lifecycle_receipt = lifecycle_claimed.expected_receipt
        record.expected_audit_receipt = audit_claimed.expected_receipt
        record.expected_artifact_receipt = (
            record.artifact_claimed.expected_receipt
            if record.artifact_claimed is not None
            else None
        )
        record.expected_intent_receipt = (
            record.intent_claimed.expected_receipt if record.intent_claimed is not None else None
        )
        record.expected_timing_receipt = timing_claimed.expected_receipt

        state_result = record.expected_state_result
        lifecycle_receipt = record.expected_lifecycle_receipt
        audit_receipt = record.expected_audit_receipt
        timing_receipt = record.expected_timing_receipt
        if (
            state_result is None
            or lifecycle_receipt is None
            or audit_receipt is None
            or timing_receipt is None
        ):
            raise EventContractError("Action-cohort owner claim omitted an expected publication")
        nested_publication_tokens = (
            ("lifecycle", lifecycle_receipt.publication_token),
            ("state_plan", record.state_plan.publication_token),
            ("state_result", record.expected_state_result_publication_token),
            ("audit", audit_receipt.publication_token),
            (
                "artifacts",
                (
                    record.expected_artifact_receipt.group_token
                    if record.expected_artifact_receipt is not None
                    else ""
                ),
            ),
            (
                "intent",
                (
                    record.expected_intent_receipt.publication_token
                    if record.expected_intent_receipt is not None
                    else ""
                ),
            ),
            ("timing", timing_receipt._integrity),
        )
        receipt = ActionCohortPublicationReceipt(
            dispatcher_id=self._action_cohort_dispatcher_id,
            receipt_id=secrets.token_hex(16),
            publication_token=secrets.token_hex(32),
            root_action_id=record.root_action_id,
            state_semantic_id=state_result.semantic_id,
            expected_state_version=record.state_plan.expected_version,
            committed_state_version=state_result.committed_version,
            occurrence_ids=record.member_occurrence_ids,
            member_integrity_digest=record.member_integrity_digest,
            nested_publication_tokens=nested_publication_tokens,
        )
        object.__setattr__(receipt, "_integrity", self._action_cohort_receipt_integrity(receipt))
        outcomes = tuple(
            ActionCohortProjectionOutcome(occurrence_id)
            for occurrence_id in record.member_occurrence_ids
        )
        result = ActionCohortPublicationResult(
            receipt=receipt,
            state=state_result,
            lifecycle=lifecycle_receipt,
            audit=audit_receipt,
            artifacts=record.expected_artifact_receipt,
            intent=record.expected_intent_receipt,
            timing=timing_receipt,
            projections=outcomes,
        )
        record.publication_receipt = receipt
        record.projection_outcomes = outcomes
        record.publication_result = result
        if record.exact_projection:
            exact_batch = record.exact_publication_batch
            if exact_batch is None or len(outcomes) != 1:
                raise EventContractError("Exact action-cohort recovery preallocation is malformed")
            record.exact_recovery = _ExactProjectionRecoveryRecord(
                kind="action_cohort",
                receipt=receipt,
                result=result,
                batch=exact_batch,
                outcome=outcomes[0],
                occurrence_ids=record.member_occurrence_ids,
                member_integrity_digest=record.member_integrity_digest,
                identifiers=record.exact_prepared_identifiers,
                owner_record=record,
            )
        if not self._action_cohort_expected_publications_authenticate(record):
            raise EventContractError(
                "Action-cohort expected owner publications failed preallocation authentication"
            )

    def _certify_action_cohort_owner_commits(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Cross every owner's one-shot final-auth boundary before primitive mutation."""

        cast("PreparedActionCohortMaterialization", record.state_claimed).certify_composite_commit(
            cast("ActionCohortMaterializationResult", record.expected_state_result)
        )
        cast("PreparedLifecycleActionCohort", record.lifecycle_claimed).certify_composite_commit(
            cast("LifecycleActionCohortReceipt", record.expected_lifecycle_receipt)
        )
        cast("PreparedExecutionEffectAuditCommit", record.audit_claimed).certify_composite_commit(
            cast("ExecutionEffectAuditCommitReceipt", record.expected_audit_receipt)
        )
        if record.intent_claimed is not None:
            record.intent_claimed.certify_composite_commit(
                cast("IntentExecutionBatchReceipt", record.expected_intent_receipt)
            )
        cast("SourceTimingPreparation", record.timing_claimed).certify_composite_commit(
            cast("SourceTimingPreparationReceipt", record.expected_timing_receipt)
        )

    @staticmethod
    def _copy_observation_summary(summary: ObservationSummary) -> ObservationSummary:
        """Copy one fixed-shape summary without retaining caller-owned containers."""

        return ObservationSummary(
            visible=summary.visible,
            delayed=summary.delayed,
            dropped=summary.dropped,
            filtered=summary.filtered,
            out_of_window=summary.out_of_window,
        )

    @contextmanager
    def _claimed_action_cohort_observations(
        self,
        record: _PreparedActionCohortBatchRecord | _StateNeutralProjectionPublicationRecord,
    ) -> Iterator[None]:
        """Precompute affected-only summary replacements while fencing other updates."""

        self._source_evidence_lock.acquire()
        try:
            affected: dict[str, dict[str, ObservationSummary]] = {}
            canonical_clusters: dict[str, dict[str, ObservationSummary] | None] = {}
            for delta in record.observation_deltas:
                cluster = affected.get(delta.cluster_id)
                if cluster is None:
                    cluster = {}
                    affected[delta.cluster_id] = cluster
                    canonical_clusters[delta.cluster_id] = self._source_evidence_status.get(
                        delta.cluster_id
                    )
                summary = cluster.get(delta.source)
                if summary is None:
                    canonical_cluster = canonical_clusters[delta.cluster_id]
                    prior = (
                        canonical_cluster.get(delta.source)
                        if canonical_cluster is not None
                        else None
                    )
                    summary = (
                        ObservationSummary()
                        if prior is None
                        else self._copy_observation_summary(prior)
                    )
                    cluster[delta.source] = summary
                summary.record(delta.status)
            record.prepared_observation_updates = tuple(
                _ActionCohortPreparedObservationCluster(
                    cluster_id=cluster_id,
                    canonical_cluster=canonical_clusters[cluster_id],
                    new_cluster=(cluster if canonical_clusters[cluster_id] is None else None),
                    source_updates=(
                        () if canonical_clusters[cluster_id] is None else tuple(cluster.items())
                    ),
                )
                for cluster_id, cluster in affected.items()
            )
            try:
                yield
            except BaseException:
                record.prepared_observation_updates = None
                raise
            else:
                if not record.observation_committed:
                    record.prepared_observation_updates = None
                    raise EventContractError(
                        "Claimed action-cohort observation delta exited without commit"
                    )
        finally:
            self._source_evidence_lock.release()

    def _commit_action_cohort_observations_no_fail(
        self,
        record: _PreparedActionCohortBatchRecord | _StateNeutralProjectionPublicationRecord,
    ) -> None:
        """Install only preallocated affected summaries after canonical owner commit."""

        updates = cast(
            tuple[_ActionCohortPreparedObservationCluster, ...],
            record.prepared_observation_updates,
        )
        for update in updates:
            if update.new_cluster is not None:
                self._source_evidence_status[update.cluster_id] = update.new_cluster
                continue
            cluster = cast(dict[str, ObservationSummary], update.canonical_cluster)
            for source, summary in update.source_updates:
                cluster[source] = summary
        self._source_evidence_version += 1
        record.observation_committed = True

    def _exact_projection_targets(
        self,
        projection: _PreparedProjection,
    ) -> tuple[tuple[str, LogEmitter], ...]:
        """Return only targets whose emit callbacks will run during exact rendering."""

        if projection.mode == "suppressed":
            return ()
        if projection.mode == "legacy":
            return tuple(
                (target.format_name, target.emitter)
                for target in projection.legacy_targets
                if target.occurrence is not None
            )
        if projection.mode != "compiled":
            raise EventContractError("Exact projection mode is unsupported")
        return tuple(
            (target.format_name, target.emitter)
            for target in projection.compiled_targets
            if self._action_cohort_compiled_projection_status(
                projection.occurrence,
                target,
            )
            in {"visible", "delayed"}
        )

    @staticmethod
    def _require_exact_projection_target(
        format_name: str,
        emitter: LogEmitter,
    ) -> None:
        """Fail closed before rendering unless the concrete sink has exact admission."""

        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
        from evidenceforge.generation.emitters.windows import WindowsEventEmitter

        if format_name == "ecar" and type(emitter) is EcarEmitter:
            return
        if (
            format_name == "windows_event_security"
            and type(emitter) is WindowsEventEmitter
            and getattr(emitter, "supports_exact_candidate_publication", None) is True
        ):
            return
        if (
            format_name == "windows_event_sysmon"
            and type(emitter) is SysmonEventEmitter
            and getattr(emitter, "supports_exact_projection_publication", None) is True
        ):
            return
        raise EventContractError(
            f"Exact projection target {format_name!r} is unsupported before rendering"
        )

    def _exact_projection_participants(
        self,
        projection: _PreparedProjection,
    ) -> tuple[LogEmitter, ...]:
        """Authenticate and deduplicate exact-capable emitter participants."""

        participants: list[LogEmitter] = []
        participant_ids: set[int] = set()
        for format_name, emitter in self._exact_projection_targets(projection):
            self._require_exact_projection_target(format_name, emitter)
            if id(emitter) in participant_ids:
                continue
            participant_ids.add(id(emitter))
            participants.append(emitter)
        return tuple(participants)

    @staticmethod
    def _require_type_five_projection(projection: _PreparedProjection) -> None:
        """Require the narrow single-occurrence semantic family authorized for exact mode."""

        event = projection.occurrence
        auth = event.auth
        if (
            event.event_type is not EventKind.LOGON
            or auth is None
            or type(auth.logon_type) is not int
            or auth.logon_type != 5
            or auth.result != "success"
        ):
            raise EventContractError("Exact projection is limited to successful Type-5 logons")

    @staticmethod
    def _require_ssh_terminal_projection(
        record: _PreparedActionCohortBatchRecord,
    ) -> str:
        """Authenticate one narrow SSH terminal State/event cohort.

        SSH terminal exact mode is deliberately limited to one client-process
        termination or one target SSH-session logout.  It cannot be used as a
        generic exact action-cohort escape hatch.
        """

        from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext
        from evidenceforge.events.identity import (
            EventIdentityPlan,
            ProcessIdentity,
            SessionIdentity,
        )
        from evidenceforge.events.lifecycle import ActionLifecycleContext

        if len(record.trusted_projections) != 1 or len(record.dispatches) != 1:
            raise EventContractError("Exact SSH terminal projection requires one member")
        projection = record.trusted_projections[0]
        event = projection.occurrence
        plan = record.state_plan
        identity_plan = event.identity_plan
        lifecycle = event.lifecycle
        empty_common_state = not any(
            (
                plan.sessions,
                plan.processes,
                plan.live_session_process_role_patches,
                plan.session_metadata_patches,
                plan.process_activity_patches,
            )
        )
        if (
            not record.root_action_id.startswith("ssh-close:")
            or not empty_common_state
            or plan._smb_connection_finalization is not None
            or plan._smb_file_mutation_terminalization is not None
            or type(identity_plan) is not EventIdentityPlan
            or type(lifecycle) is not ActionLifecycleContext
            or lifecycle.phase != "closure"
        ):
            raise EventContractError("Exact SSH terminal projection changed its closed owner")

        if event.event_type is EventKind.PROCESS_TERMINATE:
            source_terminal = record.root_action_id.endswith(":source-terminate")
            receiver_terminal = record.root_action_id.endswith(":receiver-terminate")
            if (
                not (source_terminal or receiver_terminal)
                or len(plan.process_terminations) != 1
                or plan.session_terminalizations
                or type(identity_plan.subject) is not ProcessIdentity
                or identity_plan.actor is not None
                or identity_plan.target is not None
                or len(plan.session_activity_patches) > 1
                or type(event.src_host) is not HostContext
                or event.dst_host is not None
                or type(event.process) is not ProcessContext
                or type(event.auth) is not AuthContext
            ):
                raise EventContractError(
                    "Exact SSH source termination changed its singleton State/event shape"
                )
            identity = identity_plan.subject
            termination = plan.process_terminations[0]
            session_patch_identity = (
                EventDispatcher._action_cohort_target_identity(
                    plan.session_activity_patches[0].target
                )
                if plan.session_activity_patches
                else None
            )
            executable = identity.image.casefold().replace("\\", "/").rsplit("/", 1)[-1]
            if (
                termination.identity != identity
                or termination.end_time != event.timestamp
                or ((identity_plan.session is None) is not (session_patch_identity is None))
                or (
                    identity_plan.session is not None
                    and identity_plan.session != session_patch_identity
                )
                or (
                    plan.session_activity_patches
                    and plan.session_activity_patches[0].activity_time != event.timestamp
                )
                or (
                    source_terminal
                    and executable not in {"ssh", "ssh.exe", "scp", "scp.exe", "sftp", "sftp.exe"}
                )
                or (receiver_terminal and executable != "sshd")
                or (receiver_terminal and identity.principal.casefold() != "root")
                or event.src_host.hostname != identity.hostname
                or event.process.pid != identity.pid
                or event.process.parent_pid not in {0, identity.parent_pid}
                or event.process.image != identity.image
                or event.process.username != identity.principal
                or event.process.logon_id != identity.logon_id
                or event.process.start_time != identity.started_at
                or event.auth.username != identity.principal
                or event.auth.logon_id != identity.logon_id
                or lifecycle.group_id != identity.lifecycle_group_id
                or lifecycle.canonical_start != identity.started_at
                or lifecycle.parent_group_id != (identity.parent_lifecycle_group_id or None)
            ):
                raise EventContractError(
                    "Exact SSH source termination disagrees with its live process identity"
                )
            return "ssh_process_terminate"

        if event.event_type is EventKind.LOGOFF:
            if (
                not record.root_action_id.endswith(":logout")
                or plan.process_terminations
                or len(plan.session_terminalizations) != 1
                or plan.session_activity_patches
                or type(identity_plan.subject) is not SessionIdentity
                or identity_plan.actor is not None
                or identity_plan.target is not None
                or identity_plan.session != identity_plan.subject
                or event.src_host is not None
                or type(event.dst_host) is not HostContext
                or event.dst_host.os_category != "linux"
                or type(event.auth) is not AuthContext
                or event.syslog is None
                or event.syslog.app_name != "sshd"
            ):
                raise EventContractError("Exact SSH logout changed its singleton State/event shape")
            identity = identity_plan.subject
            terminalization = plan.session_terminalizations[0]
            if (
                identity.session_kind != "ssh"
                or terminalization.identity != identity
                or terminalization.end_time != event.timestamp
                or event.dst_host.hostname != identity.hostname
                or event.auth.username != identity.principal
                or event.auth.logon_id != identity.logon_id
                or event.auth.session_id != identity.session_id
                or event.auth.logon_type != 10
                or event.auth.source_ip in {"", "-"}
                or type(event.auth.source_port) is not int
                or not 1 <= event.auth.source_port <= 65_535
                or lifecycle.group_id != identity.lifecycle_group_id
                or lifecycle.canonical_start != identity.started_at
                or lifecycle.parent_group_id != (identity.parent_lifecycle_group_id or None)
            ):
                raise EventContractError(
                    "Exact SSH logout disagrees with its live session identity"
                )
            return "ssh_logout"

        raise EventContractError("Exact SSH terminal projection event kind is unsupported")

    def _exact_action_cohort_projection_kind(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> str:
        """Return the authenticated closed semantic kind for exact cohort projection."""

        projection = record.trusted_projections[0]
        try:
            self._require_type_five_projection(projection)
        except EventContractError:
            try:
                return self._require_ssh_terminal_projection(record)
            except EventContractError:
                return self._require_rdp_terminal_projection(record)
        return "type5"

    @staticmethod
    def _require_rdp_terminal_projection(
        record: _PreparedActionCohortBatchRecord,
    ) -> str:
        """Authenticate one narrow Windows RDP process/session terminal cohort."""

        from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext
        from evidenceforge.events.identity import (
            EventIdentityPlan,
            ProcessIdentity,
            SessionIdentity,
        )
        from evidenceforge.events.lifecycle import ActionLifecycleContext

        if len(record.trusted_projections) != 1 or len(record.dispatches) != 1:
            raise EventContractError("Exact RDP terminal projection requires one member")
        event = record.trusted_projections[0].occurrence
        plan = record.state_plan
        identity_plan = event.identity_plan
        lifecycle = event.lifecycle
        empty_common_state = not any(
            (
                plan.sessions,
                plan.processes,
                plan.live_session_process_role_patches,
                plan.session_metadata_patches,
                plan.process_activity_patches,
            )
        )
        if (
            not record.root_action_id.startswith("rdp-close:")
            or not empty_common_state
            or plan._smb_connection_finalization is not None
            or plan._smb_file_mutation_terminalization is not None
            or type(identity_plan) is not EventIdentityPlan
            or type(lifecycle) is not ActionLifecycleContext
            or lifecycle.phase != "closure"
        ):
            raise EventContractError("Exact RDP terminal projection changed its closed owner")

        if event.event_type is EventKind.PROCESS_TERMINATE:
            if (
                not record.root_action_id.endswith(":process-terminate")
                or len(plan.process_terminations) != 1
                or plan.session_terminalizations
                or len(plan.session_activity_patches) > 1
                or type(identity_plan.subject) is not ProcessIdentity
                or identity_plan.actor is not None
                or identity_plan.target is not None
                or (
                    identity_plan.session is not None
                    and type(identity_plan.session) is not SessionIdentity
                )
                or type(event.src_host) is not HostContext
                or event.src_host.os_category != "windows"
                or event.dst_host is not None
                or type(event.process) is not ProcessContext
                or type(event.auth) is not AuthContext
            ):
                raise EventContractError("Exact RDP process close changed its singleton shape")
            identity = identity_plan.subject
            termination = plan.process_terminations[0]
            executable = identity.image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
            if (
                executable not in {"mstsc.exe", "explorer.exe", "userinit.exe", "winlogon.exe"}
                or termination.identity != identity
                or termination.end_time != event.timestamp
                or event.src_host.hostname != identity.hostname
                or event.process.pid != identity.pid
                or event.process.image != identity.image
                or event.process.username != identity.principal
                or event.process.logon_id != identity.logon_id
                or event.process.start_time != identity.started_at
                or event.auth.username != identity.principal
                or event.auth.logon_id != identity.logon_id
                or (
                    identity_plan.session is not None
                    and (
                        identity_plan.session.hostname != identity.hostname
                        or identity_plan.session.logon_id != identity.logon_id
                    )
                )
                or lifecycle.group_id != identity.lifecycle_group_id
                or lifecycle.canonical_start != identity.started_at
                or lifecycle.parent_group_id != (identity.parent_lifecycle_group_id or None)
            ):
                raise EventContractError(
                    "Exact RDP process close disagrees with its live process identity"
                )
            return "rdp_process_terminate"

        if event.event_type is EventKind.LOGOFF:
            if (
                not record.root_action_id.endswith(":logout")
                or plan.process_terminations
                or len(plan.session_terminalizations) != 1
                or plan.session_activity_patches
                or type(identity_plan.subject) is not SessionIdentity
                or identity_plan.actor is not None
                or identity_plan.target is not None
                or identity_plan.session != identity_plan.subject
                or event.src_host is not None
                or type(event.dst_host) is not HostContext
                or event.dst_host.os_category != "windows"
                or type(event.auth) is not AuthContext
            ):
                raise EventContractError("Exact RDP logout changed its singleton shape")
            identity = identity_plan.subject
            terminalization = plan.session_terminalizations[0]
            if (
                identity.session_kind != "rdp"
                or terminalization.identity != identity
                or terminalization.end_time != event.timestamp
                or event.dst_host.hostname != identity.hostname
                or event.auth.username != identity.principal
                or event.auth.logon_id != identity.logon_id
                or event.auth.session_id != identity.session_id
                or event.auth.logon_type != 10
                or event.auth.source_ip in {"", "-"}
                or type(event.auth.source_port) is not int
                or not 1 <= event.auth.source_port <= 65_535
                or lifecycle.group_id != identity.lifecycle_group_id
                or lifecycle.canonical_start != identity.started_at
            ):
                raise EventContractError(
                    "Exact RDP logout disagrees with its live session identity"
                )
            return "rdp_logout"

        raise EventContractError("Exact RDP terminal projection event kind is unsupported")

    def _ssh_terminal_exact_projection_participants(
        self,
        projection: _PreparedProjection,
    ) -> tuple[LogEmitter, ...]:
        """Require eCAR, except for one exact zero-row warm-up terminal."""

        from evidenceforge.generation.emitters.ecar import EcarEmitter

        if self._projection_is_exact_warmup_suppressed(projection):
            return ()
        participants: list[LogEmitter] = []
        participant_ids: set[int] = set()
        for format_name, emitter in self._exact_projection_targets(projection):
            marker = type(emitter).__dict__.get("supports_exact_projection_publication")
            if (
                format_name != "ecar"
                or type(emitter) is not EcarEmitter
                or marker is None
                or getattr(emitter, "supports_exact_projection_publication", None) is not True
            ):
                raise EventContractError(
                    f"Exact SSH terminal target {format_name!r} is unsupported before State"
                )
            if id(emitter) not in participant_ids:
                participant_ids.add(id(emitter))
                participants.append(emitter)
        if len(participants) != 1:
            raise EventContractError("Exact SSH terminal projection requires one eCAR target")
        return tuple(participants)

    def _rdp_terminal_exact_projection_participants(
        self,
        projection: _PreparedProjection,
    ) -> tuple[LogEmitter, ...]:
        """Require an exact RDP sink, except for one authenticated warm-up zero-row shape."""

        if self._projection_is_exact_warmup_suppressed(projection):
            return ()
        participants = self._exact_projection_participants(projection)
        if not participants:
            raise EventContractError(
                "Exact visible RDP terminal projection requires a durable source target"
            )
        return participants

    def _initialize_action_cohort_exact_projection(
        self,
        record: _PreparedActionCohortBatchRecord,
        cleanup_record: _ActionCohortPreparationCleanupRecord,
    ) -> None:
        """Validate one closed State-backed member and issue its private exact batch."""

        if (
            not record.exact_projection
            or len(record.trusted_projections) != 1
            or len(record.dispatches) != 1
        ):
            raise EventContractError(
                "Exact action-cohort projection requires exactly one closed member"
            )
        projection = record.trusted_projections[0]
        exact_kind = self._exact_action_cohort_projection_kind(record)
        record.exact_projection_kind = exact_kind
        terminal_kind = exact_kind.startswith(("ssh_", "rdp_"))
        record.exact_all_suppressed = bool(
            terminal_kind and self._projection_is_exact_warmup_suppressed(projection)
        )
        if (
            record.artifact_publications
            or record.effect_member_bindings
            or record.external_effect_links
            or record.owned_effect_plans
            or record.published_provenances
        ):
            raise EventContractError(
                "Exact action-cohort projection cannot carry artifact or effect owners"
            )
        if exact_kind == "type5":
            if record.member_binary_identity_kinds != ("",):
                raise EventContractError("Exact Type-5 projection cannot carry binary owners")
            self._exact_projection_participants(projection)
        elif exact_kind.startswith("ssh_"):
            self._ssh_terminal_exact_projection_participants(projection)
        elif exact_kind.startswith("rdp_"):
            self._rdp_terminal_exact_projection_participants(projection)
        else:
            self._exact_projection_participants(projection)
        cleanup_record.exact_publication_batch = self._exact_publication_authority.issue_batch()
        record.exact_publication_batch = cleanup_record.exact_publication_batch

    def _prepare_action_cohort_exact_projection(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Freeze exact sink rows outside every dispatcher and member lock."""

        batch = record.exact_publication_batch
        if batch is None or len(record.trusted_projections) != 1:
            raise EventContractError("Exact action-cohort batch was not issued")
        projection = record.trusted_projections[0]
        exact_kind = self._exact_action_cohort_projection_kind(record)
        if exact_kind != record.exact_projection_kind:
            raise EventContractError("Exact action-cohort projection kind changed before rendering")
        terminal_kind = exact_kind.startswith(("ssh_", "rdp_"))
        exact_all_suppressed = bool(
            terminal_kind and self._projection_is_exact_warmup_suppressed(projection)
        )
        if exact_all_suppressed is not record.exact_all_suppressed:
            raise EventContractError("Exact terminal warm-up suppression changed before rendering")
        participants = (
            self._exact_projection_participants(projection)
            if exact_kind == "type5"
            else self._ssh_terminal_exact_projection_participants(projection)
            if exact_kind.startswith("ssh_")
            else self._rdp_terminal_exact_projection_participants(projection)
            if exact_kind.startswith("rdp_")
            else self._exact_projection_participants(projection)
        )
        batch.reserve_participants(cast(tuple[object, ...], participants))
        prepared_result = batch.prepare(
            lambda: tuple(sorted(self._publish_action_cohort_projection(projection).items()))
        )
        record.exact_prepared_identifiers = self._validate_exact_projection_identifiers(
            prepared_result
        )
        record.exact_prepared_row_count = batch.prepared_row_count
        if terminal_kind:
            prepared_row_count = record.exact_prepared_row_count
            if record.exact_all_suppressed:
                if prepared_row_count != 0 or record.exact_prepared_identifiers != ():
                    raise EventContractError(
                        "Exact warm-up terminal projection changed its zero-row shape"
                    )
            elif prepared_row_count <= 0:
                raise EventContractError("Exact visible terminal projection staged no durable row")

    @staticmethod
    def _require_state_neutral_type_five_projection(
        record: _PreparedActionCohortProjectionRecord,
    ) -> str:
        """Return the narrow authenticated no-State authentication/transition kind."""

        from evidenceforge.events.contexts import AuthContext, HostContext
        from evidenceforge.events.identity import (
            EntityIdentity,
            EventIdentityPlan,
            SessionIdentity,
        )
        from evidenceforge.events.lifecycle import ActionLifecycleContext

        event = record.occurrence
        auth = event.auth
        host = event.dst_host
        identity_plan = event.identity_plan
        lifecycle = event.lifecycle
        seal_occurrence = event.contract_seal.occurrence
        if event.event_type is EventKind.RDP_DISCONNECT:
            identity = identity_plan.subject if type(identity_plan) is EventIdentityPlan else None
            if (
                type(auth) is not AuthContext
                or type(host) is not HostContext
                or host.os_category != "windows"
                or type(identity_plan) is not EventIdentityPlan
                or type(identity) is not SessionIdentity
                or identity_plan.session != identity
                or identity_plan.actor is not None
                or identity_plan.target is not None
                or identity.session_kind != "rdp"
                or type(lifecycle) is not ActionLifecycleContext
                or lifecycle.phase != "dependent"
                or lifecycle.group_id != identity.lifecycle_group_id
                or lifecycle.canonical_start != identity.started_at
                or lifecycle.parent_group_id != (identity.parent_lifecycle_group_id or None)
                or seal_occurrence is None
                or record.binary_identity_kind != ""
                or event.src_host is not None
                or host.hostname != identity.hostname
                or auth.username != identity.principal
                or auth.logon_id != identity.logon_id
                or auth.session_id != identity.session_id
                or auth.logon_type != 10
                or auth.source_ip in {"", "-"}
                or type(auth.source_port) is not int
                or not 1 <= auth.source_port <= 65_535
            ):
                raise EventContractError(
                    "State-neutral exact RDP disconnect disagrees with its live session"
                )
            return "rdp_disconnect"
        EventDispatcher._require_type_five_projection(record.projection)
        expected_accounts = {
            "SYSTEM": ("S-1-5-18", "0x3e7"),
            "LOCAL SERVICE": ("S-1-5-19", "0x3e5"),
            "NETWORK SERVICE": ("S-1-5-20", "0x3e4"),
        }
        if (
            type(auth) is not AuthContext
            or type(host) is not HostContext
            or host.os_category != "windows"
            or type(identity_plan) is not EventIdentityPlan
            or type(identity_plan.subject) is not EntityIdentity
            or identity_plan.subject.kind != "authentication_occurrence"
            or not identity_plan.subject.semantic_key
            or identity_plan.subject.hostname != host.hostname
            or identity_plan.actor is not None
            or identity_plan.target is not None
            or identity_plan.session is not None
            or type(lifecycle) is not ActionLifecycleContext
            or lifecycle.phase != "start"
            or lifecycle.canonical_start != event.timestamp
            or lifecycle.parent_group_id is not None
            or seal_occurrence is None
            or seal_occurrence.present_contexts
            != frozenset({ContextKind.AUTH, ContextKind.DST_HOST, ContextKind.LIFECYCLE})
            or record.binary_identity_kind != ""
        ):
            raise EventContractError(
                "State-neutral exact projection requires one built-in authentication occurrence"
            )
        expected = expected_accounts.get(auth.username)
        if (
            expected is None
            or (auth.user_sid, auth.logon_id) != expected
            or auth.source_ip != "-"
            or auth.source_port != 0
            or auth.subject_sid != "S-1-5-18"
            or auth.subject_username != "SYSTEM"
            or auth.subject_domain != "NT AUTHORITY"
            or auth.subject_logon_id != "0x3e7"
            or auth.logon_process != "Advapi"
            or auth.auth_package != "Negotiate"
            or auth.lm_package != "-"
        ):
            raise EventContractError(
                "State-neutral exact projection built-in account/SID/LUID tuple is invalid"
            )
        return "type5"

    def _state_neutral_intent_request(
        self,
        record: _PreparedActionCohortProjectionRecord,
        observation_deltas: tuple[_ActionCohortObservationDelta, ...],
    ) -> IntentExecutionBatchRequest | None:
        """Build the same occurrence/observation intent delta as ordinary dispatch."""

        authored_intent_id = record.authored_intent_id
        if authored_intent_id is None:
            return None
        from evidenceforge.generation.intent_ledger import (
            IntentExecutionBatchRequest,
            IntentObservationDelta,
            IntentOccurrenceDelta,
        )

        occurrence_key = record.occurrence.occurrence_key
        if type(occurrence_key) is not SemanticOccurrenceKey:
            raise EventContractError("State-neutral exact projection lost occurrence identity")
        deltas = [
            IntentOccurrenceDelta(
                authored_intent_id,
                occurrence_key,
                record.occurrence.timestamp,
            ),
            *(
                IntentObservationDelta(
                    authored_intent_id,
                    delta.source,
                    delta.status,
                    delta.timestamp,
                )
                for delta in observation_deltas
            ),
        ]
        return IntentExecutionBatchRequest(tuple(deltas))

    def _detach_state_neutral_projection_locked(
        self,
        carrier: PreparedActionCohortProjection,
        record: _PreparedActionCohortProjectionRecord,
    ) -> None:
        """Consume one authenticated single-member timing group without cancelling timing."""

        group = self._action_cohort_projection_groups.get(id(record.source_timing_preparation))
        if (
            self._action_cohort_projections.get(record.preparation_id) is not record
            or record.carrier_ref() is not carrier
            or group != {record.preparation_id}
            or record.state != "publishing"
        ):
            raise EventContractError("State-neutral projection ownership changed before claim")
        self._action_cohort_projections.pop(record.preparation_id)
        self._action_cohort_projection_locators.pop(record.carrier_id, None)
        self._action_cohort_projection_groups.pop(id(record.source_timing_preparation), None)
        self._action_cohort_projection_retained_bytes -= record.retained_bytes
        record.state = "bound"
        carrier._consumed = True

    def _install_state_neutral_publication_locked(
        self,
        publication: _StateNeutralProjectionPublicationRecord,
        recovery: _ExactProjectionRecoveryRecord,
    ) -> None:
        """Install receipt and recovery before no-fail canonical ledger commits."""

        receipt = cast(
            StateNeutralProjectionPublicationReceipt,
            publication.publication_receipt,
        )
        if (
            len(self._exact_projection_recoveries) + self._exact_projection_recovery_reservations
            >= self._exact_projection_recovery_capacity
            or id(receipt) in self._exact_projection_recoveries
            or id(receipt) in self._state_neutral_projection_receipts
        ):
            raise EventContractError("State-neutral exact recovery capacity is exhausted")
        eviction_id: int | None = None
        if (
            self._state_neutral_projection_committed_receipts
            >= self._action_cohort_receipt_capacity
        ):
            eviction_id = next(
                (
                    receipt_id
                    for receipt_id, retained in self._state_neutral_projection_receipts.items()
                    if retained._published and receipt_id not in self._exact_projection_recoveries
                ),
                None,
            )
            if eviction_id is None:
                raise EventContractError(
                    "State-neutral receipt capacity has no resolved published eviction"
                )
        publication.receipt_eviction_id = eviction_id
        self._state_neutral_projection_receipts[id(receipt)] = receipt
        self._exact_projection_recoveries[id(receipt)] = recovery
        self._exact_projection_recovery_high_water = max(
            self._exact_projection_recovery_high_water,
            len(self._exact_projection_recoveries),
        )

    @staticmethod
    def _commit_exact_expected_owner(
        operation: Callable[[], object],
        *,
        expected: object,
        terminal_authenticates: Callable[[], bool],
        label: str,
    ) -> None:
        """Adopt only an exact terminal receipt after a canonical lost return."""

        try:
            returned = operation()
        except BaseException:
            try:
                adopted = terminal_authenticates()
            except BaseException:
                adopted = False
            if not adopted:
                raise
            return
        try:
            authentic = terminal_authenticates()
        except BaseException as exc:
            raise EventContractError(
                f"{label} terminal receipt authentication raised after commit"
            ) from exc
        if returned is not expected or not authentic:
            raise EventContractError(
                f"{label} returned a different or unauthenticated terminal receipt"
            )

    def publish_state_neutral_exact_projection(
        self,
        carrier: PreparedActionCohortProjection,
    ) -> StateNeutralProjectionPublicationResult:
        """Commit real non-State owners once, then publish one exact built-in Type-5 row set."""

        from evidenceforge.generation.intent_ledger import IntentExecutionBatchReceipt
        from evidenceforge.generation.source_timing import SourceTimingPreparationReceipt

        if type(carrier) is not PreparedActionCohortProjection:
            raise TypeError("State-neutral exact publication requires its exact carrier")
        timing_preparation: SourceTimingPreparation | None = None
        exact_batch: ExactPublicationBatch | None = None
        intent_ledger: IntentExecutionLedger | None = None
        intent_request: IntentExecutionBatchRequest | None = None
        intent_token: IntentExecutionBatchToken | None = None
        publication: _StateNeutralProjectionPublicationRecord | None = None
        recovery: _ExactProjectionRecoveryRecord | None = None
        detached = False
        canonical_committed = False
        try:
            with self._action_cohort_lock:
                record = self._active_action_cohort_projection_locked(carrier)
                timing_preparation = record.source_timing_preparation
                group = self._action_cohort_projection_groups.get(id(timing_preparation))
                if record.owner_thread_id != get_ident() or group != {record.preparation_id}:
                    raise EventContractError(
                        "State-neutral exact publication requires one same-thread timing member"
                    )
                record.state = "publishing"
            if not self._action_cohort_projection_record_authenticates(record):
                raise EventContractError("State-neutral projection failed nested authentication")
            if not self.source_timing_planner.authenticates_preparation(timing_preparation):
                raise EventContractError("State-neutral source timing is not sealed and authentic")
            exact_kind = self._require_state_neutral_type_five_projection(record)
            exact_all_suppressed = bool(
                exact_kind == "rdp_disconnect"
                and record.facts.disposition
                is ActionCohortProjectionDisposition.EXACT_WARMUP_SUPPRESSED
            )
            if exact_kind == "rdp_disconnect" and exact_all_suppressed != (
                self._projection_is_exact_warmup_suppressed(record.projection)
            ):
                raise EventContractError(
                    "State-neutral RDP disconnect disposition changed before rendering"
                )
            participants = (
                self._rdp_terminal_exact_projection_participants(record.projection)
                if exact_kind == "rdp_disconnect"
                else self._exact_projection_participants(record.projection)
            )
            exact_batch = self._exact_publication_authority.issue_batch()
            exact_batch.reserve_participants(cast(tuple[object, ...], participants))
            prepared_identifiers = self._validate_exact_projection_identifiers(
                exact_batch.prepare(
                    lambda: tuple(
                        sorted(self._publish_action_cohort_projection(record.projection).items())
                    )
                )
            )
            prepared_row_count = exact_batch.prepared_row_count
            if exact_kind == "rdp_disconnect":
                if exact_all_suppressed:
                    if prepared_row_count != 0 or prepared_identifiers != ():
                        raise EventContractError(
                            "Exact warm-up RDP disconnect changed its zero-row shape"
                        )
                elif prepared_row_count <= 0:
                    raise EventContractError("Exact visible RDP disconnect staged no durable row")
            observation_deltas = self._action_cohort_projection_observation_deltas(
                record.projection
            )
            intent_request = self._state_neutral_intent_request(record, observation_deltas)
            if intent_request is not None:
                intent_ledger = self.intent_execution_ledger
                if intent_ledger is None:
                    raise EventContractError(
                        "Attributed state-neutral projection requires the bound intent ledger"
                    )
                intent_token = intent_ledger.prepare_batch(intent_request)
            with self._action_cohort_lock:
                self._detach_state_neutral_projection_locked(carrier, record)
                detached = True

            member_integrity_digest = hashlib.sha256(
                repr(
                    (
                        record.occurrence_digest,
                        record.projection_digest,
                        record.facts_digest,
                        record.timing_digest,
                        exact_kind,
                        exact_all_suppressed,
                        prepared_row_count,
                    )
                ).encode("utf-8")
            ).hexdigest()
            outcome = ActionCohortProjectionOutcome(record.occurrence.occurrence_id)
            publication = _StateNeutralProjectionPublicationRecord(
                occurrence_id=record.occurrence.occurrence_id,
                member_integrity_digest=member_integrity_digest,
                source_timing_preparation=timing_preparation,
                authored_intent_id=record.authored_intent_id,
                intent_ledger=intent_ledger,
                intent_request=intent_request,
                intent_token=intent_token,
                observation_deltas=observation_deltas,
                exact_publication_batch=exact_batch,
                projection_outcome=outcome,
                exact_kind=exact_kind,
                exact_all_suppressed=exact_all_suppressed,
                prepared_row_count=prepared_row_count,
            )

            with ExitStack() as claims:
                timing_claimed = claims.enter_context(timing_preparation.claimed_commit())
                intent_claimed: PreparedIntentExecutionBatch | None = None
                if intent_ledger is not None and intent_token is not None:
                    intent_claimed = claims.enter_context(intent_ledger.claimed_batch(intent_token))
                timing_receipt = timing_claimed.expected_receipt
                if (
                    type(timing_receipt) is not SourceTimingPreparationReceipt
                    or not self.source_timing_planner.authenticates_expected_preparation_receipt(
                        timing_receipt,
                        preparation=timing_claimed,
                    )
                ):
                    raise EventContractError(
                        "State-neutral timing expected receipt failed authentication"
                    )
                intent_receipt = (
                    intent_claimed.expected_receipt if intent_claimed is not None else None
                )
                if intent_claimed is not None and (
                    type(intent_receipt) is not IntentExecutionBatchReceipt
                    or intent_ledger is None
                    or not intent_ledger.authenticates_expected_batch_receipt(
                        intent_receipt,
                        preparation=intent_claimed,
                    )
                ):
                    raise EventContractError(
                        "State-neutral intent expected receipt failed authentication"
                    )
                timing_claimed.certify_composite_commit(timing_receipt)
                if intent_claimed is not None:
                    intent_claimed.certify_composite_commit(
                        cast(IntentExecutionBatchReceipt, intent_receipt)
                    )

                receipt = StateNeutralProjectionPublicationReceipt(
                    dispatcher_id=self._action_cohort_dispatcher_id,
                    receipt_id=secrets.token_hex(16),
                    publication_token=secrets.token_hex(32),
                    occurrence_ids=(record.occurrence.occurrence_id,),
                    member_integrity_digest=member_integrity_digest,
                    timing_preparation_id=timing_receipt.binding_token.preparation_id,
                    timing_overlay_digest=timing_receipt.overlay_digest,
                    timing_publication_token=timing_receipt._integrity,
                    intent_publication_token=(
                        intent_receipt.publication_token if intent_receipt is not None else ""
                    ),
                )
                object.__setattr__(
                    receipt,
                    "_integrity",
                    self._state_neutral_projection_receipt_integrity(receipt),
                )
                result = StateNeutralProjectionPublicationResult(
                    receipt=receipt,
                    timing=timing_receipt,
                    intent=intent_receipt,
                    projection=outcome,
                )
                recovery = _ExactProjectionRecoveryRecord(
                    kind="state_neutral",
                    receipt=receipt,
                    result=result,
                    batch=exact_batch,
                    outcome=outcome,
                    occurrence_ids=receipt.occurrence_ids,
                    member_integrity_digest=member_integrity_digest,
                    identifiers=prepared_identifiers,
                    owner_record=publication,
                )
                publication.expected_timing_receipt = timing_receipt
                publication.expected_intent_receipt = intent_receipt
                publication.publication_receipt = receipt
                publication.publication_result = result
                if not self._state_neutral_projection_receipt_shape_is_valid(
                    receipt
                ) or not hmac.compare_digest(
                    receipt._integrity,
                    self._state_neutral_projection_receipt_integrity(receipt),
                ):
                    raise EventContractError("State-neutral receipt preallocation is malformed")

                with self._publication_ledger_lock:
                    with self._claimed_action_cohort_observations(publication):
                        with self._action_cohort_lock:
                            self._install_state_neutral_publication_locked(
                                publication,
                                recovery,
                            )
                        if intent_claimed is not None:
                            expected_intent_receipt = cast(
                                IntentExecutionBatchReceipt,
                                intent_receipt,
                            )
                            assert intent_ledger is not None
                            self._commit_exact_expected_owner(
                                intent_claimed.commit_no_fail,
                                expected=expected_intent_receipt,
                                terminal_authenticates=lambda: bool(
                                    intent_claimed.committed
                                    and intent_claimed.receipt is expected_intent_receipt
                                    and intent_ledger.authenticates_batch_receipt(
                                        expected_intent_receipt,
                                        request=intent_request,
                                    )
                                ),
                                label="State-neutral intent owner",
                            )
                        self._commit_exact_expected_owner(
                            timing_claimed.commit_no_fail,
                            expected=timing_receipt,
                            terminal_authenticates=lambda: bool(
                                timing_preparation.committed
                                and timing_preparation.receipt is timing_receipt
                                and self.source_timing_planner.authenticates_preparation_receipt(
                                    timing_receipt
                                )
                            ),
                            label="State-neutral source-timing owner",
                        )
                        try:
                            self._commit_action_cohort_observations_no_fail(publication)
                        except BaseException:
                            if not publication.observation_committed:
                                raise
                        if not publication.observation_committed:
                            raise EventContractError(
                                "State-neutral dispatcher observations did not commit"
                            )
                        object.__setattr__(receipt, "_published", True)
                        canonical_committed = True
                        with self._action_cohort_lock:
                            recovery.state = "ready"
                            if publication.receipt_eviction_id is not None:
                                evicted = self._state_neutral_projection_receipts.pop(
                                    publication.receipt_eviction_id,
                                    None,
                                )
                                if evicted is not None and evicted._published:
                                    self._state_neutral_projection_committed_receipts -= 1
                            self._state_neutral_projection_committed_receipts += 1

            return cast(
                StateNeutralProjectionPublicationResult,
                self._resume_exact_projection_recovery(
                    receipt,
                    expected_kind="state_neutral",
                ),
            )
        except BaseException as primary:
            if not canonical_committed:
                cleanup_failures: list[BaseException] = []
                if publication is not None and publication.publication_receipt is not None:
                    pending_receipt = publication.publication_receipt
                    with self._action_cohort_lock:
                        self._state_neutral_projection_receipts.pop(
                            id(pending_receipt),
                            None,
                        )
                        self._exact_projection_recoveries.pop(id(pending_receipt), None)
                if intent_ledger is not None and intent_token is not None:
                    try:
                        if intent_ledger.authenticates_batch_token(intent_token):
                            intent_ledger.cancel_batch(intent_token)
                    except BaseException as failure:
                        cleanup_failures.append(failure)
                if exact_batch is not None and exact_batch.state in {"issued", "ready"}:
                    try:
                        exact_batch.cancel()
                    except BaseException as failure:
                        if exact_batch.state != "canceled":
                            cleanup_failures.append(failure)
                if timing_preparation is not None and not timing_preparation.committed:
                    try:
                        if detached:
                            timing_preparation.cancel()
                        else:
                            self._cancel_action_cohort_projection_group(
                                timing_preparation,
                                allow_binding=True,
                            )
                    except BaseException as failure:
                        cleanup_failures.append(failure)
                self._add_action_cohort_cleanup_notes(primary, tuple(cleanup_failures))
            raise

    def prepare_action_cohort_batch(
        self,
        root_action_id: str,
        state_plan: ActionCohortMaterializationPlan,
        dispatches: tuple[PreparedDispatch, ...],
        audit_entries: tuple[ExecutionEffectAuditCohortEntry, ...],
        effect_member_bindings: tuple[ActionCohortEffectMemberBinding, ...],
        external_effect_links: tuple[ActionCohortExternalEffectLink, ...],
        *,
        owned_effect_plans: tuple[OwnedEffectOccurrencePlan, ...] = (),
        exact_projection: bool = False,
    ) -> PreparedActionCohortBatch:
        """Prepare one bounded all-owner action cohort without canonical mutation."""

        from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
        from evidenceforge.generation.actions.command_effects import (
            ExecutionEffectAuditCohortEntry,
            ExecutionEffectAuditCounter,
            ExecutionEffectPlan,
            ExecutionEffectReconciliation,
        )
        from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
        from evidenceforge.generation.intent_ledger import (
            IntentExecutionBatchRequest,
            IntentObservationDelta,
            IntentOccurrenceDelta,
        )
        from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan

        if type(exact_projection) is not bool:
            raise EventContractError("Action-cohort exact projection opt-in must be an exact bool")

        if type(root_action_id) is not str or not root_action_id.strip():
            raise EventContractError("Action-cohort batch requires a non-empty root action ID")
        if type(state_plan) is not ActionCohortMaterializationPlan:
            raise EventContractError("Action-cohort batch requires an exact State plan")
        if type(dispatches) is not tuple or not dispatches:
            raise EventContractError("Action-cohort batch requires an ordered dispatch tuple")
        if len(dispatches) > _MAX_ACTION_COHORT_DISPATCHES:
            raise EventContractError(
                "Action-cohort dispatch capacity exceeded: "
                f"{len(dispatches)} > {_MAX_ACTION_COHORT_DISPATCHES}"
            )
        if type(audit_entries) is not tuple:
            raise EventContractError("Action-cohort audit entries must be an exact tuple")
        if len(audit_entries) > _MAX_ACTION_COHORT_AUDIT_ENTRIES:
            raise EventContractError(
                "Action-cohort audit-entry capacity exceeded: "
                f"{len(audit_entries)} > {_MAX_ACTION_COHORT_AUDIT_ENTRIES}"
            )
        if any(type(entry) is not ExecutionEffectAuditCohortEntry for entry in audit_entries):
            raise EventContractError("Action-cohort audit entries must be an exact tuple")
        nested_effect_members = 0
        for entry in audit_entries:
            plan = entry.plan
            reconciliation = entry.reconciliation
            if (
                type(plan) is not ExecutionEffectPlan
                or type(reconciliation) is not ExecutionEffectReconciliation
            ):
                raise EventContractError(
                    "Action-cohort audit entries require exact immutable nested tuples"
                )
            reconciliation_id_tuples = (
                reconciliation.missing_node_ids,
                reconciliation.missing_required_node_ids,
                reconciliation.unexpected_node_ids,
                reconciliation.invalid_outcome_node_ids,
                reconciliation.policy_invalid_outcome_node_ids,
                reconciliation.cardinality_mismatch_node_ids,
                reconciliation.failed_outcome_node_ids,
                reconciliation.audited_occurrence_node_ids,
            )
            if (
                type(plan.nodes) is not tuple
                or type(plan._ordered_ids) is not tuple
                or type(reconciliation.outcomes) is not tuple
                or type(reconciliation.unplanned_failures) is not tuple
                or any(type(values) is not tuple for values in reconciliation_id_tuples)
            ):
                raise EventContractError(
                    "Action-cohort audit entries require exact immutable nested tuples"
                )
            nested_effect_members += (
                5
                + 3 * len(plan.nodes)
                + len(plan._ordered_ids)
                + len(reconciliation.outcomes)
                + len(reconciliation.unplanned_failures)
                + sum(len(values) for values in reconciliation_id_tuples)
            )
            if nested_effect_members > _MAX_ACTION_COHORT_NESTED_EFFECT_MEMBERS:
                raise EventContractError("Action-cohort nested effect-member capacity exceeded")
        if type(effect_member_bindings) is not tuple:
            raise EventContractError("Action-cohort effect-member bindings must be an exact tuple")
        if len(effect_member_bindings) > _MAX_ACTION_COHORT_EFFECT_MEMBER_BINDINGS or len(
            effect_member_bindings
        ) > len(dispatches):
            raise EventContractError("Action-cohort effect-member binding capacity exceeded")
        if any(
            type(binding) is not ActionCohortEffectMemberBinding
            for binding in effect_member_bindings
        ):
            raise EventContractError("Action-cohort effect-member bindings must be an exact tuple")
        if type(external_effect_links) is not tuple:
            raise EventContractError("Action-cohort external-effect links must be an exact tuple")
        if len(external_effect_links) > _MAX_ACTION_COHORT_EXTERNAL_EFFECT_LINKS:
            raise EventContractError("Action-cohort external-effect link capacity exceeded")
        if any(type(link) is not ActionCohortExternalEffectLink for link in external_effect_links):
            raise EventContractError("Action-cohort external-effect links must be an exact tuple")
        if type(owned_effect_plans) is not tuple:
            raise EventContractError("Action-cohort owned effect plans must be an exact tuple")
        if len(owned_effect_plans) > _MAX_ACTION_COHORT_OWNED_EFFECT_PLANS:
            raise EventContractError("Action-cohort owned effect-plan capacity exceeded")
        if any(type(plan) is not OwnedEffectOccurrencePlan for plan in owned_effect_plans):
            raise EventContractError("Action-cohort owned effect plans must be an exact tuple")
        owned_effect_occurrences = 0
        for plan in owned_effect_plans:
            if (
                type(plan.occurrence_count) is not int
                or plan.occurrence_count <= 0
                or plan.occurrence_count > _MAX_ACTION_COHORT_OWNED_EFFECT_OCCURRENCES
            ):
                raise EventContractError("Action-cohort owned effect occurrence capacity exceeded")
            owned_effect_occurrences += plan.occurrence_count
            if (
                owned_effect_occurrences > _MAX_ACTION_COHORT_OWNED_EFFECT_OCCURRENCES
                or owned_effect_occurrences > len(dispatches)
            ):
                raise EventContractError("Action-cohort owned effect occurrence capacity exceeded")
        if not self.state_manager.authenticates_action_cohort_plan(state_plan):
            raise EventContractError("Action-cohort State plan failed authentication")
        self.state_manager.validate_action_cohort_materialization(state_plan)

        authority = self._lifecycle_authority
        if authority is None:
            raise EventContractError("Action-cohort batch requires the bound lifecycle authority")
        execution_effect_audit = self._execution_effect_audit
        if (
            execution_effect_audit is None
            or type(execution_effect_audit) is not ExecutionEffectAuditCounter
        ):
            raise EventContractError(
                "Action-cohort batch requires the engine-owned execution-effect audit"
            )

        occurrence_ids: set[str] = set()
        artifact_publications: list[LocalArtifactPublishToken] = []
        artifact_publication_ids: set[int] = set()
        authored_intent_id = dispatches[0]._authored_intent_id
        timing_preparation = dispatches[0]._source_timing_preparation
        if timing_preparation is None:
            raise EventContractError("Action-cohort batch requires shared source timing")
        for prepared in dispatches:
            if type(prepared) is not PreparedDispatch:
                raise TypeError("Action-cohort batch contains a non-dispatch member")
            if type(prepared._artifact_publications) is not tuple or any(
                type(token) is not LocalArtifactPublishToken
                for token in prepared._artifact_publications
            ):
                raise EventContractError(
                    "Action-cohort artifact publications must be an exact typed tuple"
                )
            if (
                prepared._state_intent is not PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT
                or prepared._lifecycle_ticket is not state_plan
                or prepared._expected_state_version != state_plan.expected_version
                or prepared._source_timing_preparation is not timing_preparation
                or prepared._authored_intent_id != authored_intent_id
                or prepared._projection.mode == "deferred"
                or prepared._action_cohort_batch_id is not None
                or prepared._network_dependent_batch_id is not None
                or prepared._deferred_session_publication_batch_id is not None
                or prepared.occurrence_id in occurrence_ids
            ):
                raise EventContractError(
                    "Action-cohort member changed State plan, timing, intent, order, or ownership"
                )
            occurrence_ids.add(prepared.occurrence_id)
            for token in prepared._artifact_publications:
                if id(token) in artifact_publication_ids:
                    continue
                artifact_publication_ids.add(id(token))
                artifact_publications.append(token)
            self.validate_prepared(prepared)
            identity_plan = prepared._occurrence.identity_plan
            if identity_plan is None or not any(
                type(candidate) in {ProcessIdentity, SessionIdentity}
                for candidate in (
                    identity_plan.subject,
                    identity_plan.actor,
                    identity_plan.target,
                    identity_plan.session,
                )
            ):
                raise EventContractError(
                    "Action-cohort member has no exact process/session identity"
                )
        artifact_publication_tuple = tuple(artifact_publications)
        artifact_registry = self.local_artifact_registry
        if artifact_publication_tuple:
            if artifact_registry is None:
                raise EventContractError(
                    "Action-cohort artifacts require the engine-owned local artifact registry"
                )
            if any(
                not artifact_registry.authenticates_prepared_publication(token)
                for token in artifact_publication_tuple
            ):
                raise EventContractError(
                    "Action-cohort contains a stale or foreign artifact publication"
                )
        if not self.source_timing_planner.authenticates_preparation(timing_preparation):
            raise EventContractError("Action-cohort source timing is not sealed and authentic")
        with self._action_cohort_lock:
            if self._action_cohort_projection_groups.get(id(timing_preparation)):
                raise EventContractError(
                    "Action-cohort timing still owns unbound projection preflights"
                )
        self._validate_action_cohort_dispatch_coverage(state_plan, dispatches)

        published_provenances: list[EffectOccurrenceProvenance] = []
        for prepared in dispatches:
            event = prepared._occurrence
            provenance = event.effect_provenance
            if event.file is None and event.registry is None:
                if provenance is None:
                    continue
                if (
                    type(provenance) is not EffectOccurrenceProvenance
                    or provenance.disposition is not EffectOccurrenceDisposition.OWNED_ROOT
                    or provenance.owner is not EffectOccurrenceOwner.SMB_PROTOCOL_FILE_PHASE
                    or provenance.kind is not EffectOccurrenceKind.FILE
                ):
                    raise EventContractError(
                        "Context-free action-cohort provenance requires an owned SMB phase"
                    )
                published_provenances.append(provenance)
                continue
            if event.file is not None and event.registry is not None:
                raise EventContractError(
                    "Action-cohort endpoint effects require exactly one file or registry context"
                )
            if type(provenance) is not EffectOccurrenceProvenance:
                raise EventContractError(
                    "Action-cohort file/registry projection requires exact effect provenance"
                )
            expected_kind = (
                EffectOccurrenceKind.FILE
                if event.file is not None
                else EffectOccurrenceKind.REGISTRY
            )
            if provenance.kind is not expected_kind:
                raise EventContractError(
                    "Action-cohort endpoint effect provenance kind disagrees with its context"
                )
            published_provenances.append(provenance)
        published_provenance_tuple = tuple(published_provenances)
        self._validate_action_cohort_effect_member_bindings(
            root_action_id=root_action_id,
            state_plan=state_plan,
            dispatches=dispatches,
            audit_entries=audit_entries,
            bindings=effect_member_bindings,
            external_links=external_effect_links,
            owned_effect_plans=owned_effect_plans,
        )

        observation_deltas = tuple(
            delta
            for prepared in dispatches
            for delta in self._action_cohort_projection_observation_deltas(prepared._projection)
        )
        observation_digest = self._action_cohort_observation_digest(observation_deltas)

        intent_ledger = self.intent_execution_ledger
        intent_request: IntentExecutionBatchRequest | None = None
        if authored_intent_id is not None:
            if intent_ledger is None:
                raise EventContractError(
                    "Attributed action-cohort batch requires the bound intent ledger"
                )
            intent_deltas: list[IntentOccurrenceDelta | IntentObservationDelta] = []
            for prepared in dispatches:
                intent_deltas.append(
                    IntentOccurrenceDelta(
                        authored_intent_id,
                        cast(SemanticOccurrenceKey, prepared._occurrence.occurrence_key),
                        prepared._occurrence.timestamp,
                    )
                )
                intent_deltas.extend(
                    IntentObservationDelta(
                        authored_intent_id,
                        delta.source,
                        delta.status,
                        delta.timestamp,
                    )
                    for delta in self._action_cohort_projection_observation_deltas(
                        prepared._projection
                    )
                )
            intent_request = IntentExecutionBatchRequest(tuple(intent_deltas))

        lifecycle_request = authority.action_cohort_request(state_plan)
        retained_bytes = self._action_cohort_batch_retained_size(
            state_plan,
            dispatches,
            artifact_publication_tuple,
            lifecycle_request,
            audit_entries,
            effect_member_bindings,
            external_effect_links,
            owned_effect_plans,
            published_provenance_tuple,
            observation_deltas,
            intent_request,
        )
        with self._action_cohort_lock:
            if (
                len(self._action_cohort_batches)
                + len(self._action_cohort_prepare_cleanups)
                + len(self._action_cohort_projections)
                >= self._action_cohort_preparation_capacity
            ):
                raise EventContractError("Action-cohort batch preparation capacity is exhausted")
            if (
                self._action_cohort_retained_members
                + len(self._action_cohort_projections)
                + len(dispatches)
                > self._action_cohort_member_capacity
            ):
                raise EventContractError("Action-cohort aggregate member capacity is exhausted")
            if (
                self._action_cohort_retained_bytes
                + self._action_cohort_projection_retained_bytes
                + retained_bytes
                > self._action_cohort_byte_capacity
            ):
                raise EventContractError(
                    "Action-cohort aggregate retained-byte capacity is exhausted"
                )
            if type(self._action_cohort_prepare_cleanups) is not dict:
                raise EventContractError("Action-cohort cleanup registry is malformed")
            cleanup_id = self._next_action_cohort_cleanup_id
            self._next_action_cohort_cleanup_id += 1
            cleanup_record = _ActionCohortPreparationCleanupRecord(
                cleanup_id=cleanup_id,
                batch_id=None,
                root_action_id=root_action_id,
                dispatches=dispatches,
                source_timing_preparation=timing_preparation,
                lifecycle_authority=authority,
                lifecycle_request=lifecycle_request,
                lifecycle_token=None,
                execution_effect_audit=execution_effect_audit,
                artifact_registry=(artifact_registry if artifact_publication_tuple else None),
                artifact_publications=artifact_publication_tuple,
                audit_entries=audit_entries,
                owned_effect_plans=owned_effect_plans,
                published_provenances=published_provenance_tuple,
                audit_preparation=None,
                intent_ledger=(intent_ledger if intent_request is not None else None),
                intent_request=intent_request,
                intent_token=None,
                exact_publication_batch=None,
                retained_bytes=retained_bytes,
                member_locks=tuple(prepared._lock for prepared in dispatches),
                member_installed=[False] * len(dispatches),
                member_cleanup_complete=[False] * len(dispatches),
                artifact_cleanup_status=[False] * len(artifact_publication_tuple),
            )
            self._action_cohort_prepare_cleanups[cleanup_id] = cleanup_record
            self._action_cohort_retained_members += len(dispatches)
            self._action_cohort_retained_bytes += retained_bytes

        lifecycle_token: LifecycleActionCohortAdmissionToken | None = None
        audit_preparation: PreparedExecutionEffectAuditCommit | None = None
        intent_token: IntentExecutionBatchToken | None = None
        assigned_batch_id: int | None = None
        installed_record: _PreparedActionCohortBatchRecord | None = None
        carrier: PreparedActionCohortBatch | None = None
        try:
            lifecycle_token = authority.prepare_action_cohort(state_plan)
            cleanup_record.lifecycle_token = lifecycle_token
            if lifecycle_token.request != lifecycle_request:
                raise EventContractError(
                    "Action-cohort lifecycle authority returned a different request"
                )
            audit_preparation = execution_effect_audit.prepare_action_cohort(
                root_action_id,
                audit_entries,
                owned_plans=owned_effect_plans,
                published_provenances=published_provenance_tuple,
            )
            cleanup_record.audit_preparation = audit_preparation
            if intent_request is not None:
                assert intent_ledger is not None
                intent_token = intent_ledger.prepare_batch(intent_request)
                cleanup_record.intent_token = intent_token

            with ExitStack() as member_locks:
                for member_lock in sorted(cleanup_record.member_locks, key=id):
                    member_locks.enter_context(cast(AbstractContextManager[object], member_lock))
                for prepared in dispatches:
                    self.validate_prepared(prepared)
                    if (
                        type(prepared._consumed) is not bool
                        or prepared._consumed
                        or prepared._action_cohort_batch_id is not None
                        or prepared._network_dependent_batch_id is not None
                        or prepared._deferred_session_publication_batch_id is not None
                    ):
                        raise EventContractError(
                            "Action-cohort dispatch is already claimed or published"
                        )
                with self._action_cohort_lock:
                    assigned_batch_id = self._next_action_cohort_batch_id
                    self._next_action_cohort_batch_id += 1
                    cleanup_record.batch_id = assigned_batch_id
                for ordinal, prepared in enumerate(dispatches):
                    prepared._action_cohort_batch_id = assigned_batch_id
                    cleanup_record.member_installed[ordinal] = True
                    prepared._integrity_token = self._prepared_dispatch_integrity(prepared)

                member_digest = self._action_cohort_member_integrity_digest(dispatches)
                member_ids = tuple(id(prepared) for prepared in dispatches)
                member_locks = tuple(prepared._lock for prepared in dispatches)
                member_integrity_tokens = tuple(
                    prepared._integrity_token for prepared in dispatches
                )
                member_occurrence_ids = tuple(prepared.occurrence_id for prepared in dispatches)
                member_occurrences = tuple(prepared._occurrence for prepared in dispatches)
                member_projections = tuple(prepared._projection for prepared in dispatches)
                trusted_projections = tuple(
                    self._freeze_action_cohort_projection(prepared._projection)
                    for prepared in dispatches
                )
                member_expected_state_versions = tuple(
                    prepared._expected_state_version for prepared in dispatches
                )
                member_authored_intent_ids = tuple(
                    prepared._authored_intent_id for prepared in dispatches
                )
                member_binary_identity_kinds = tuple(
                    prepared._binary_identity_kind for prepared in dispatches
                )
                state_plan_digest = hashlib.sha256(repr(state_plan).encode("utf-8")).hexdigest()
                effect_binding_digest = self._action_cohort_effect_binding_digest(
                    effect_member_bindings,
                    external_effect_links,
                )
                nested_token_digest = self._action_cohort_nested_token_digest(
                    timing_preparation=timing_preparation,
                    lifecycle_token=lifecycle_token,
                    audit_preparation=audit_preparation,
                    intent_token=intent_token,
                )
                carrier = PreparedActionCohortBatch(
                    dispatcher_token=id(self),
                    batch_id=assigned_batch_id,
                    root_action_id=root_action_id,
                    state_plan=state_plan,
                    dispatches=dispatches,
                    source_timing_preparation=timing_preparation,
                    lifecycle_binding_token=lifecycle_token,
                    audit_binding_token=audit_preparation.binding_token,
                    artifact_publications=artifact_publication_tuple,
                    intent_binding_token=intent_token,
                    exact_projection=exact_projection,
                )
                record = _PreparedActionCohortBatchRecord(
                    batch_id=assigned_batch_id,
                    carrier_id=id(carrier),
                    carrier_ref=ref(carrier),
                    root_action_id=root_action_id,
                    state_plan=state_plan,
                    dispatches=dispatches,
                    member_ids=member_ids,
                    member_locks=member_locks,
                    member_integrity_tokens=member_integrity_tokens,
                    member_occurrence_ids=member_occurrence_ids,
                    member_occurrences=member_occurrences,
                    member_projections=member_projections,
                    trusted_projections=trusted_projections,
                    member_expected_state_versions=member_expected_state_versions,
                    member_authored_intent_ids=member_authored_intent_ids,
                    member_binary_identity_kinds=member_binary_identity_kinds,
                    source_timing_preparation=timing_preparation,
                    lifecycle_request=lifecycle_request,
                    lifecycle_token=lifecycle_token,
                    audit_entries=audit_entries,
                    effect_member_bindings=effect_member_bindings,
                    external_effect_links=external_effect_links,
                    owned_effect_plans=owned_effect_plans,
                    published_provenances=published_provenance_tuple,
                    execution_effect_audit=execution_effect_audit,
                    audit_preparation=audit_preparation,
                    artifact_registry=(artifact_registry if artifact_publication_tuple else None),
                    artifact_publications=artifact_publication_tuple,
                    intent_ledger=(intent_ledger if intent_request is not None else None),
                    intent_request=intent_request,
                    intent_token=intent_token,
                    exact_projection=exact_projection,
                    exact_projection_kind="",
                    exact_all_suppressed=False,
                    exact_publication_batch=None,
                    exact_prepared_identifiers=(),
                    exact_prepared_row_count=0,
                    observation_deltas=observation_deltas,
                    observation_digest=observation_digest,
                    member_integrity_digest=member_digest,
                    state_plan_digest=state_plan_digest,
                    effect_binding_digest=effect_binding_digest,
                    nested_token_digest=nested_token_digest,
                    integrity_token="",
                    retained_bytes=retained_bytes,
                    member_cleanup_status=[False] * len(dispatches),
                    artifact_cleanup_status=[False] * len(artifact_publication_tuple),
                )
                if exact_projection:
                    self._initialize_action_cohort_exact_projection(record, cleanup_record)
                integrity = self._action_cohort_batch_integrity(carrier, record)
                carrier._integrity_token = integrity
                record.integrity_token = integrity
                with self._action_cohort_lock:
                    if (
                        type(self._action_cohort_batches) is not dict
                        or type(self._action_cohort_batch_locators) is not dict
                        or self._action_cohort_prepare_cleanups.get(cleanup_id)
                        is not cleanup_record
                    ):
                        raise EventContractError("Action-cohort batch registries are malformed")
                    try:
                        self._action_cohort_batches[assigned_batch_id] = record
                        self._action_cohort_batch_locators[id(carrier)] = assigned_batch_id
                        self._action_cohort_prepare_cleanups.pop(cleanup_id)
                        installed_record = record
                    except BaseException:
                        self._action_cohort_batches.pop(assigned_batch_id, None)
                        self._action_cohort_batch_locators.pop(id(carrier), None)
                        raise
            if installed_record is None or carrier is None:
                raise EventContractError("Action-cohort batch installation was incomplete")
            if exact_projection:
                self._prepare_action_cohort_exact_projection(installed_record)
                exact_integrity = self._action_cohort_batch_integrity(carrier, installed_record)
                carrier._integrity_token = exact_integrity
                installed_record.integrity_token = exact_integrity
            return carrier
        except BaseException as primary:
            with self._action_cohort_lock:
                registered_record = (
                    self._action_cohort_batches.get(installed_record.batch_id)
                    if installed_record is not None
                    else None
                )
                if self._action_cohort_prepare_cleanups.get(cleanup_id) is cleanup_record:
                    cleanup_record.state = "pending"
            if registered_record is installed_record and installed_record is not None:
                cleanup_failures = self._finish_action_cohort_batch_cleanup(
                    installed_record,
                    terminal_state="cancelled",
                )
            else:
                cleanup_failures = self._finish_action_cohort_preparation_cleanup(cleanup_record)
            self._add_action_cohort_cleanup_notes(primary, cleanup_failures)
            raise

    def _cancel_action_cohort_preparation_record(
        self,
        record: _ActionCohortPreparationCleanupRecord,
    ) -> tuple[BaseException, ...]:
        """Attempt every provisional-member and nested-owner rollback independently."""

        failures: list[BaseException] = []
        exact_batch = record.exact_publication_batch
        if exact_batch is None:
            record.exact_cleanup_complete = True
        elif not record.exact_cleanup_complete:
            try:
                exact_batch.cancel()
            except BaseException as exc:
                if exact_batch.state == "canceled":
                    record.exact_cleanup_complete = True
                else:
                    failures.append(exc)
            else:
                record.exact_cleanup_complete = True
        for ordinal, prepared in enumerate(record.dispatches):
            if record.member_cleanup_complete[ordinal]:
                continue
            try:
                with cast(AbstractContextManager[object], record.member_locks[ordinal]):
                    if record.member_installed[ordinal]:
                        previous_integrity = prepared._integrity_token
                        prepared._action_cohort_batch_id = None
                        try:
                            prepared._integrity_token = self._prepared_dispatch_integrity(prepared)
                        except BaseException:
                            prepared._action_cohort_batch_id = record.batch_id
                            prepared._integrity_token = previous_integrity
                            raise
                    record.member_cleanup_complete[ordinal] = True
            except BaseException as exc:
                failures.append(exc)

        artifact_failures = self._cancel_action_cohort_artifacts(
            record.artifact_registry,
            record.artifact_publications,
            record.artifact_cleanup_status,
        )
        failures.extend(artifact_failures)
        record.artifact_cleanup_complete = all(record.artifact_cleanup_status)

        if record.intent_token is None or record.intent_ledger is None:
            record.intent_cleanup_complete = True
        elif not record.intent_cleanup_complete:
            try:
                record.intent_ledger.cancel_batch(record.intent_token)
            except BaseException as exc:
                try:
                    still_active = record.intent_ledger.authenticates_batch_token(
                        record.intent_token,
                        request=record.intent_request,
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.intent_cleanup_complete = True
            else:
                record.intent_cleanup_complete = True

        if record.audit_preparation is None:
            record.audit_cleanup_complete = True
        elif not record.audit_cleanup_complete:
            try:
                record.execution_effect_audit.cancel_action_cohort(record.audit_preparation)
            except BaseException as exc:
                try:
                    still_active = (
                        record.execution_effect_audit.authenticates_action_cohort_preparation(
                            record.audit_preparation,
                            root_action_id=record.root_action_id,
                            entries=record.audit_entries,
                            owned_plans=record.owned_effect_plans,
                            published_provenances=record.published_provenances,
                        )
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.audit_cleanup_complete = True
            else:
                record.audit_cleanup_complete = True

        if record.lifecycle_token is None:
            record.lifecycle_cleanup_complete = True
        elif not record.lifecycle_cleanup_complete:
            try:
                record.lifecycle_authority.registry.cancel_action_cohort(record.lifecycle_token)
            except BaseException as exc:
                try:
                    still_active = record.lifecycle_authority.registry.authenticates_action_cohort_admission_token(
                        record.lifecycle_token,
                        request=record.lifecycle_request,
                        state_publication_token=record.lifecycle_request.state_publication_token,
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.lifecycle_cleanup_complete = True
            else:
                record.lifecycle_cleanup_complete = True

        if record.source_timing_preparation.committed:
            record.timing_cleanup_complete = True
        elif not record.timing_cleanup_complete:
            try:
                record.source_timing_preparation.cancel()
            except BaseException as exc:
                try:
                    still_active = self.source_timing_planner.authenticates_preparation(
                        record.source_timing_preparation
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.timing_cleanup_complete = True
            else:
                record.timing_cleanup_complete = True
        return tuple(failures)

    def _finish_action_cohort_preparation_cleanup(
        self,
        record: _ActionCohortPreparationCleanupRecord,
    ) -> tuple[BaseException, ...]:
        """Retry one failed preparation while retaining its sole trusted locator."""

        with self._action_cohort_lock:
            if self._action_cohort_prepare_cleanups.get(record.cleanup_id) is not record:
                return ()
            if record.state == "cleaning":
                return (EventContractError("Action-cohort preparation cleanup is already active"),)
            record.state = "cleaning"
        try:
            failures = self._cancel_action_cohort_preparation_record(record)
        except BaseException as exc:
            failures = (exc,)
        complete = all(record.member_cleanup_complete) and all(
            (
                record.artifact_cleanup_complete,
                record.intent_cleanup_complete,
                record.audit_cleanup_complete,
                record.lifecycle_cleanup_complete,
                record.timing_cleanup_complete,
                record.exact_cleanup_complete,
            )
        )
        with self._action_cohort_lock:
            if failures or not complete:
                record.state = "pending"
                if not failures:
                    failures = (
                        EventContractError("Action-cohort preparation cleanup remained incomplete"),
                    )
                return failures
            if self._action_cohort_prepare_cleanups.get(record.cleanup_id) is record:
                self._action_cohort_prepare_cleanups.pop(record.cleanup_id)
                self._action_cohort_retained_members -= len(record.dispatches)
                self._action_cohort_retained_bytes -= record.retained_bytes
            record.state = "cancelled"
        return ()

    @staticmethod
    def _cancel_action_cohort_artifacts(
        registry: LocalArtifactVersionRegistry | None,
        publications: tuple[LocalArtifactPublishToken, ...],
        cleanup_status: list[bool],
    ) -> tuple[BaseException, ...]:
        """Release each still-prepared artifact token without short-circuiting cleanup."""

        failures: list[BaseException] = []
        if not publications:
            return ()
        if registry is None or len(cleanup_status) != len(publications):
            return (EventContractError("Action-cohort artifact cleanup state is malformed"),)
        for ordinal, token in enumerate(publications):
            if cleanup_status[ordinal]:
                continue
            try:
                registry.cancel_prepared(token)
            except BaseException as exc:
                try:
                    still_active = registry.authenticates_prepared_publication(token)
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                    continue
            cleanup_status[ordinal] = True
        return tuple(failures)

    def _active_action_cohort_batch_locked(
        self,
        batch: PreparedActionCohortBatch,
        *,
        states: tuple[str, ...] = ("prepared",),
    ) -> _PreparedActionCohortBatchRecord:
        """Return one exact callback-free carrier record under the dispatcher lock."""

        if type(batch) is not PreparedActionCohortBatch:
            raise EventContractError("Action-cohort batch must be the exact opaque type")
        batch_id = self._action_cohort_batch_locators.get(id(batch))
        record = self._action_cohort_batches.get(batch_id) if batch_id is not None else None
        if record is None or record.carrier_ref() is not batch:
            raise EventContractError("Action-cohort batch is foreign, stale, or consumed")
        dispatcher_token = batch._dispatcher_token
        carrier_batch_id = batch._batch_id
        root_action_id = batch._root_action_id
        integrity_token = batch._integrity_token
        consumed = batch._consumed
        exact_projection = batch._exact_projection
        if (
            type(dispatcher_token) is not int
            or type(carrier_batch_id) is not int
            or type(root_action_id) is not str
            or type(integrity_token) is not str
            or type(consumed) is not bool
            or type(exact_projection) is not bool
        ):
            raise EventContractError("Action-cohort batch carrier shape is malformed")
        expected = self._action_cohort_batch_integrity(batch, record)
        if (
            dispatcher_token != id(self)
            or carrier_batch_id != record.batch_id
            or root_action_id != record.root_action_id
            or consumed
            or record.state not in states
            or batch._state_plan is not record.state_plan
            or batch._dispatches is not record.dispatches
            or batch._source_timing_preparation is not record.source_timing_preparation
            or batch._lifecycle_binding_token is not record.lifecycle_token
            or batch._audit_binding_token is not record.audit_preparation._token
            or batch._artifact_publications is not record.artifact_publications
            or batch._intent_binding_token is not record.intent_token
            or exact_projection is not record.exact_projection
            or not hmac.compare_digest(integrity_token, expected)
            or not hmac.compare_digest(record.integrity_token, expected)
        ):
            raise EventContractError("Action-cohort batch integrity validation failed")
        return record

    def _action_cohort_batch_record_authenticates(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> bool:
        """Reauthenticate every fallible nested owner outside dispatcher locks."""

        authority = self._lifecycle_authority
        if authority is None or self._execution_effect_audit is not record.execution_effect_audit:
            return False
        if type(record.exact_projection) is not bool:
            return False
        if record.exact_projection:
            if (
                record.exact_publication_batch is None
                or record.exact_publication_batch.state != "ready"
                or len(record.trusted_projections) != 1
            ):
                return False
        elif record.exact_publication_batch is not None:
            return False
        if not self.state_manager.authenticates_action_cohort_plan(record.state_plan):
            return False
        self.state_manager.validate_action_cohort_materialization(record.state_plan)
        if authority.action_cohort_request(record.state_plan) != record.lifecycle_request:
            return False
        if not authority.authenticates_action_cohort_binding(
            record.state_plan,
            record.lifecycle_token,
        ):
            return False
        if not self.source_timing_planner.authenticates_preparation(
            record.source_timing_preparation
        ):
            return False
        if record.artifact_publications:
            if (
                record.artifact_registry is None
                or self.local_artifact_registry is not record.artifact_registry
                or any(
                    not record.artifact_registry.authenticates_prepared_publication(token)
                    for token in record.artifact_publications
                )
            ):
                return False
        elif record.artifact_registry is not None:
            return False
        audit = record.execution_effect_audit
        if not audit.authenticates_action_cohort_binding_token(
            record.audit_preparation.binding_token
        ) or not audit.authenticates_action_cohort_preparation(
            record.audit_preparation,
            root_action_id=record.root_action_id,
            entries=record.audit_entries,
            owned_plans=record.owned_effect_plans,
            published_provenances=record.published_provenances,
        ):
            return False
        if record.intent_request is None:
            if record.intent_ledger is not None or record.intent_token is not None:
                return False
        elif (
            record.intent_ledger is None
            or self.intent_execution_ledger is not record.intent_ledger
            or record.intent_token is None
            or not record.intent_ledger.authenticates_batch_token(
                record.intent_token,
                request=record.intent_request,
            )
        ):
            return False

        with ExitStack() as member_locks:
            for prepared in sorted(record.dispatches, key=id):
                member_locks.enter_context(prepared._lock)
            for prepared in record.dispatches:
                if (
                    type(prepared._consumed) is not bool
                    or prepared._consumed
                    or type(prepared._action_cohort_batch_id) is not int
                    or prepared._action_cohort_batch_id != record.batch_id
                    or prepared._network_dependent_batch_id is not None
                    or prepared._deferred_session_publication_batch_id is not None
                ):
                    return False
                self.validate_prepared(prepared)
            member_digest = self._action_cohort_member_integrity_digest(record.dispatches)
            observed_artifacts: list[LocalArtifactPublishToken] = []
            observed_artifact_ids: set[int] = set()
            for prepared in record.dispatches:
                for token in prepared._artifact_publications:
                    if id(token) in observed_artifact_ids:
                        continue
                    observed_artifact_ids.add(id(token))
                    observed_artifacts.append(token)
            if len(observed_artifacts) != len(record.artifact_publications) or any(
                observed is not retained
                for observed, retained in zip(
                    observed_artifacts,
                    record.artifact_publications,
                    strict=True,
                )
            ):
                return False
        if not hmac.compare_digest(record.member_integrity_digest, member_digest):
            return False

        self._validate_action_cohort_dispatch_coverage(
            record.state_plan,
            record.dispatches,
        )
        self._validate_action_cohort_effect_member_bindings(
            root_action_id=record.root_action_id,
            state_plan=record.state_plan,
            dispatches=record.dispatches,
            audit_entries=record.audit_entries,
            bindings=record.effect_member_bindings,
            external_links=record.external_effect_links,
            owned_effect_plans=record.owned_effect_plans,
        )
        observation_deltas = tuple(
            delta
            for prepared in record.dispatches
            for delta in self._action_cohort_projection_observation_deltas(prepared._projection)
        )
        if observation_deltas != record.observation_deltas or not hmac.compare_digest(
            record.observation_digest,
            self._action_cohort_observation_digest(observation_deltas),
        ):
            return False
        state_plan_digest = hashlib.sha256(repr(record.state_plan).encode("utf-8")).hexdigest()
        effect_binding_digest = self._action_cohort_effect_binding_digest(
            record.effect_member_bindings,
            record.external_effect_links,
        )
        nested_token_digest = self._action_cohort_nested_token_digest(
            timing_preparation=record.source_timing_preparation,
            lifecycle_token=record.lifecycle_token,
            audit_preparation=record.audit_preparation,
            intent_token=record.intent_token,
        )
        retained_bytes = self._action_cohort_batch_retained_size(
            record.state_plan,
            record.dispatches,
            record.artifact_publications,
            record.lifecycle_request,
            record.audit_entries,
            record.effect_member_bindings,
            record.external_effect_links,
            record.owned_effect_plans,
            record.published_provenances,
            record.observation_deltas,
            record.intent_request,
        )
        return bool(
            hmac.compare_digest(record.state_plan_digest, state_plan_digest)
            and hmac.compare_digest(record.effect_binding_digest, effect_binding_digest)
            and hmac.compare_digest(record.nested_token_digest, nested_token_digest)
            and retained_bytes == record.retained_bytes
        )

    @staticmethod
    def _action_cohort_closed_members_authenticate_locked(
        record: _PreparedActionCohortBatchRecord,
    ) -> bool:
        """Check only exact member identities and closed scalar fences under trusted locks."""

        member_count = len(record.dispatches)
        closed_sequences = (
            record.member_ids,
            record.member_locks,
            record.member_integrity_tokens,
            record.member_occurrence_ids,
            record.member_occurrences,
            record.member_projections,
            record.trusted_projections,
            record.member_expected_state_versions,
            record.member_authored_intent_ids,
            record.member_binary_identity_kinds,
        )
        if any(
            type(sequence) is not tuple or len(sequence) != member_count
            for sequence in closed_sequences
        ):
            return False
        for ordinal, prepared in enumerate(record.dispatches):
            consumed = prepared._consumed
            batch_id = prepared._action_cohort_batch_id
            integrity_token = prepared._integrity_token
            expected_state_version = prepared._expected_state_version
            authored_intent_id = prepared._authored_intent_id
            binary_identity_kind = prepared._binary_identity_kind
            artifact_publications = prepared._artifact_publications
            if (
                type(prepared) is not PreparedDispatch
                or id(prepared) != record.member_ids[ordinal]
                or prepared._lock is not record.member_locks[ordinal]
                or type(consumed) is not bool
                or consumed
                or type(batch_id) is not int
                or batch_id != record.batch_id
                or type(integrity_token) is not str
                or type(record.member_integrity_tokens[ordinal]) is not str
                or not hmac.compare_digest(
                    integrity_token,
                    record.member_integrity_tokens[ordinal],
                )
                or prepared._occurrence is not record.member_occurrences[ordinal]
                or prepared._projection is not record.member_projections[ordinal]
                or type(expected_state_version) is not int
                or expected_state_version != record.member_expected_state_versions[ordinal]
                or (authored_intent_id is not None and type(authored_intent_id) is not str)
                or authored_intent_id != record.member_authored_intent_ids[ordinal]
                or type(binary_identity_kind) is not str
                or binary_identity_kind != record.member_binary_identity_kinds[ordinal]
                or prepared._state_intent is not PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT
                or prepared._lifecycle_ticket is not record.state_plan
                or prepared._source_timing_preparation is not record.source_timing_preparation
                or prepared._network_dependent_batch_id is not None
                or prepared._deferred_session_publication_batch_id is not None
                or type(artifact_publications) is not tuple
            ):
                return False
        return True

    def _action_cohort_closed_record_authenticates(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> bool:
        """Authenticate one claimed record without rewalking caller-owned graphs."""

        authority = self._lifecycle_authority
        if (
            authority is None
            or self._execution_effect_audit is not record.execution_effect_audit
            or record.timing_claimed is not record.source_timing_preparation
            or record.state_claimed is None
            or record.lifecycle_claimed is None
            or record.audit_claimed is None
            or (
                bool(record.artifact_publications)
                != bool(
                    record.artifact_registry is not None and record.artifact_claimed is not None
                )
            )
            or (
                record.artifact_registry is not None
                and self.local_artifact_registry is not record.artifact_registry
            )
            or record.claim_thread_id != get_ident()
            or record.state not in {"claiming", "claimed"}
            or type(record.integrity_token) is not str
            or type(record.member_integrity_digest) is not str
            or type(record.state_plan_digest) is not str
            or type(record.effect_binding_digest) is not str
            or type(record.nested_token_digest) is not str
        ):
            return False
        if record.intent_request is None:
            if record.intent_ledger is not None or record.intent_claimed is not None:
                return False
        elif (
            record.intent_ledger is None
            or self.intent_execution_ledger is not record.intent_ledger
            or record.intent_claimed is None
        ):
            return False
        try:
            with ExitStack() as member_locks:
                for member_lock in sorted(record.member_locks, key=id):
                    member_locks.enter_context(cast(AbstractContextManager[object], member_lock))
                return self._action_cohort_closed_members_authenticate_locked(record)
        except BaseException:
            return False

    def authenticates_prepared_action_cohort_batch(self, batch: object) -> bool:
        """Totally authenticate one exact prepared batch and every nested owner."""

        if type(batch) is not PreparedActionCohortBatch:
            return False
        try:
            with self._action_cohort_lock:
                record = self._active_action_cohort_batch_locked(batch)
            if not self._action_cohort_batch_record_authenticates(record):
                return False
            with self._action_cohort_lock:
                return self._active_action_cohort_batch_locked(batch) is record
        except BaseException:
            return False

    def _active_claimed_action_cohort_locked(
        self,
        capability: PreparedActionCohortCapability,
        *,
        states: tuple[str, ...] = ("claimed",),
    ) -> _PreparedActionCohortBatchRecord:
        """Return one callback-free, same-thread capability record under the lock."""

        if type(capability) is not PreparedActionCohortCapability:
            raise EventContractError("Action-cohort capability must be the exact opaque type")
        batch_id = self._action_cohort_capability_locators.get(id(capability))
        record = self._action_cohort_batches.get(batch_id) if batch_id is not None else None
        if (
            record is None
            or record.capability_id != id(capability)
            or record.capability_ref is None
            or record.capability_ref() is not capability
        ):
            raise EventContractError("Action-cohort capability is foreign, stale, or consumed")
        carrier_batch_id = capability._batch_id
        claim_token = capability._claim_token
        active = capability._active
        committed = capability._committed
        if (
            type(carrier_batch_id) is not int
            or type(claim_token) is not str
            or type(active) is not bool
            or type(committed) is not bool
        ):
            raise EventContractError("Action-cohort capability shape is malformed")
        expected = self._action_cohort_claim_integrity(capability, record)
        if (
            capability._dispatcher is not self
            or carrier_batch_id != record.batch_id
            or not active
            or committed
            or capability._receipt is not None
            or capability._result is not None
            or record.state not in states
            or record.claim_thread_id != get_ident()
            or not hmac.compare_digest(claim_token, expected)
            or not hmac.compare_digest(record.claim_token, expected)
        ):
            raise EventContractError("Action-cohort capability integrity validation failed")
        return record

    @staticmethod
    def _close_action_cohort_claim_contexts(
        entered: list[AbstractContextManager[object]],
        primary: BaseException | None,
    ) -> tuple[BaseException, ...]:
        """Close every entered owner context without replacing an existing primary."""

        failures: list[BaseException] = []
        exc_type = type(primary) if primary is not None else None
        traceback = primary.__traceback__ if primary is not None else None
        for owner_context in reversed(entered):
            try:
                owner_context.__exit__(exc_type, primary, traceback)
            except BaseException as exc:
                failures.append(exc)
        return tuple(failures)

    @contextmanager
    def claimed_action_cohort(
        self,
        batch: PreparedActionCohortBatch,
    ) -> Iterator[PreparedActionCohortCapability]:
        """Claim every cohort owner in deterministic order and yield one commit capability."""

        if type(batch) is not PreparedActionCohortBatch:
            raise TypeError("Action-cohort claim requires the exact opaque batch type")
        with self._action_cohort_lock:
            record = self._active_action_cohort_batch_locked(batch)
            record.state = "claiming"

        capability: PreparedActionCohortCapability | None = None
        try:
            entered: list[AbstractContextManager[object]] = []
            try:
                if not self._action_cohort_batch_record_authenticates(record):
                    raise EventContractError(
                        "Action-cohort batch failed authentication before nested claim"
                    )
                authority = self._lifecycle_authority
                if authority is None:  # pragma: no cover - authenticated above
                    raise EventContractError("Action-cohort lifecycle authority is unavailable")

                timing_context = record.source_timing_preparation.claimed_commit()
                timing_claimed = timing_context.__enter__()
                entered.append(cast(AbstractContextManager[object], timing_context))
                state_context = self.state_manager.prepared_action_cohort_materialization(
                    record.state_plan
                )
                state_claimed = state_context.__enter__()
                entered.append(cast(AbstractContextManager[object], state_context))
                lifecycle_context = authority.registry.claimed_action_cohort(record.lifecycle_token)
                lifecycle_claimed = lifecycle_context.__enter__()
                entered.append(cast(AbstractContextManager[object], lifecycle_context))
                audit_context = record.execution_effect_audit.claimed_action_cohort(
                    record.audit_preparation
                )
                audit_claimed = audit_context.__enter__()
                entered.append(cast(AbstractContextManager[object], audit_context))
                intent_claimed: PreparedIntentExecutionBatch | None = None
                if record.intent_ledger is not None and record.intent_token is not None:
                    intent_context = record.intent_ledger.claimed_batch(record.intent_token)
                    intent_claimed = intent_context.__enter__()
                    entered.append(cast(AbstractContextManager[object], intent_context))
                artifact_claimed: LocalArtifactPreparedGroupCommit | None = None
                if record.artifact_registry is not None and record.artifact_publications:
                    artifact_context = record.artifact_registry.prepared_publication_group(
                        record.artifact_publications
                    )
                    artifact_claimed = artifact_context.__enter__()
                    entered.append(cast(AbstractContextManager[object], artifact_context))

                record.claim_thread_id = get_ident()
                record.timing_claimed = timing_claimed
                record.state_claimed = state_claimed
                record.lifecycle_claimed = lifecycle_claimed
                record.audit_claimed = audit_claimed
                record.intent_claimed = intent_claimed
                record.artifact_claimed = artifact_claimed
                self._prepare_action_cohort_publication_objects(record)
                capability = PreparedActionCohortCapability(
                    self,
                    batch_id=record.batch_id,
                    claim_token="",
                )
                record.capability_id = id(capability)
                record.capability_ref = ref(capability)
                claim_token = self._action_cohort_claim_integrity(capability, record)
                capability._claim_token = claim_token
                record.claim_token = claim_token
                with self._action_cohort_lock:
                    active = self._action_cohort_batches.get(record.batch_id)
                    if active is not record or record.state != "claiming":
                        raise EventContractError("Action-cohort batch changed during nested claim")
                    record.state = "claimed"
                    self._action_cohort_capability_locators[id(capability)] = record.batch_id
                    self._action_cohort_claimed_batches += 1

                if not self._action_cohort_closed_record_authenticates(record):
                    raise EventContractError(
                        "Action-cohort batch failed its final nested authentication sweep"
                    )
                if not self._action_cohort_expected_publications_authenticate(record):
                    raise EventContractError(
                        "Action-cohort expected publications failed final claim authentication"
                    )
                with self._action_cohort_lock:
                    self._active_claimed_action_cohort_locked(capability)

                yield capability

                with self._action_cohort_lock:
                    if record.state != "committed":
                        raise EventContractError(
                            "Claimed action-cohort batch exited without commit_no_fail"
                        )
            except BaseException as claim_primary:
                close_failures = self._close_action_cohort_claim_contexts(
                    entered,
                    claim_primary,
                )
                self._add_action_cohort_cleanup_notes(claim_primary, close_failures)
                raise
            else:
                close_failures = self._close_action_cohort_claim_contexts(entered, None)
                if close_failures:
                    close_primary = close_failures[0]
                    self._add_action_cohort_cleanup_notes(close_primary, close_failures[1:])
                    raise close_primary
        except BaseException as primary:
            should_cleanup = record.state != "committed"
            failures: tuple[BaseException, ...] = ()
            if should_cleanup:
                try:
                    failures = self._finish_action_cohort_batch_cleanup(
                        record,
                        terminal_state="cancelled",
                    )
                except BaseException as exc:
                    failures = (*failures, exc)
            self._add_action_cohort_cleanup_notes(primary, failures)
            raise
        finally:
            if capability is not None:
                object.__setattr__(capability, "_active", False)

    def _detach_action_cohort_batch_locked(
        self,
        record: _PreparedActionCohortBatchRecord,
        *,
        terminal_state: str,
    ) -> None:
        """Detach one trusted outer record without touching nested owner locks."""

        self._action_cohort_batches.pop(record.batch_id, None)
        self._action_cohort_batch_locators.pop(record.carrier_id, None)
        if record.capability_id is not None:
            self._action_cohort_capability_locators.pop(record.capability_id, None)
        receipt = record.publication_receipt
        if receipt is not None and not receipt._published:
            self._action_cohort_receipts.pop(id(receipt), None)
            self._exact_projection_recoveries.pop(id(receipt), None)
        self._action_cohort_retained_members -= len(record.dispatches)
        self._action_cohort_retained_bytes -= record.retained_bytes
        if record.state in {"claimed", "committing"}:
            self._action_cohort_claimed_batches -= 1
        record.state = terminal_state
        carrier = record.carrier_ref()
        if carrier is not None:
            carrier._consumed = True

    def _begin_action_cohort_batch_cleanup_locked(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Keep the sole trusted locator until every nested cancellation succeeds."""

        if self._action_cohort_batches.get(record.batch_id) is not record:
            return
        if record.state in {"claimed", "committing"}:
            self._action_cohort_claimed_batches -= 1
        if record.capability_id is not None:
            self._action_cohort_capability_locators.pop(record.capability_id, None)
        receipt = record.publication_receipt
        if receipt is not None and not receipt._published:
            self._action_cohort_receipts.pop(id(receipt), None)
            self._exact_projection_recoveries.pop(id(receipt), None)
        record.state = "cleanup_pending"

    def _finish_action_cohort_batch_cleanup(
        self,
        record: _PreparedActionCohortBatchRecord,
        *,
        terminal_state: str,
    ) -> tuple[BaseException, ...]:
        """Attempt every cleanup, retaining the trusted record if any owner fails."""

        with self._action_cohort_lock:
            self._begin_action_cohort_batch_cleanup_locked(record)
        failures = self._cancel_action_cohort_record(record)
        if failures:
            return failures
        if not all(
            (
                record.members_cleanup_complete,
                record.artifact_cleanup_complete,
                record.intent_cleanup_complete,
                record.audit_cleanup_complete,
                record.lifecycle_cleanup_complete,
                record.timing_cleanup_complete,
                record.exact_cleanup_complete,
            )
        ):
            return (EventContractError("Action-cohort cleanup remained incomplete"),)
        with self._action_cohort_lock:
            if self._action_cohort_batches.get(record.batch_id) is record:
                self._detach_action_cohort_batch_locked(
                    record,
                    terminal_state=terminal_state,
                )
        return ()

    @staticmethod
    def _consume_action_cohort_members(
        record: _PreparedActionCohortBatchRecord,
    ) -> tuple[BaseException, ...]:
        """Attempt every trusted exact member consumption without mutable locators."""

        failures: list[BaseException] = []
        for ordinal, prepared in enumerate(record.dispatches):
            if record.member_cleanup_status[ordinal]:
                continue
            try:
                with cast(AbstractContextManager[object], record.member_locks[ordinal]):
                    prepared._action_cohort_batch_id = None
                    prepared._consumed = True
            except BaseException as exc:
                failures.append(exc)
            else:
                record.member_cleanup_status[ordinal] = True
        return tuple(failures)

    def _prepare_action_cohort_dispatcher_ledgers(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Allocate every dispatcher-owned replacement before canonical commit."""

        observation_updates = record.prepared_observation_updates
        if observation_updates is None or any(
            type(update) is not _ActionCohortPreparedObservationCluster
            or type(update.cluster_id) is not str
            or (update.canonical_cluster is None) == (update.new_cluster is None)
            or (update.canonical_cluster is not None and type(update.canonical_cluster) is not dict)
            or (update.new_cluster is not None and type(update.new_cluster) is not dict)
            or (
                update.new_cluster is not None
                and any(
                    type(source) is not str or type(summary) is not ObservationSummary
                    for source, summary in update.new_cluster.items()
                )
            )
            or type(update.source_updates) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not ObservationSummary
                for item in update.source_updates
            )
            for update in observation_updates
        ):
            raise EventContractError("Action-cohort observation replacements are malformed")
        binary_counts = self._binary_identity_counts.copy()
        for binary_identity_kind in record.member_binary_identity_kinds:
            if binary_identity_kind:
                binary_counts[binary_identity_kind] += 1
        record.prepared_binary_counts = binary_counts
        record.prepared_latest_network_observations_uid = self._latest_network_observations_uid
        record.prepared_latest_network_observations = self._latest_network_observations
        record.prepared_latest_network_plan = self._latest_network_plan
        for projection in record.trusted_projections:
            event = projection.occurrence
            if event.network is not None and self._publishes_network_sensor_observations(event):
                record.prepared_latest_network_observations_uid = event.network.zeek_uid
                record.prepared_latest_network_observations = event.network_observations
                record.prepared_latest_network_plan = event.network

    def _commit_action_cohort_dispatcher_ledgers_no_fail(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> None:
        """Swap only preallocated dispatcher summaries after every owner commits."""

        self._binary_identity_counts = cast(Counter[str], record.prepared_binary_counts)
        self._latest_network_observations_uid = record.prepared_latest_network_observations_uid
        self._latest_network_observations = record.prepared_latest_network_observations
        self._latest_network_plan = record.prepared_latest_network_plan
        self._commit_action_cohort_observations_no_fail(record)

    def _commit_claimed_action_cohort(
        self,
        capability: PreparedActionCohortCapability,
    ) -> ActionCohortPublicationResult:
        """Commit certified owners, install one receipt, then attempt every projection."""

        with self._action_cohort_lock:
            record = self._active_claimed_action_cohort_locked(capability)
        if not self._action_cohort_closed_record_authenticates(record):
            raise EventContractError(
                "Action-cohort batch failed its immediate precommit authentication sweep"
            )

        with ExitStack() as member_locks:
            for member_lock in sorted(record.member_locks, key=id):
                member_locks.enter_context(cast(AbstractContextManager[object], member_lock))
            if not self._action_cohort_closed_members_authenticate_locked(record):
                raise EventContractError(
                    "Action-cohort member changed during the final claim fence"
                )
            if not self._action_cohort_expected_publications_authenticate(record):
                raise EventContractError(
                    "Action-cohort expected publications changed before final certification"
                )
            self._certify_action_cohort_owner_commits(record)

            receipt = cast(ActionCohortPublicationReceipt, record.publication_receipt)
            result = cast(ActionCohortPublicationResult, record.publication_result)
            with self._publication_ledger_lock:
                with self._claimed_action_cohort_observations(record):
                    self._prepare_action_cohort_dispatcher_ledgers(record)
                    with self._action_cohort_lock:
                        if self._active_claimed_action_cohort_locked(capability) is not record:
                            raise EventContractError("Action-cohort claim changed before commit")
                        if type(self._action_cohort_receipts) is not dict:
                            raise EventContractError("Action-cohort receipt registry is malformed")
                        if id(receipt) in self._action_cohort_receipts:
                            raise EventContractError(
                                "Action-cohort receipt identity is already live"
                            )
                        recovery = record.exact_recovery
                        if recovery is not None:
                            if len(
                                self._exact_projection_recoveries
                            ) + self._exact_projection_recovery_reservations >= (
                                self._exact_projection_recovery_capacity
                            ):
                                raise EventContractError(
                                    "Exact projection recovery capacity is exhausted"
                                )
                            if (
                                recovery.receipt is not receipt
                                or recovery.state != "reserved"
                                or id(receipt) in self._exact_projection_recoveries
                            ):
                                raise EventContractError(
                                    "Exact action-cohort recovery ownership is malformed"
                                )
                        eviction_id: int | None = None
                        if (
                            self._action_cohort_committed_receipts
                            >= self._action_cohort_receipt_capacity
                        ):
                            eviction_id = next(
                                (
                                    receipt_id
                                    for receipt_id, retained in self._action_cohort_receipts.items()
                                    if retained._published
                                    and receipt_id not in self._exact_projection_recoveries
                                ),
                                None,
                            )
                            if eviction_id is None:
                                raise EventContractError(
                                    "Action-cohort receipt capacity has no published eviction"
                                )
                        record.receipt_eviction_id = eviction_id
                        self._action_cohort_receipts[id(receipt)] = receipt
                        if recovery is not None:
                            self._exact_projection_recoveries[id(receipt)] = recovery
                            self._exact_projection_recovery_high_water = max(
                                self._exact_projection_recovery_high_water,
                                len(self._exact_projection_recoveries),
                            )
                        record.state = "committing"
                    for prepared in record.dispatches:
                        prepared._action_cohort_batch_id = None
                        prepared._consumed = True

                    if record.exact_recovery is not None:
                        if (
                            record.artifact_claimed is not None
                            or record.expected_artifact_receipt is not None
                        ):
                            raise EventContractError(
                                "Exact Type-5 projection unexpectedly retained an artifact owner"
                            )
                        state_claimed = cast(
                            "PreparedActionCohortMaterialization",
                            record.state_claimed,
                        )
                        lifecycle_claimed = cast(
                            "PreparedLifecycleActionCohort",
                            record.lifecycle_claimed,
                        )
                        audit_claimed = cast(
                            "PreparedExecutionEffectAuditCommit",
                            record.audit_claimed,
                        )
                        lifecycle_receipt = cast(
                            "LifecycleActionCohortReceipt",
                            record.expected_lifecycle_receipt,
                        )
                        audit_receipt = cast(
                            "ExecutionEffectAuditCommitReceipt",
                            record.expected_audit_receipt,
                        )
                        timing_claimed = cast(
                            "SourceTimingPreparation",
                            record.timing_claimed,
                        )
                        timing_receipt = cast(
                            "SourceTimingPreparationReceipt",
                            record.expected_timing_receipt,
                        )
                        state_result = cast(
                            "ActionCohortMaterializationResult",
                            record.expected_state_result,
                        )
                        authority = cast("GeneratorLifecycleAuthority", self._lifecycle_authority)

                        # Provisional State remains reversible. An exception here exits every
                        # claim before another canonical owner commits, so State rolls back.
                        state_claimed.apply_provisional()
                        self._commit_exact_expected_owner(
                            lifecycle_claimed.commit_no_fail,
                            expected=lifecycle_receipt,
                            terminal_authenticates=lambda: bool(
                                lifecycle_claimed.committed
                                and lifecycle_claimed.receipt is lifecycle_receipt
                                and authority.registry.authenticates_action_cohort_receipt(
                                    lifecycle_receipt,
                                    request=record.lifecycle_request,
                                    state_publication_token=record.state_plan.publication_token,
                                )
                            ),
                            label="Exact action-cohort lifecycle owner",
                        )
                        self._commit_exact_expected_owner(
                            audit_claimed.commit_no_fail,
                            expected=audit_receipt,
                            terminal_authenticates=lambda: bool(
                                audit_claimed.committed
                                and audit_claimed.receipt is audit_receipt
                                and record.execution_effect_audit.authenticates_action_cohort_receipt(
                                    audit_receipt,
                                    preparation=audit_claimed,
                                    root_action_id=record.root_action_id,
                                    entries=record.audit_entries,
                                    owned_plans=record.owned_effect_plans,
                                    published_provenances=record.published_provenances,
                                )
                            ),
                            label="Exact action-cohort audit owner",
                        )
                        if record.intent_claimed is not None:
                            intent_claimed = record.intent_claimed
                            intent_receipt = cast(
                                "IntentExecutionBatchReceipt",
                                record.expected_intent_receipt,
                            )
                            intent_ledger = cast("IntentExecutionLedger", record.intent_ledger)
                            self._commit_exact_expected_owner(
                                intent_claimed.commit_no_fail,
                                expected=intent_receipt,
                                terminal_authenticates=lambda: bool(
                                    intent_claimed.committed
                                    and intent_claimed.receipt is intent_receipt
                                    and intent_ledger.authenticates_batch_receipt(
                                        intent_receipt,
                                        request=record.intent_request,
                                    )
                                ),
                                label="Exact action-cohort intent owner",
                            )
                        self._commit_exact_expected_owner(
                            timing_claimed.commit_no_fail,
                            expected=timing_receipt,
                            terminal_authenticates=lambda: bool(
                                timing_claimed.committed
                                and timing_claimed.receipt is timing_receipt
                                and self.source_timing_planner.authenticates_preparation_receipt(
                                    timing_receipt
                                )
                            ),
                            label="Exact action-cohort source-timing owner",
                        )
                        try:
                            self._commit_action_cohort_dispatcher_ledgers_no_fail(record)
                        except BaseException:
                            if not record.observation_committed:
                                raise
                        if not record.observation_committed:
                            raise EventContractError(
                                "Exact action-cohort dispatcher ledgers did not commit"
                            )
                        self._commit_exact_expected_owner(
                            state_claimed.finalize_no_fail,
                            expected=state_result,
                            terminal_authenticates=lambda: bool(
                                state_claimed.committed and state_claimed._result is state_result
                            ),
                            label="Exact action-cohort State owner",
                        )
                    else:
                        # Runtime artifacts publish first through their reversible group owner.
                        # Every later owner has crossed its composite certification fence, so a
                        # successful artifact receipt is followed only by primitive mutations.
                        if record.artifact_claimed is not None:
                            artifact_receipt = record.artifact_claimed.commit_no_fail()
                            if artifact_receipt is not record.expected_artifact_receipt:
                                raise EventContractError(
                                    "Action-cohort artifact owner returned a different receipt"
                                )
                            record.artifact_cleanup_status[:] = [True] * len(
                                record.artifact_cleanup_status
                            )
                            record.artifact_cleanup_complete = True

                        cast(
                            "PreparedActionCohortMaterialization",
                            record.state_claimed,
                        ).apply_provisional()
                        cast(
                            "PreparedLifecycleActionCohort",
                            record.lifecycle_claimed,
                        ).commit_no_fail()
                        cast(
                            "PreparedExecutionEffectAuditCommit",
                            record.audit_claimed,
                        ).commit_no_fail()
                        if record.intent_claimed is not None:
                            record.intent_claimed.commit_no_fail()
                        cast(
                            "SourceTimingPreparation",
                            record.timing_claimed,
                        ).commit_no_fail()
                        self._commit_action_cohort_dispatcher_ledgers_no_fail(record)
                        cast(
                            "PreparedActionCohortMaterialization",
                            record.state_claimed,
                        ).finalize_no_fail()
                    object.__setattr__(receipt, "_published", True)
                    object.__setattr__(capability, "_committed", True)
                    object.__setattr__(capability, "_receipt", receipt)
                    object.__setattr__(capability, "_result", result)
                    with self._action_cohort_lock:
                        if record.exact_recovery is not None:
                            record.exact_recovery.state = "ready"
                        self._detach_action_cohort_batch_locked(
                            record,
                            terminal_state="committed",
                        )
                        if record.receipt_eviction_id is not None:
                            evicted = self._action_cohort_receipts.pop(
                                record.receipt_eviction_id,
                                None,
                            )
                            if evicted is not None and evicted._published:
                                self._action_cohort_committed_receipts -= 1
                        self._action_cohort_committed_receipts += 1

        if record.exact_recovery is not None:
            return cast(
                ActionCohortPublicationResult,
                self._resume_exact_projection_recovery(receipt, expected_kind="action_cohort"),
            )

        first_failure: BaseException | None = None
        stop_after_base_exception = False
        for projection, outcome in zip(
            record.trusted_projections,
            record.projection_outcomes,
            strict=True,
        ):
            if stop_after_base_exception:
                object.__setattr__(outcome, "_status", "skipped")
                continue
            object.__setattr__(outcome, "_status", "started")
            try:
                identifiers = self._publish_action_cohort_projection(projection)
                frozen_identifiers = tuple(sorted(identifiers.items()))
            except Exception as exc:
                object.__setattr__(outcome, "_error", exc)
                object.__setattr__(outcome, "_status", "failed")
                if first_failure is None:
                    first_failure = exc
            except BaseException as exc:
                object.__setattr__(outcome, "_error", exc)
                object.__setattr__(outcome, "_status", "failed")
                if first_failure is None or isinstance(first_failure, Exception):
                    first_failure = exc
                stop_after_base_exception = True
            else:
                object.__setattr__(outcome, "_identifiers", frozen_identifiers)
                object.__setattr__(outcome, "_status", "succeeded")
        if first_failure is not None:
            try:
                object.__setattr__(first_failure, "action_cohort_receipt", receipt)
                object.__setattr__(first_failure, "action_cohort_result", result)
                first_failure.add_note(
                    "Canonical action cohort committed before sink failure: "
                    f"batch={record.batch_id}, receipt={receipt.receipt_id}"
                )
            except BaseException:
                pass
            raise first_failure
        return result

    def publish_prepared_action_cohort_batch(
        self,
        batch: PreparedActionCohortBatch,
    ) -> ActionCohortPublicationResult:
        """Claim and publish one exact prepared cohort in a single call."""

        with self.claimed_action_cohort(batch) as capability:
            return capability.commit_no_fail()

    def authenticates_action_cohort_publication_receipt(
        self,
        receipt: object,
    ) -> bool:
        """Totally authenticate one exact retained dispatcher receipt object."""

        if type(receipt) is not ActionCohortPublicationReceipt:
            return False
        try:
            with self._action_cohort_lock:
                canonical = self._action_cohort_receipts.get(id(receipt))
                if canonical is not receipt:
                    return False
            if (
                not self._action_cohort_receipt_shape_is_valid(receipt)
                or not receipt._published
                or receipt.dispatcher_id != self._action_cohort_dispatcher_id
            ):
                return False
            expected = self._action_cohort_receipt_integrity(receipt)
            if not hmac.compare_digest(receipt._integrity, expected):
                return False
            with self._action_cohort_lock:
                return (
                    self._action_cohort_receipts.get(id(receipt)) is receipt and receipt._published
                )
        except BaseException:
            return False

    def authenticates_state_neutral_projection_publication_receipt(
        self,
        receipt: object,
    ) -> bool:
        """Totally authenticate one exact retained non-State receipt object."""

        if type(receipt) is not StateNeutralProjectionPublicationReceipt:
            return False
        try:
            with self._action_cohort_lock:
                canonical = self._state_neutral_projection_receipts.get(id(receipt))
                if canonical is not receipt:
                    return False
            if (
                not self._state_neutral_projection_receipt_shape_is_valid(receipt)
                or not receipt._published
                or receipt.dispatcher_id != self._action_cohort_dispatcher_id
                or not hmac.compare_digest(
                    receipt._integrity,
                    self._state_neutral_projection_receipt_integrity(receipt),
                )
            ):
                return False
            with self._action_cohort_lock:
                return (
                    self._state_neutral_projection_receipts.get(id(receipt)) is receipt
                    and receipt._published
                )
        except BaseException:
            return False

    def _exact_projection_recovery_receipt_authenticates(
        self,
        receipt: object,
        *,
        expected_kind: str,
    ) -> bool:
        """Authenticate the public receipt domain without holding recovery locks."""

        if expected_kind == "action_cohort":
            return self.authenticates_action_cohort_publication_receipt(receipt)
        if expected_kind == "state_neutral":
            return self.authenticates_state_neutral_projection_publication_receipt(receipt)
        if expected_kind == "deferred_session":
            if self.authenticates_deferred_session_publication_receipt(receipt):
                return True
            if (
                type(receipt) is not DeferredSessionPublicationReceipt
                or not self._deferred_session_publication_receipt_shape_is_valid(receipt)
            ):
                return False
            expected_integrity = self._deferred_session_publication_receipt_integrity(receipt)
            with self._action_cohort_lock:
                recovery = self._exact_projection_recoveries.get(id(receipt))
                if (
                    recovery is None
                    or recovery.receipt is not receipt
                    or recovery.kind != "deferred_session"
                ):
                    return False
                with self._deferred_session_publication_lock:
                    owner = recovery.owner_record
                    return bool(
                        type(owner) is _PreparedDeferredSessionPublicationRecord
                        and owner.exact_recovery is recovery
                        and owner.publication_receipt is receipt
                        and owner.publication_result is recovery.result
                        and self._deferred_session_publication_pending_receipts.get(id(receipt))
                        is receipt
                        and hmac.compare_digest(receipt._integrity, expected_integrity)
                        and receipt.target_proof_digest
                        == hashlib.sha256(repr(recovery.target_proofs).encode("utf-8")).hexdigest()
                    )
        return False

    def _released_exact_projection_result_authenticates(
        self,
        record: _ExactProjectionRecoveryRecord,
    ) -> bool:
        """Authenticate retained terminal result identity after batch release won the race."""

        receipt = record.receipt
        outcome = record.outcome
        result = record.result
        if record.kind == "deferred_session":
            outcomes = record.outcomes
            owner = record.owner_record
            all_suppressed_terminal = bool(
                type(owner) is _PreparedDeferredSessionPublicationRecord
                and owner.exact_recovery is record
                and owner.all_suppressed
                and owner.prepared_target_proofs is record.target_proofs
                and owner.prepared_identifiers is record.member_identifiers
                and record.target_proofs == ()
                and record.batch.commit_cursor == 0
                and all(member == () for member in record.member_identifiers)
                and all(
                    self._projection_is_exact_warmup_suppressed(prepared._projection)
                    for prepared in owner.dispatches
                )
            )
            positive_target_terminal = bool(
                type(owner) is _PreparedDeferredSessionPublicationRecord
                and owner.exact_recovery is record
                and not owner.all_suppressed
                and record.target_proofs
                and record.target_proofs[-1].row_end == record.batch.commit_cursor
            )
            return bool(
                record.batch.released
                and type(receipt) is DeferredSessionPublicationReceipt
                and type(result) is DeferredSessionPublicationResult
                and result.receipt is receipt
                and result.projections is outcomes
                and result.target_proofs is record.target_proofs
                and result.identifiers is record.member_identifiers
                and receipt.occurrence_ids == record.occurrence_ids
                and receipt.target_proof_digest
                == hashlib.sha256(repr(record.target_proofs).encode("utf-8")).hexdigest()
                and (positive_target_terminal or all_suppressed_terminal)
                and hmac.compare_digest(
                    receipt.member_integrity_digest,
                    record.member_integrity_digest,
                )
                and len(outcomes) == len(record.occurrence_ids)
                and len(record.member_identifiers) == len(record.occurrence_ids)
                and all(
                    type(member_outcome) is ActionCohortProjectionOutcome
                    and member_outcome.occurrence_id == occurrence_id
                    and member_outcome.status == "succeeded"
                    and member_outcome.identifiers == identifiers
                    and member_outcome.error is None
                    for member_outcome, occurrence_id, identifiers in zip(
                        outcomes,
                        record.occurrence_ids,
                        record.member_identifiers,
                        strict=True,
                    )
                )
            )
        if (
            not record.batch.released
            or receipt.occurrence_ids != record.occurrence_ids
            or not hmac.compare_digest(
                receipt.member_integrity_digest,
                record.member_integrity_digest,
            )
            or outcome.occurrence_id not in record.occurrence_ids
            or outcome.status != "succeeded"
            or outcome.identifiers != record.identifiers
            or outcome.error is not None
        ):
            return False
        if record.kind == "action_cohort":
            owner = record.owner_record
            if (
                type(owner) is not _PreparedActionCohortBatchRecord
                or owner.exact_recovery is not record
                or owner.exact_publication_batch is not record.batch
                or owner.exact_prepared_identifiers != record.identifiers
                or (
                    owner.exact_projection_kind.startswith(("ssh_", "rdp_"))
                    and (
                        owner.exact_prepared_row_count != record.batch.commit_cursor
                        or (
                            owner.exact_all_suppressed
                            and (owner.exact_prepared_row_count != 0 or record.identifiers != ())
                        )
                        or (not owner.exact_all_suppressed and owner.exact_prepared_row_count <= 0)
                    )
                )
            ):
                return False
            return bool(
                type(receipt) is ActionCohortPublicationReceipt
                and type(result) is ActionCohortPublicationResult
                and result.receipt is receipt
                and result.projections == (outcome,)
            )
        owner = record.owner_record
        if (
            type(owner) is not _StateNeutralProjectionPublicationRecord
            or owner.publication_receipt is not receipt
            or owner.publication_result is not result
            or owner.exact_publication_batch is not record.batch
            or owner.projection_outcome is not outcome
            or (
                owner.exact_kind == "rdp_disconnect"
                and (
                    owner.prepared_row_count != record.batch.commit_cursor
                    or (
                        owner.exact_all_suppressed
                        and (owner.prepared_row_count != 0 or record.identifiers != ())
                    )
                    or (not owner.exact_all_suppressed and owner.prepared_row_count <= 0)
                )
            )
        ):
            return False
        return bool(
            record.kind == "state_neutral"
            and type(receipt) is StateNeutralProjectionPublicationReceipt
            and type(result) is StateNeutralProjectionPublicationResult
            and result.receipt is receipt
            and result.projection is outcome
        )

    @staticmethod
    def _annotate_exact_projection_failure(
        failure: BaseException,
        record: _ExactProjectionRecoveryRecord,
    ) -> None:
        """Attach the exact retry carrier without replacing a sink's primary failure."""

        try:
            object.__setattr__(failure, "exact_projection_receipt", record.receipt)
            object.__setattr__(failure, "exact_projection_result", record.result)
            if record.kind == "action_cohort":
                object.__setattr__(failure, "action_cohort_receipt", record.receipt)
                object.__setattr__(failure, "action_cohort_result", record.result)
            elif record.kind == "state_neutral":
                object.__setattr__(
                    failure,
                    "state_neutral_projection_receipt",
                    record.receipt,
                )
                object.__setattr__(
                    failure,
                    "state_neutral_projection_result",
                    record.result,
                )
            else:
                object.__setattr__(
                    failure,
                    "deferred_session_publication_receipt",
                    record.receipt,
                )
                object.__setattr__(
                    failure,
                    "deferred_session_publication_result",
                    record.result,
                )
            failure.add_note(
                "Canonical owners committed; resume the dispatcher-retained exact projection"
            )
        except BaseException:
            return

    def _resume_exact_projection_recovery(
        self,
        receipt: object,
        *,
        expected_kind: str,
    ) -> (
        ActionCohortPublicationResult
        | StateNeutralProjectionPublicationResult
        | DeferredSessionPublicationResult
    ):
        """Resume one retained exact batch/cursor with every sink callback lock-free."""

        if expected_kind not in {"action_cohort", "state_neutral", "deferred_session"}:
            raise EventContractError("Exact projection recovery kind is unsupported")
        with self._action_cohort_lock:
            record = self._exact_projection_recoveries.get(id(receipt))
            if record is None or record.receipt is not receipt or record.kind != expected_kind:
                raise EventContractError(
                    "Exact projection receipt is copied, foreign, stale, or already released"
                )
            canonical_pending = bool(
                expected_kind == "deferred_session" and record.state == "canonical_pending"
            )
            pending_owner = record.owner_record if canonical_pending else None
        if canonical_pending:
            if type(pending_owner) is not _PreparedDeferredSessionPublicationRecord:
                raise EventContractError(
                    "Deferred-session canonical recovery lost its bridge owner"
                )
            materialization_receipt = pending_owner.materialization_receipt_shell
            if materialization_receipt is None:
                raise EventContractError(
                    "Deferred-session canonical recovery awaits its materialization receipt"
                )
            return self.publish_prepared_deferred_session_publication_batch(
                pending_owner.carrier,
                materialization_receipt=materialization_receipt,
            )
        if not self._exact_projection_recovery_receipt_authenticates(
            receipt,
            expected_kind=expected_kind,
        ):
            raise EventContractError("Exact projection receipt failed authentication")

        owner_thread = get_ident()
        with self._action_cohort_lock:
            active = self._exact_projection_recoveries.get(id(receipt))
            if active is not record or record.receipt is not receipt:
                raise EventContractError("Exact projection receipt became stale before resume")
            if record.state == "active":
                qualifier = "reentrant" if record.active_thread_id == owner_thread else "concurrent"
                raise EventContractError(f"Exact projection recovery is already {qualifier}")
            resumable_states = (
                {"ready", "owner_pending"} if expected_kind == "deferred_session" else {"ready"}
            )
            if record.state not in resumable_states or record.active_thread_id is not None:
                raise EventContractError("Exact projection recovery is not resumable")
            owner_tail_complete = record.state != "owner_pending"
            record.state = "active"
            record.active_thread_id = owner_thread
            self._exact_projection_active_recoveries += 1

        outcome = record.outcome
        outcomes = record.outcomes if record.kind == "deferred_session" else (outcome,)

        def update_deferred_outcomes(
            *,
            failure: BaseException | None = None,
            release_pending: bool = False,
        ) -> None:
            if record.kind != "deferred_session":
                return
            cursor = record.batch.commit_cursor
            failed_member: int | None = None
            if failure is not None:
                failed_member = next(
                    (
                        proof.member_ordinal
                        for proof in record.target_proofs
                        if proof.row_start <= cursor < proof.row_end
                    ),
                    None,
                )
            for member_ordinal, (member_outcome, identifiers) in enumerate(
                zip(outcomes, record.member_identifiers, strict=True)
            ):
                member_proofs = tuple(
                    proof
                    for proof in record.target_proofs
                    if proof.member_ordinal == member_ordinal
                )
                completed = not member_proofs or all(
                    proof.row_end <= cursor for proof in member_proofs
                )
                if completed:
                    object.__setattr__(member_outcome, "_identifiers", identifiers)
                    object.__setattr__(
                        member_outcome,
                        "_status",
                        "release_pending" if release_pending else "succeeded",
                    )
                    object.__setattr__(
                        member_outcome,
                        "_error",
                        failure if release_pending else None,
                    )
                elif failed_member == member_ordinal:
                    object.__setattr__(member_outcome, "_status", "recoverable")
                    object.__setattr__(member_outcome, "_error", failure)
                else:
                    object.__setattr__(member_outcome, "_status", "pending")
                    object.__setattr__(member_outcome, "_error", None)

        try:
            if record.kind == "deferred_session" and not owner_tail_complete:
                try:
                    self._complete_deferred_session_owner_tail(record)
                except BaseException as failure:
                    self._annotate_exact_projection_failure(failure, record)
                    if self._deferred_session_owner_tail_terminal_authenticates(record):
                        owner_tail_complete = True
                    raise
                owner_tail_complete = True
            if record.batch.released:
                if not self._released_exact_projection_result_authenticates(record):
                    raise EventContractError(
                        "Released exact projection retained a malformed terminal result"
                    )
                if record.kind == "deferred_session":
                    self._complete_deferred_session_exact_recovery(record)
                with self._action_cohort_lock:
                    if self._exact_projection_recoveries.get(id(receipt)) is not record:
                        raise EventContractError(
                            "Released exact projection recovery ownership changed"
                        )
                    self._exact_projection_recoveries.pop(id(receipt))
                    record.state = "released"
                return record.result
            if record.kind == "deferred_session":
                update_deferred_outcomes()
            else:
                object.__setattr__(outcome, "_status", "started")
                object.__setattr__(outcome, "_error", None)
            if record.batch.state not in {"committed", "releasing"}:
                try:
                    record.batch.commit()
                except BaseException as failure:
                    if record.batch.state != "committed":
                        if record.kind == "deferred_session":
                            update_deferred_outcomes(failure=failure)
                        else:
                            object.__setattr__(outcome, "_status", "recoverable")
                            object.__setattr__(outcome, "_error", failure)
                        self._annotate_exact_projection_failure(failure, record)
                        raise
            if record.kind == "deferred_session":
                update_deferred_outcomes()
            else:
                object.__setattr__(outcome, "_identifiers", record.identifiers)
                object.__setattr__(outcome, "_status", "succeeded")
                object.__setattr__(outcome, "_error", None)
            try:
                record.batch.release_no_fail()
            except BaseException as failure:
                if not record.batch.released:
                    if record.kind == "deferred_session":
                        update_deferred_outcomes(
                            failure=failure,
                            release_pending=True,
                        )
                    else:
                        object.__setattr__(outcome, "_status", "release_pending")
                        object.__setattr__(outcome, "_error", failure)
                    self._annotate_exact_projection_failure(failure, record)
                    raise
            if record.kind == "deferred_session":
                self._complete_deferred_session_exact_recovery(record)
            with self._action_cohort_lock:
                if self._exact_projection_recoveries.get(id(receipt)) is not record:
                    raise EventContractError(
                        "Exact projection recovery ownership changed after release"
                    )
                self._exact_projection_recoveries.pop(id(receipt))
                record.state = "released"
            return record.result
        finally:
            with self._action_cohort_lock:
                if record.active_thread_id == owner_thread:
                    record.active_thread_id = None
                    self._exact_projection_active_recoveries -= 1
                    if record.state == "active":
                        record.state = "ready" if owner_tail_complete else "owner_pending"

    def resume_action_cohort_projection(
        self,
        receipt: ActionCohortPublicationReceipt,
    ) -> ActionCohortPublicationResult:
        """Resume the same exact sink batch retained for a State-backed Type-5 cohort."""

        if type(receipt) is not ActionCohortPublicationReceipt:
            raise TypeError("Action-cohort recovery requires its exact receipt type")
        return cast(
            ActionCohortPublicationResult,
            self._resume_exact_projection_recovery(
                receipt,
                expected_kind="action_cohort",
            ),
        )

    def resume_state_neutral_exact_projection(
        self,
        receipt: StateNeutralProjectionPublicationReceipt,
    ) -> StateNeutralProjectionPublicationResult:
        """Resume the same exact sink batch retained for one built-in Type-5 event."""

        if type(receipt) is not StateNeutralProjectionPublicationReceipt:
            raise TypeError("State-neutral recovery requires its exact receipt type")
        return cast(
            StateNeutralProjectionPublicationResult,
            self._resume_exact_projection_recovery(
                receipt,
                expected_kind="state_neutral",
            ),
        )

    def resume_deferred_session_publication(
        self,
        receipt: DeferredSessionPublicationReceipt,
    ) -> DeferredSessionPublicationResult:
        """Resume the dispatcher-retained exact tail for one committed session root."""

        if type(receipt) is not DeferredSessionPublicationReceipt:
            raise TypeError("Deferred-session recovery requires its exact receipt type")
        return cast(
            DeferredSessionPublicationResult,
            self._resume_exact_projection_recovery(
                receipt,
                expected_kind="deferred_session",
            ),
        )

    def drain_exact_projection_recoveries(
        self,
    ) -> tuple[
        ActionCohortPublicationResult
        | StateNeutralProjectionPublicationResult
        | DeferredSessionPublicationResult,
        ...,
    ]:
        """Boundedly retry every retained batch before emitters enter close."""

        with self._action_cohort_lock:
            recoveries = tuple(self._exact_projection_recoveries.values())
        results: list[
            ActionCohortPublicationResult
            | StateNeutralProjectionPublicationResult
            | DeferredSessionPublicationResult
        ] = []
        for recovery in recoveries:
            results.append(
                self._resume_exact_projection_recovery(
                    recovery.receipt,
                    expected_kind=recovery.kind,
                )
            )
        return tuple(results)

    def assert_exact_projection_recoveries_drained(self) -> None:
        """Fail fast before emitter close if exact sink fences remain unresolved."""

        with self._action_cohort_lock:
            unresolved = len(self._exact_projection_recoveries)
            active = self._exact_projection_active_recoveries
        if unresolved or active:
            raise EventContractError(
                "Exact projection recovery must drain before emitter close: "
                f"unresolved={unresolved}, active={active}"
            )

    def exact_projection_recovery_census(self) -> ExactProjectionRecoveryCensus:
        """Return constant-time authority, recovery, and receipt retention counts."""

        authority = self._exact_publication_authority.census()
        with self._action_cohort_lock:
            return ExactProjectionRecoveryCensus(
                unresolved_recoveries=len(self._exact_projection_recoveries),
                reserved_recoveries=self._exact_projection_recovery_reservations,
                active_recoveries=self._exact_projection_active_recoveries,
                recovery_capacity=self._exact_projection_recovery_capacity,
                high_water_recoveries=self._exact_projection_recovery_high_water,
                state_neutral_receipts=self._state_neutral_projection_committed_receipts,
                authority=authority,
            )

    def _cancel_action_cohort_record(
        self,
        record: _PreparedActionCohortBatchRecord,
    ) -> tuple[BaseException, ...]:
        """Attempt every trusted cleanup and return failures without short-circuiting."""

        failures: list[BaseException] = []
        exact_batch = record.exact_publication_batch
        if exact_batch is None:
            record.exact_cleanup_complete = True
        elif not record.exact_cleanup_complete:
            try:
                exact_batch.cancel()
            except BaseException as exc:
                if exact_batch.state == "canceled":
                    record.exact_cleanup_complete = True
                else:
                    failures.append(exc)
            else:
                record.exact_cleanup_complete = True
        if not record.members_cleanup_complete:
            failures.extend(self._consume_action_cohort_members(record))
            if all(record.member_cleanup_status):
                record.members_cleanup_complete = True
        if not record.artifact_cleanup_complete:
            failures.extend(
                self._cancel_action_cohort_artifacts(
                    record.artifact_registry,
                    record.artifact_publications,
                    record.artifact_cleanup_status,
                )
            )
            if all(record.artifact_cleanup_status):
                record.artifact_cleanup_complete = True
        if record.intent_token is None or record.intent_ledger is None:
            record.intent_cleanup_complete = True
        elif not record.intent_cleanup_complete:
            try:
                record.intent_ledger.cancel_batch(record.intent_token)
            except BaseException as exc:
                try:
                    still_active = record.intent_ledger.authenticates_batch_token(
                        record.intent_token,
                        request=record.intent_request,
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.intent_cleanup_complete = True
            else:
                record.intent_cleanup_complete = True
        if not record.audit_cleanup_complete:
            try:
                record.execution_effect_audit.cancel_action_cohort(record.audit_preparation)
            except BaseException as exc:
                try:
                    still_active = (
                        record.execution_effect_audit.authenticates_action_cohort_preparation(
                            record.audit_preparation,
                            root_action_id=record.root_action_id,
                            entries=record.audit_entries,
                            owned_plans=record.owned_effect_plans,
                            published_provenances=record.published_provenances,
                        )
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.audit_cleanup_complete = True
            else:
                record.audit_cleanup_complete = True
        authority = self._lifecycle_authority
        if authority is None:
            record.lifecycle_cleanup_complete = True
        elif not record.lifecycle_cleanup_complete:
            try:
                authority.registry.cancel_action_cohort(record.lifecycle_token)
            except BaseException as exc:
                try:
                    still_active = authority.registry.authenticates_action_cohort_admission_token(
                        record.lifecycle_token,
                        request=record.lifecycle_request,
                        state_publication_token=record.state_plan.publication_token,
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.lifecycle_cleanup_complete = True
            else:
                record.lifecycle_cleanup_complete = True
        if record.source_timing_preparation.committed:
            record.timing_cleanup_complete = True
        elif not record.timing_cleanup_complete:
            try:
                record.source_timing_preparation.cancel()
            except BaseException as exc:
                try:
                    still_active = self.source_timing_planner.authenticates_preparation(
                        record.source_timing_preparation
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    failures.append(exc)
                else:
                    record.timing_cleanup_complete = True
            else:
                record.timing_cleanup_complete = True
        return tuple(failures)

    @staticmethod
    def _add_action_cohort_cleanup_notes(
        primary: BaseException,
        failures: tuple[BaseException, ...],
    ) -> None:
        """Annotate a primary failure without invoking hostile exception formatting."""

        for failure in failures:
            try:
                primary.add_note(
                    "Action-cohort cleanup also failed with "
                    f"{type(failure).__module__}.{type(failure).__qualname__}"
                )
            except BaseException:
                continue

    def cancel_prepared_action_cohort_batch(
        self,
        batch: PreparedActionCohortBatch,
    ) -> bool:
        """Cancel one exact unclaimed batch through its trusted object locator."""

        if type(batch) is not PreparedActionCohortBatch:
            raise TypeError("Action-cohort cancellation requires the exact opaque type")
        with self._action_cohort_lock:
            batch_id = self._action_cohort_batch_locators.get(id(batch))
            record = self._action_cohort_batches.get(batch_id) if batch_id is not None else None
            if record is None or record.carrier_ref() is not batch:
                return False
            if record.state not in {"prepared", "cleanup_pending"}:
                raise EventContractError("Claimed action-cohort batch cannot cancel directly")
        failures = self._finish_action_cohort_batch_cleanup(
            record,
            terminal_state="cancelled",
        )
        if failures:
            error = EventContractError("Action-cohort cancellation cleanup failed")
            self._add_action_cohort_cleanup_notes(error, failures)
            raise error
        return True

    def prune_prepared_action_cohort_batches(self) -> int:
        """Release weak-ownerless unclaimed batches with bounded work."""

        with self._action_cohort_lock:
            preparation_cleanups = tuple(self._action_cohort_prepare_cleanups.values())
            preparation_cleanups = tuple(
                record for record in preparation_cleanups if record.state == "pending"
            )
            records = tuple(
                record
                for record in self._action_cohort_batches.values()
                if record.state in {"prepared", "cleanup_pending"} and record.carrier_ref() is None
            )
        removed = 0
        failures: tuple[BaseException, ...] = ()
        for cleanup_record in preparation_cleanups:
            record_failures = self._finish_action_cohort_preparation_cleanup(cleanup_record)
            if record_failures:
                failures = (*failures, *record_failures)
            else:
                removed += 1
        for record in records:
            record_failures = self._finish_action_cohort_batch_cleanup(
                record,
                terminal_state="pruned",
            )
            if record_failures:
                failures = (*failures, *record_failures)
            else:
                removed += 1
        if failures:
            error = EventContractError("Action-cohort pruning cleanup failed")
            self._add_action_cohort_cleanup_notes(error, failures)
            raise error
        return removed

    def action_cohort_publication_census(self) -> ActionCohortPublicationCensus:
        """Return constant-time dispatcher capability and receipt counts."""

        with self._action_cohort_lock:
            return ActionCohortPublicationCensus(
                prepared_batches=(
                    len(self._action_cohort_batches)
                    - self._action_cohort_claimed_batches
                    + len(self._action_cohort_prepare_cleanups)
                ),
                claimed_batches=self._action_cohort_claimed_batches,
                retained_members=(
                    self._action_cohort_retained_members + len(self._action_cohort_projections)
                ),
                retained_bytes=(
                    self._action_cohort_retained_bytes
                    + self._action_cohort_projection_retained_bytes
                ),
                capability_locators=(
                    len(self._action_cohort_batch_locators)
                    + len(self._action_cohort_projection_locators)
                    + len(self._action_cohort_capability_locators)
                    + len(self._action_cohort_prepare_cleanups)
                ),
                prepared_projections=len(self._action_cohort_projections),
                projection_groups=len(self._action_cohort_projection_groups),
                projection_retained_bytes=self._action_cohort_projection_retained_bytes,
                committed_receipts=self._action_cohort_committed_receipts,
                preparation_capacity=self._action_cohort_preparation_capacity,
                member_capacity=self._action_cohort_member_capacity,
                retained_byte_capacity=self._action_cohort_byte_capacity,
                receipt_capacity=self._action_cohort_receipt_capacity,
            )

    def _deferred_session_publication_batch_integrity(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
        record: _PreparedDeferredSessionPublicationRecord,
    ) -> str:
        """Authenticate one exact signed composition and frozen dispatch sequence."""

        composition = record.composition
        coordinator = record.coordinator
        timing_token = record.source_timing_preparation.binding_token
        exact_batch = record.exact_publication_batch
        exact_token = getattr(exact_batch, "_token", None)
        intent_token = record.intent_token
        expected_intent_receipt = record.expected_intent_receipt
        publication_receipt = record.publication_receipt
        publication_result = record.publication_result
        exact_recovery = record.exact_recovery
        payload = repr(
            (
                "prepared-deferred-session-publication-v2",
                batch._dispatcher_id,
                batch._batch_id,
                batch._occurrence_count,
                id(composition),
                record.composition_token,
                record.physical_transport_id,
                id(coordinator),
                getattr(coordinator, "coordinator_id", None),
                self._lifecycle_ticket_signature(record.root),
                (
                    id(record.source_timing_preparation),
                    type(timing_token).__module__,
                    type(timing_token).__qualname__,
                    getattr(timing_token, "preparation_id", None),
                    getattr(timing_token, "base_state_digest", None),
                    getattr(timing_token, "_integrity", None),
                ),
                tuple(
                    (
                        id(prepared),
                        prepared.occurrence_id,
                        integrity,
                        self._prepared_dispatch_integrity(prepared),
                    )
                    for prepared, integrity in zip(
                        record.dispatches,
                        record.member_integrity_tokens,
                        strict=True,
                    )
                ),
                tuple(id(member_lock) for member_lock in record.member_locks),
                (
                    id(exact_batch) if exact_batch is not None else None,
                    id(exact_token) if exact_token is not None else None,
                    getattr(exact_token, "namespace", None),
                    getattr(exact_token, "ordinal", None),
                    getattr(exact_token, "integrity", None),
                ),
                record.prepared_identifiers,
                record.prepared_target_proofs,
                record.all_suppressed,
                record.occurrence_ids,
                record.member_binary_identity_kinds,
                record.member_digest,
                record.target_proof_digest,
                record.frozen_latest_network_observations_uid,
                record.frozen_latest_network_observations,
                record.frozen_latest_network_plan,
                repr(record.observation_deltas),
                (
                    id(record.intent_ledger) if record.intent_ledger is not None else None,
                    repr(record.intent_request),
                    id(intent_token) if intent_token is not None else None,
                    getattr(intent_token, "ledger_id", None),
                    getattr(intent_token, "preparation_id", None),
                    getattr(intent_token, "plan_digest", None),
                    getattr(intent_token, "_integrity", None),
                ),
                (
                    id(record.intent_claim_context)
                    if record.intent_claim_context is not None
                    else None,
                    id(record.intent_claimed) if record.intent_claimed is not None else None,
                    id(expected_intent_receipt) if expected_intent_receipt is not None else None,
                    getattr(expected_intent_receipt, "ledger_id", None),
                    getattr(expected_intent_receipt, "preparation_id", None),
                    getattr(expected_intent_receipt, "plan_digest", None),
                    getattr(expected_intent_receipt, "_integrity", None),
                ),
                (
                    id(publication_receipt) if publication_receipt is not None else None,
                    getattr(publication_receipt, "dispatcher_id", None),
                    getattr(publication_receipt, "receipt_id", None),
                    getattr(publication_receipt, "publication_token", None),
                    getattr(publication_receipt, "composition_token", None),
                    getattr(publication_receipt, "physical_transport_id", None),
                    getattr(publication_receipt, "occurrence_ids", None),
                    getattr(publication_receipt, "member_integrity_digest", None),
                    getattr(publication_receipt, "target_proof_digest", None),
                    getattr(publication_receipt, "intent_publication_token", None),
                    id(publication_result) if publication_result is not None else None,
                    id(exact_recovery) if exact_recovery is not None else None,
                    id(record.materialization_receipt_shell)
                    if record.materialization_receipt_shell is not None
                    else None,
                    record.materialization_receipt_shell_digest,
                ),
                record.retained_bytes,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _active_deferred_session_publication_batch_locked(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
    ) -> _PreparedDeferredSessionPublicationRecord:
        """Return one exact retained carrier without invoking nested owners."""

        if type(batch) is not PreparedDeferredSessionPublicationBatch:
            raise EventContractError(
                "Deferred-session publication batch must be the exact opaque type"
            )
        if (
            type(batch._dispatcher_id) is not str
            or not batch._dispatcher_id
            or len(batch._dispatcher_id) > _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
            or type(batch._batch_id) is not int
            or batch._batch_id <= 0
            or type(batch._occurrence_count) is not int
            or not 1 <= batch._occurrence_count <= _MAX_DEFERRED_SESSION_PUBLICATION_MEMBERS
            or type(batch._integrity_token) is not str
            or len(batch._integrity_token) != 64
            or type(batch._consumed) is not bool
        ):
            raise EventContractError("Deferred-session publication batch shape is malformed")
        if batch._dispatcher_id != self._deferred_session_publication_dispatcher_id:
            raise EventContractError(
                "Deferred-session publication batch belongs to another dispatcher"
            )
        record = self._deferred_session_publication_batches.get(batch._batch_id)
        if record is None or record.carrier is not batch or batch._consumed:
            raise EventContractError(
                "Deferred-session publication batch is stale or already consumed"
            )
        expected = self._deferred_session_publication_batch_integrity(batch, record)
        if (
            batch._occurrence_count != len(record.dispatches)
            or type(record.all_suppressed) is not bool
            or not hmac.compare_digest(batch._integrity_token, expected)
            or not hmac.compare_digest(record.integrity_token, expected)
        ):
            raise EventContractError(
                "Deferred-session publication batch integrity validation failed"
            )
        return record

    @staticmethod
    def _deferred_session_prepared_projection_shape(
        result: object,
        *,
        member_count: int,
    ) -> tuple[
        tuple[tuple[tuple[str, str], ...], ...],
        tuple[DeferredSessionExactTargetProof, ...],
    ]:
        """Accept only bounded immutable identifiers and target row proofs."""

        if (
            type(result) is not tuple
            or len(result) != 2
            or type(result[0]) is not tuple
            or len(result[0]) != member_count
            or any(
                type(member) is not tuple
                or any(
                    type(item) is not tuple
                    or len(item) != 2
                    or type(item[0]) is not str
                    or type(item[1]) is not str
                    for item in member
                )
                for member in result[0]
            )
            or type(result[1]) is not tuple
            or any(type(proof) is not DeferredSessionExactTargetProof for proof in result[1])
        ):
            raise EventContractError(
                "Deferred-session exact projection returned malformed frozen proof"
            )
        return cast(
            tuple[
                tuple[tuple[tuple[str, str], ...], ...],
                tuple[DeferredSessionExactTargetProof, ...],
            ],
            result,
        )

    def _deferred_session_exact_projection_participants(
        self,
        dispatches: tuple[PreparedDispatch, ...],
    ) -> tuple[LogEmitter, ...]:
        """Return explicitly exact-capable participants or fail before rendering."""

        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.windows import (
            WindowsEventEmitter,
            _supports_windows_exact_projection_publication,
        )
        from evidenceforge.generation.emitters.zeek import ZeekEmitter

        exact_types_by_format: dict[str, type[LogEmitter]] = {
            "ecar": EcarEmitter,
            "windows_event_security": WindowsEventEmitter,
            "zeek_conn": ZeekEmitter,
        }
        participants: list[LogEmitter] = []
        participant_ids: set[int] = set()
        for prepared in dispatches:
            for format_name, emitter in self._exact_projection_targets(prepared._projection):
                emitter_type = type(emitter)
                expected_type = (
                    exact_types_by_format.get(format_name) if type(format_name) is str else None
                )
                marker = (
                    emitter_type.__dict__.get("supports_exact_projection_publication")
                    if expected_type is emitter_type
                    else None
                )
                supported = expected_type is emitter_type and marker is True
                if supported and emitter_type is WindowsEventEmitter:
                    supported = _supports_windows_exact_projection_publication(emitter)
                if not supported:
                    raise EventContractError(
                        f"Deferred-session projection target {format_name!r} lacks exact "
                        "projection publication"
                    )
                if id(emitter) in participant_ids:
                    continue
                participant_ids.add(id(emitter))
                participants.append(emitter)
        return tuple(participants)

    def _deferred_session_exact_target_slices(
        self,
        projection: _PreparedProjection,
    ) -> tuple[tuple[int, str, LogEmitter, _PreparedProjection], ...]:
        """Freeze one render-only projection slice per visible source target."""

        slices: list[tuple[int, str, LogEmitter, _PreparedProjection]] = []
        if projection.mode == "suppressed":
            return ()
        if projection.mode == "legacy":
            for target_ordinal, target in enumerate(projection.legacy_targets):
                if target.occurrence is None:
                    continue
                slices.append(
                    (
                        target_ordinal,
                        target.format_name,
                        target.emitter,
                        _PreparedProjection(
                            mode="legacy",
                            occurrence=projection.occurrence,
                            legacy_targets=(target,),
                        ),
                    )
                )
            return tuple(slices)
        if projection.mode != "compiled":
            raise EventContractError("Deferred-session projection mode is unsupported")
        for target_ordinal, target in enumerate(projection.compiled_targets):
            if self._action_cohort_compiled_projection_status(
                projection.occurrence,
                target,
            ) not in {"visible", "delayed"}:
                continue
            slices.append(
                (
                    target_ordinal,
                    target.format_name,
                    target.emitter,
                    _PreparedProjection(
                        mode="compiled",
                        occurrence=projection.occurrence,
                        compiled_targets=(target,),
                    ),
                )
            )
        return tuple(slices)

    @staticmethod
    def _deferred_session_ecar_order_keys(
        row_facts: tuple[tuple[str, str, int], ...],
    ) -> tuple[int, ...]:
        """Parse exact eCAR source times from authenticated staged bytes."""

        parsed_order_keys: list[int] = []
        for frozen_row, _content_digest, _retained_bytes in row_facts:
            try:
                parsed = json.loads(frozen_row)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise EventContractError(
                    "Deferred-session eCAR exact row is not valid JSON"
                ) from exc
            timestamp_ms = parsed.get("timestamp_ms") if type(parsed) is dict else None
            if type(timestamp_ms) is not int or timestamp_ms < 0:
                raise EventContractError("Deferred-session eCAR exact row lacks source-native time")
            parsed_order_keys.append(timestamp_ms)
        return tuple(parsed_order_keys)

    @staticmethod
    def _deferred_session_windows_ordering_facts(
        row_facts: tuple[tuple[str, str, int], ...],
    ) -> tuple[tuple[int, str, str, int], ...]:
        """Parse exact Windows source facts from authenticated staged bytes."""

        from evidenceforge.generation.emitters.windows import _spool_decode

        parsed_windows_facts: list[tuple[int, str, str, int]] = []
        for frozen_row, content_digest, retained_bytes in row_facts:
            try:
                decoded = _spool_decode(frozen_row)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise EventContractError(
                    "Deferred-session Windows exact row is not a valid candidate"
                ) from exc
            event_id = decoded.get("EventID")
            time_created = decoded.get("TimeCreated")
            if (
                type(event_id) is not int
                or event_id <= 0
                or event_id > (2**31 - 1)
                or type(time_created) is not datetime
                or time_created.tzinfo is None
                or time_created.utcoffset() is None
            ):
                raise EventContractError(
                    "Deferred-session Windows exact row lacks inert EventID/time"
                )
            parsed_windows_facts.append(
                (
                    event_id,
                    time_created.isoformat(),
                    content_digest,
                    retained_bytes,
                )
            )
        return tuple(parsed_windows_facts)

    def _freeze_deferred_session_exact_projection(
        self,
        dispatches: tuple[PreparedDispatch, ...],
    ) -> tuple[
        tuple[tuple[tuple[str, str], ...], ...],
        tuple[DeferredSessionExactTargetProof, ...],
    ]:
        """Render every visible target separately and attest its positive row range."""

        from evidenceforge.generation.emitters.base import (
            exact_publication_staged_row_count,
            exact_publication_staged_row_facts,
        )

        identifiers_by_member: list[tuple[tuple[str, str], ...]] = []
        proofs: list[DeferredSessionExactTargetProof] = []
        for member_ordinal, prepared in enumerate(dispatches):
            member_identifiers: dict[str, str] = {}
            for (
                target_ordinal,
                format_name,
                _emitter,
                target_projection,
            ) in self._deferred_session_exact_target_slices(prepared._projection):
                row_start = exact_publication_staged_row_count()
                member_identifiers.update(self._publish_action_cohort_projection(target_projection))
                row_end = exact_publication_staged_row_count()
                if row_end <= row_start:
                    raise EventContractError(
                        "Deferred-session exact projection target staged no durable row: "
                        f"member={member_ordinal}, target={target_ordinal}, "
                        f"format={format_name!r}"
                    )
                source_order_keys: tuple[int, ...] = ()
                windows_ordering_facts: tuple[tuple[int, str, str, int], ...] = ()
                if format_name == "ecar":
                    source_order_keys = self._deferred_session_ecar_order_keys(
                        exact_publication_staged_row_facts(row_start, row_end)
                    )
                elif format_name == "windows_event_security":
                    windows_ordering_facts = self._deferred_session_windows_ordering_facts(
                        exact_publication_staged_row_facts(row_start, row_end)
                    )
                proofs.append(
                    DeferredSessionExactTargetProof(
                        occurrence_id=prepared.occurrence_id,
                        member_ordinal=member_ordinal,
                        target_ordinal=target_ordinal,
                        format_name=format_name,
                        row_start=row_start,
                        row_end=row_end,
                        source_order_keys=source_order_keys,
                        windows_ordering_facts=windows_ordering_facts,
                    )
                )
            identifiers_by_member.append(tuple(sorted(member_identifiers.items())))
        return tuple(identifiers_by_member), tuple(proofs)

    def _validate_deferred_session_target_proofs(
        self,
        dispatches: tuple[PreparedDispatch, ...],
        proofs: tuple[DeferredSessionExactTargetProof, ...],
        *,
        prepared_row_facts: tuple[tuple[str, str, int], ...],
    ) -> None:
        """Authenticate exact ordered provenance for every visible member target."""

        self._deferred_session_exact_projection_participants(dispatches)
        if type(prepared_row_facts) is not tuple or any(
            type(fact) is not tuple
            or len(fact) != 3
            or type(fact[0]) is not str
            or type(fact[1]) is not str
            or len(fact[1]) != 64
            or any(character not in "0123456789abcdef" for character in fact[1])
            or type(fact[2]) is not int
            or fact[2] <= 0
            or hashlib.sha256(fact[0].encode("utf-8")).hexdigest() != fact[1]
            or len(fact[0].encode("utf-8")) != fact[2]
            for fact in prepared_row_facts
        ):
            raise EventContractError("Deferred-session exact prepared-row facts are malformed")
        prepared_row_count = len(prepared_row_facts)

        expected = tuple(
            (
                member_ordinal,
                target_ordinal,
                format_name,
                prepared.occurrence_id,
                id(emitter),
                (
                    target_projection.legacy_targets[0].occurrence.timestamp
                    if target_projection.mode == "legacy"
                    else target_projection.compiled_targets[0].projected_timestamp
                ),
            )
            for member_ordinal, prepared in enumerate(dispatches)
            for target_ordinal, format_name, emitter, target_projection in (
                self._deferred_session_exact_target_slices(prepared._projection)
            )
        )
        if type(proofs) is not tuple or len(proofs) != len(expected):
            raise EventContractError(
                "Deferred-session exact projection target proof cardinality changed"
            )
        proven_members = {proof.member_ordinal for proof in proofs}
        if proven_members != set(range(len(dispatches))):
            raise EventContractError(
                "Deferred-session publication requires a positive exact target for every member"
            )
        cursor = 0
        for proof, expected_target in zip(proofs, expected, strict=True):
            if (
                type(proof) is not DeferredSessionExactTargetProof
                or (
                    proof.member_ordinal,
                    proof.target_ordinal,
                    proof.format_name,
                    proof.occurrence_id,
                )
                != expected_target[:4]
                or type(proof.row_start) is not int
                or type(proof.row_end) is not int
                or proof.row_start != cursor
                or proof.row_end <= proof.row_start
                or type(proof.source_order_keys) is not tuple
                or any(type(value) is not int or value < 0 for value in proof.source_order_keys)
                or (proof.format_name == "ecar" and len(proof.source_order_keys) != proof.row_count)
                or (proof.format_name != "ecar" and bool(proof.source_order_keys))
                or type(proof.windows_ordering_facts) is not tuple
                or any(
                    type(fact) is not tuple
                    or len(fact) != 4
                    or type(fact[0]) is not int
                    or fact[0] <= 0
                    or fact[0] > (2**31 - 1)
                    or type(fact[1]) is not str
                    or not fact[1]
                    or len(fact[1]) > 64
                    or type(fact[2]) is not str
                    or len(fact[2]) != 64
                    or any(character not in "0123456789abcdef" for character in fact[2])
                    or type(fact[3]) is not int
                    or fact[3] <= 0
                    for fact in proof.windows_ordering_facts
                )
                or (
                    proof.format_name == "windows_event_security"
                    and len(proof.windows_ordering_facts) != proof.row_count
                )
                or (
                    proof.format_name != "windows_event_security"
                    and bool(proof.windows_ordering_facts)
                )
            ):
                raise EventContractError(
                    "Deferred-session exact projection target proof is malformed"
                )
            actual_row_facts = prepared_row_facts[proof.row_start : proof.row_end]
            if proof.format_name == "ecar" and (
                proof.source_order_keys != self._deferred_session_ecar_order_keys(actual_row_facts)
            ):
                raise EventContractError(
                    "Deferred-session eCAR source proof changed from its prepared bytes"
                )
            if proof.format_name == "windows_event_security":
                if proof.windows_ordering_facts != self._deferred_session_windows_ordering_facts(
                    actual_row_facts
                ):
                    raise EventContractError(
                        "Deferred-session Windows source proof changed from its prepared bytes"
                    )
                event = dispatches[proof.member_ordinal]._occurrence
                auth = event.auth
                if event.event_type is EventKind.LOGON:
                    if (
                        auth is None
                        or type(auth.logon_type) is not int
                        or auth.logon_type != 10
                        or auth.result != "success"
                        or type(auth.elevated) is not bool
                        or type(auth.emit_special_privileges) is not bool
                    ):
                        raise EventContractError(
                            "Deferred-session Windows exact target is not an RDP logon"
                        )
                    expected_event_ids = (
                        (4624, 4672) if auth.elevated and auth.emit_special_privileges else (4624,)
                    )
                elif event.event_type in {
                    EventKind.PROCESS_CREATE,
                    EventKind.SYSTEM_PROCESS_CREATE,
                }:
                    if event.process is None or auth is None:
                        raise EventContractError(
                            "Deferred-session Windows process target lost canonical context"
                        )
                    expected_event_ids = (4688,)
                elif event.event_type is EventKind.RDP_RECONNECT:
                    expected_event_ids = (4778,)
                elif event.event_type is EventKind.RDP_DISCONNECT:
                    expected_event_ids = (4779,)
                elif event.event_type is EventKind.LOGOFF:
                    expected_event_ids = (4634,)
                else:
                    raise EventContractError(
                        "Deferred-session Windows exact target has an unsupported event kind"
                    )
                if tuple(fact[0] for fact in proof.windows_ordering_facts) != expected_event_ids:
                    raise EventContractError(
                        "Deferred-session Windows exact target changed its EventID sequence"
                    )
                parsed_windows_times: list[datetime] = []
                for _event_id, raw_time, _digest, _retained_bytes in proof.windows_ordering_facts:
                    try:
                        parsed_time = datetime.fromisoformat(raw_time)
                    except ValueError as exc:
                        raise EventContractError(
                            "Deferred-session Windows exact target has malformed TimeCreated"
                        ) from exc
                    if (
                        parsed_time.tzinfo is None
                        or parsed_time.utcoffset() is None
                        or parsed_time.isoformat() != raw_time
                    ):
                        raise EventContractError(
                            "Deferred-session Windows exact target has noncanonical TimeCreated"
                        )
                    parsed_windows_times.append(parsed_time)
                if any(
                    parsed_windows_times[index] <= parsed_windows_times[index - 1]
                    for index in range(1, len(parsed_windows_times))
                ):
                    raise EventContractError(
                        "Deferred-session Windows exact rows are not strictly ordered"
                    )
            cursor = proof.row_end
        if cursor != prepared_row_count:
            raise EventContractError("Deferred-session exact projection row proof is incomplete")
        transport_targets = tuple(
            projected_timestamp
            for (
                member_ordinal,
                _target_ordinal,
                format_name,
                _occurrence_id,
                emitter_id,
                projected_timestamp,
            ) in expected
            if member_ordinal == 0
        )
        if any(member_ordinal > 0 for member_ordinal, *_rest in expected) and not (
            transport_targets
        ):
            raise EventContractError(
                "Deferred-session visible dependents require exact transport evidence"
            )
        for (
            member_ordinal,
            _target_ordinal,
            _format_name,
            _occurrence_id,
            _emitter_id,
            projected_timestamp,
        ) in expected:
            if member_ordinal == 0:
                continue
            if (
                type(projected_timestamp) is not datetime
                or any(type(value) is not datetime for value in transport_targets)
                or any(projected_timestamp <= value for value in transport_targets)
            ):
                raise EventContractError(
                    "Deferred-session shared source timing does not place transport "
                    "strictly before its dependent"
                )
        transport_ecar_keys = tuple(
            value
            for proof in proofs
            if proof.member_ordinal == 0 and proof.format_name == "ecar"
            for value in proof.source_order_keys
        )
        for proof in proofs:
            if proof.member_ordinal == 0 or proof.format_name != "ecar":
                continue
            if not transport_ecar_keys or min(proof.source_order_keys) <= max(transport_ecar_keys):
                raise EventContractError(
                    "Deferred-session eCAR source-native ordering does not place FLOW "
                    "before its dependent"
                )
        transport_source_times = (
            tuple(
                datetime.fromtimestamp(
                    value / 1_000,
                    tz=UTC,
                )
                for value in transport_ecar_keys
            )
            if transport_ecar_keys
            else cast(tuple[datetime, ...], transport_targets)
        )
        for proof in proofs:
            if proof.member_ordinal == 0 or proof.format_name != "windows_event_security":
                continue
            windows_times = tuple(
                datetime.fromisoformat(fact[1]) for fact in proof.windows_ordering_facts
            )
            if (
                not transport_source_times
                or not windows_times
                or min(windows_times) <= max(transport_source_times)
            ):
                raise EventContractError(
                    "Deferred-session Windows source-native ordering does not place transport "
                    "before its dependent"
                )

    def _projection_is_exact_warmup_suppressed(
        self,
        projection: _PreparedProjection,
    ) -> bool:
        """Return whether one member has the exact canonical warm-up suppression shape."""

        return bool(
            self.output_start_time is not None
            and self._is_suppressed(projection.occurrence.timestamp)
            and projection.mode == "suppressed"
            and projection.initial_statuses == (("all", "out_of_window"),)
            and projection.legacy_targets == ()
            and projection.compiled_targets == ()
        )

    def _validate_deferred_session_all_suppressed_projection(
        self,
        dispatches: tuple[PreparedDispatch, ...],
        identifiers: tuple[tuple[tuple[str, str], ...], ...],
        proofs: tuple[DeferredSessionExactTargetProof, ...],
        *,
        prepared_row_facts: tuple[tuple[str, str, int], ...],
    ) -> None:
        """Authenticate the sole zero-row exception for a fully suppressed warm-up cohort."""

        if (
            type(dispatches) is not tuple
            or not dispatches
            or not all(
                self._projection_is_exact_warmup_suppressed(prepared._projection)
                for prepared in dispatches
            )
            or type(identifiers) is not tuple
            or len(identifiers) != len(dispatches)
            or any(member != () for member in identifiers)
            or proofs != ()
            or prepared_row_facts != ()
            or self._deferred_session_exact_projection_participants(dispatches) != ()
        ):
            raise EventContractError(
                "Deferred-session all-suppressed projection changed its zero-row warm-up shape"
            )

    @staticmethod
    def _deferred_session_allowed_state_members(root: object) -> tuple[object, ...]:
        """Return exact session/process/active-session members of one root."""

        state_plan = getattr(root, "state_plan", None)
        batch = getattr(state_plan, "batch", None)
        if batch is None:
            return ()
        return (
            *((batch.session,) if batch.session is not None else ()),
            *batch.processes,
            *(
                (state_plan.existing_session_patch,)
                if state_plan.existing_session_patch is not None
                else ()
            ),
        )

    def _deferred_session_intent_request(
        self,
        dispatches: tuple[PreparedDispatch, ...],
        observation_deltas: tuple[tuple[_ActionCohortObservationDelta, ...], ...],
    ) -> IntentExecutionBatchRequest | None:
        """Prepare exact occurrence/observation ledger deltas for every member."""

        if self.intent_execution_ledger is None:
            return None
        from evidenceforge.generation.intent_ledger import (
            IntentExecutionBatchRequest,
            IntentObservationDelta,
            IntentOccurrenceDelta,
        )

        deltas: list[IntentOccurrenceDelta | IntentObservationDelta] = []
        for prepared, member_observations in zip(
            dispatches,
            observation_deltas,
            strict=True,
        ):
            intent_id = prepared._authored_intent_id
            if intent_id is None:
                continue
            occurrence_key = prepared._occurrence.occurrence_key
            if type(occurrence_key) is not SemanticOccurrenceKey:
                raise EventContractError(
                    "Deferred-session authored member lost occurrence identity"
                )
            deltas.append(
                IntentOccurrenceDelta(
                    intent_id,
                    occurrence_key,
                    prepared._occurrence.timestamp,
                )
            )
            deltas.extend(
                IntentObservationDelta(
                    intent_id,
                    delta.source,
                    delta.status,
                    delta.timestamp,
                )
                for delta in member_observations
            )
        return IntentExecutionBatchRequest(tuple(deltas)) if deltas else None

    def _detach_deferred_session_publication_batch_locked(
        self,
        record: _PreparedDeferredSessionPublicationRecord,
        *,
        terminal_state: str,
    ) -> None:
        """Release dispatcher/member ownership without invoking source callbacks."""

        if self._deferred_session_publication_batches.get(record.batch_id) is record:
            self._deferred_session_publication_batches.pop(record.batch_id)
            self._deferred_session_publication_locators.pop(id(record.carrier), None)
            if record.precommit is not None:
                self._deferred_session_publication_precommit_locators.pop(
                    id(record.precommit),
                    None,
                )
            self._deferred_session_publication_retained_members -= len(record.dispatches)
            self._deferred_session_publication_retained_bytes -= record.retained_bytes
            if record.recovery_capacity_reserved:
                self._exact_projection_recovery_reservations -= 1
                record.recovery_capacity_reserved = False
            if record.receipt_capacity_reserved:
                self._deferred_session_publication_receipt_reservations -= 1
                record.receipt_capacity_reserved = False
            if record.receipt_eviction_id is not None:
                self._deferred_session_publication_receipt_eviction_reservations.discard(
                    record.receipt_eviction_id
                )
                record.receipt_eviction_id = None
        for prepared, member_lock in zip(
            record.dispatches,
            record.member_locks,
            strict=True,
        ):
            with cast(AbstractContextManager[object], member_lock):
                prepared._deferred_session_publication_batch_id = None
        record.state = terminal_state
        record.active_thread_id = None
        record.carrier._consumed = True

    def prepare_deferred_session_publication_batch(
        self,
        composition: object,
        coordinator: object,
    ) -> PreparedDeferredSessionPublicationBatch:
        """Claim and exact-freeze one authenticated SSH/RDP projection sequence."""

        from evidenceforge.generation.deferred_session_composition import (
            DeferredSessionComposition,
            DeferredSessionCompositionCoordinator,
            DeferredSessionKind,
        )
        from evidenceforge.generation.state_manager import (
            ConnectionExistingSessionPatch,
            ProcessMaterializationPlan,
            SessionMaterializationPlan,
        )

        if type(composition) is not DeferredSessionComposition:
            raise TypeError("Deferred-session publication requires an exact signed composition")
        if type(coordinator) is not DeferredSessionCompositionCoordinator:
            raise TypeError(
                "Deferred-session publication requires an exact composition coordinator"
            )
        if not coordinator.authenticates(composition):
            raise EventContractError("Deferred-session composition failed authentication")
        root = composition.prepared_root
        timing_preparation = composition.source_timing_preparation
        dispatches = composition.publication_order
        if (
            type(dispatches) is not tuple
            or len(dispatches) < 2
            or len(dispatches) > _MAX_DEFERRED_SESSION_PUBLICATION_MEMBERS
        ):
            raise EventContractError(
                "Deferred-session publication has unsupported ordered cardinality"
            )
        allowed_state_members = self._deferred_session_allowed_state_members(root)
        member_locks = tuple(prepared._lock for prepared in dispatches)
        if len({id(member_lock) for member_lock in member_locks}) != len(member_locks):
            raise EventContractError(
                "Deferred-session publication members must have unique exact locks"
            )
        occurrence_ids: set[str] = set()
        for ordinal, prepared in enumerate(dispatches):
            if type(prepared) is not PreparedDispatch:
                raise TypeError("Deferred-session publication contains a non-dispatch member")
            expected_intent = (
                PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT
                if ordinal == 0
                else PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT
            )
            if (
                prepared._state_intent is not expected_intent
                or prepared._source_timing_preparation is not timing_preparation
                or prepared._artifact_publications
                or prepared._projection.mode == "deferred"
                or prepared._action_cohort_batch_id is not None
                or prepared._network_dependent_batch_id is not None
                or prepared._deferred_session_publication_batch_id is not None
                or prepared.occurrence_id in occurrence_ids
            ):
                raise EventContractError(
                    "Deferred-session publication member changed intent, timing, or ordering"
                )
            if (
                prepared._occurrence.file is not None
                or prepared._occurrence.registry is not None
                or prepared._occurrence.image_load is not None
                or prepared._occurrence.effect_provenance is not None
            ):
                raise EventContractError(
                    "Deferred-session publication cannot carry an unowned effect occurrence"
                )
            if ordinal == 0:
                if (
                    prepared is not composition.transport_dispatch
                    or prepared._lifecycle_ticket is not root
                ):
                    raise EventContractError(
                        "Deferred-session publication lost its exact transport root"
                    )
            elif not any(prepared._lifecycle_ticket is member for member in allowed_state_members):
                raise EventContractError(
                    "Deferred-session dependent is outside the root State batch"
                )
            if ordinal > 0:
                dependent_event = prepared._occurrence
                dependent_plan = prepared._lifecycle_ticket
                if type(dependent_plan) is SessionMaterializationPlan:
                    session_identity = dependent_plan.identity
                    auth = dependent_event.auth
                    allowed_event_kinds = (
                        {EventKind.LOGON, EventKind.SSH_SESSION, EventKind.SYSLOG}
                        if composition.kind is DeferredSessionKind.SSH
                        else {EventKind.LOGON}
                    )
                    target_host = (
                        dependent_event.src_host
                        if dependent_event.event_type is EventKind.SYSLOG
                        else dependent_event.dst_host
                    )
                    if (
                        target_host is None
                        or target_host.ip != root.transaction.dst_ip
                        or target_host.hostname != session_identity.hostname
                    ):
                        raise EventContractError(
                            "Deferred-session dependent is not projected on its exact State target"
                        )
                    if (
                        dependent_event.event_type not in allowed_event_kinds
                        or auth is None
                        or auth.result != "success"
                        or auth.username != session_identity.principal
                        or auth.logon_id != session_identity.logon_id
                        or auth.session_id != session_identity.session_id
                        or auth.logon_type != 10
                        or auth.source_ip != root.transaction.src_ip
                        or auth.source_port != root.transaction.src_port
                        or session_identity.session_kind != composition.kind.value
                    ):
                        raise EventContractError(
                            "Deferred-session authentication dependent does not match its "
                            "protocol, State session, and transport tuple"
                        )
                elif type(dependent_plan) is ProcessMaterializationPlan:
                    process_identity = dependent_plan.identity
                    process = dependent_event.process
                    target_host = dependent_event.src_host
                    endpoint_ips: list[str] = []
                    state_plan = root.state_plan
                    source_names = {
                        state_plan._source_system,
                        state_plan._source_hostname,
                    }
                    if (
                        target_host is not None
                        and process_identity.hostname in source_names
                        and target_host.hostname == process_identity.hostname
                        and (
                            not state_plan._source_hostname
                            or state_plan._source_hostname
                            in {target_host.hostname, target_host.fqdn}
                        )
                    ):
                        endpoint_ips.append(root.transaction.src_ip)
                    if (
                        target_host is not None
                        and target_host.hostname == process_identity.hostname
                        and state_plan._hostname in {target_host.hostname, target_host.fqdn}
                    ):
                        endpoint_ips.append(root.transaction.dst_ip)
                    if (
                        target_host is None
                        or target_host.hostname != process_identity.hostname
                        or len(endpoint_ips) != 1
                        or target_host.ip != endpoint_ips[0]
                    ):
                        raise EventContractError(
                            "Deferred-session dependent is not projected on its exact State target"
                        )
                    if (
                        dependent_event.event_type
                        not in {EventKind.PROCESS_CREATE, EventKind.SYSTEM_PROCESS_CREATE}
                        or process is None
                        or process.pid != process_identity.pid
                        or process.parent_pid != process_identity.parent_pid
                        or process.image != process_identity.image
                        or process.command_line != process_identity.command_line
                        or process.username != process_identity.principal
                        or process.logon_id != process_identity.logon_id
                        or process.integrity_level != dependent_plan.integrity_level
                        or process.start_time != process_identity.started_at
                    ):
                        raise EventContractError(
                            "Deferred-session process dependent does not match its exact "
                            "root-owned process"
                        )
                elif type(dependent_plan) is ConnectionExistingSessionPatch:
                    session_identity = dependent_plan.after.identity
                    auth = dependent_event.auth
                    target_host = dependent_event.dst_host
                    if (
                        composition.kind is not DeferredSessionKind.RDP
                        or dependent_plan.lifecycle_disposition.value != "existing"
                        or dependent_event.event_type is not EventKind.RDP_RECONNECT
                        or target_host is None
                        or target_host.ip != root.transaction.dst_ip
                        or target_host.hostname != session_identity.hostname
                        or auth is None
                        or auth.result != "success"
                        or auth.username != session_identity.principal
                        or auth.logon_id != session_identity.logon_id
                        or auth.session_id != session_identity.session_id
                        or auth.logon_type != 10
                        or auth.source_ip != root.transaction.src_ip
                        or auth.source_port != root.transaction.src_port
                        or session_identity.session_kind != "rdp"
                    ):
                        raise EventContractError(
                            "Deferred RDP reconnect does not match its exact active session"
                        )
                else:
                    raise EventContractError(
                        "Deferred-session dependent has an unsupported State owner"
                    )
            if prepared._binary_identity_kind and prepared._lifecycle_ticket not in (
                *getattr(getattr(root.state_plan, "batch", None), "processes", ()),
            ):
                raise EventContractError(
                    "Deferred-session binary projection lacks an exact root-owned process"
                )
            occurrence_ids.add(prepared.occurrence_id)
            self.validate_prepared(prepared)
        if not coordinator.authenticates(composition):
            raise EventContractError(
                "Deferred-session composition changed during dispatcher validation"
            )
        all_suppressed = all(
            self._projection_is_exact_warmup_suppressed(prepared._projection)
            for prepared in dispatches
        )

        retained_bytes = len(
            repr(
                (
                    composition.publication_token,
                    self._lifecycle_ticket_signature(root),
                    tuple(
                        (
                            prepared.occurrence_id,
                            prepared._integrity_token,
                            self._prepared_projection_signature(prepared._projection),
                        )
                        for prepared in dispatches
                    ),
                )
            ).encode("utf-8")
        )
        with self._deferred_session_publication_lock:
            if (
                len(self._deferred_session_publication_batches)
                >= self._action_cohort_preparation_capacity
            ):
                raise StateError("Deferred-session publication preparation capacity is exhausted")
            if (
                self._deferred_session_publication_retained_members + len(dispatches)
                > self._action_cohort_member_capacity
            ):
                raise StateError("Deferred-session publication member capacity is exhausted")
            if (
                self._deferred_session_publication_retained_bytes + retained_bytes
                > self._action_cohort_byte_capacity
            ):
                raise StateError("Deferred-session publication retained-byte capacity is exhausted")
            batch_id = self._next_deferred_session_publication_batch_id
            self._next_deferred_session_publication_batch_id += 1
            carrier = PreparedDeferredSessionPublicationBatch(
                dispatcher_id=self._deferred_session_publication_dispatcher_id,
                batch_id=batch_id,
                occurrence_count=len(dispatches),
            )
            record = _PreparedDeferredSessionPublicationRecord(
                batch_id=batch_id,
                carrier=carrier,
                composition=composition,
                coordinator=coordinator,
                composition_token=composition.publication_token,
                physical_transport_id=composition.physical_transport_id,
                root=root,
                source_timing_preparation=timing_preparation,
                dispatches=dispatches,
                member_locks=member_locks,
                member_integrity_tokens=tuple(prepared._integrity_token for prepared in dispatches),
                occurrence_ids=tuple(prepared.occurrence_id for prepared in dispatches),
                member_binary_identity_kinds=tuple(
                    prepared._binary_identity_kind for prepared in dispatches
                ),
                all_suppressed=all_suppressed,
                retained_bytes=retained_bytes,
                integrity_token="",
                state="freezing",
                active_thread_id=get_ident(),
            )
            claimed: list[PreparedDispatch] = []
            try:
                with ExitStack() as retained_locks:
                    for member_lock in sorted(member_locks, key=id):
                        retained_locks.enter_context(
                            cast(AbstractContextManager[object], member_lock)
                        )
                    for prepared, member_lock in zip(
                        dispatches,
                        member_locks,
                        strict=True,
                    ):
                        if (
                            prepared._lock is not member_lock
                            or prepared._consumed
                            or prepared._action_cohort_batch_id is not None
                            or prepared._network_dependent_batch_id is not None
                            or prepared._deferred_session_publication_batch_id is not None
                        ):
                            raise EventContractError(
                                "Deferred-session dispatch is already claimed or published"
                            )
                        prepared._deferred_session_publication_batch_id = batch_id
                        claimed.append(prepared)
                integrity = self._deferred_session_publication_batch_integrity(
                    carrier,
                    record,
                )
                carrier._integrity_token = integrity
                record.integrity_token = integrity
                self._deferred_session_publication_batches[batch_id] = record
                self._deferred_session_publication_locators[id(carrier)] = batch_id
                self._deferred_session_publication_retained_members += len(dispatches)
                self._deferred_session_publication_retained_bytes += retained_bytes
            except BaseException:
                for prepared, member_lock in zip(
                    dispatches,
                    member_locks,
                    strict=True,
                ):
                    if prepared not in claimed:
                        continue
                    with cast(AbstractContextManager[object], member_lock):
                        if prepared._deferred_session_publication_batch_id == batch_id:
                            prepared._deferred_session_publication_batch_id = None
                carrier._consumed = True
                raise

        exact_batch: ExactPublicationBatch | None = None
        intent_ledger: IntentExecutionLedger | None = None
        intent_token: IntentExecutionBatchToken | None = None
        try:
            participants = self._deferred_session_exact_projection_participants(dispatches)
            exact_batch = self._exact_publication_authority.issue_batch()
            exact_batch.reserve_participants(cast(tuple[object, ...], participants))
            prepared_identifiers, prepared_target_proofs = (
                self._deferred_session_prepared_projection_shape(
                    exact_batch.prepare(
                        lambda: self._freeze_deferred_session_exact_projection(dispatches)
                    ),
                    member_count=len(dispatches),
                )
            )
            prepared_row_facts = exact_batch._prepared_row_facts()
            if all_suppressed:
                self._validate_deferred_session_all_suppressed_projection(
                    dispatches,
                    prepared_identifiers,
                    prepared_target_proofs,
                    prepared_row_facts=prepared_row_facts,
                )
            else:
                self._validate_deferred_session_target_proofs(
                    dispatches,
                    prepared_target_proofs,
                    prepared_row_facts=prepared_row_facts,
                )
            observation_deltas_by_member = tuple(
                self._action_cohort_projection_observation_deltas(prepared._projection)
                for prepared in dispatches
            )
            observation_deltas = tuple(
                delta for member in observation_deltas_by_member for delta in member
            )
            intent_request = self._deferred_session_intent_request(
                dispatches,
                observation_deltas_by_member,
            )
            if intent_request is not None:
                intent_ledger = self.intent_execution_ledger
                if intent_ledger is None:  # pragma: no cover - owner checked by helper
                    raise EventContractError(
                        "Deferred-session authored members lost their intent ledger"
                    )
                intent_token = intent_ledger.prepare_batch(intent_request)
            member_digest = hashlib.sha256(
                repr(
                    tuple(
                        (
                            occurrence_id,
                            integrity,
                            identifiers,
                            tuple(
                                proof
                                for proof in prepared_target_proofs
                                if proof.member_ordinal == member_ordinal
                            ),
                        )
                        for member_ordinal, (
                            occurrence_id,
                            integrity,
                            identifiers,
                        ) in enumerate(
                            zip(
                                record.occurrence_ids,
                                record.member_integrity_tokens,
                                prepared_identifiers,
                                strict=True,
                            )
                        )
                    )
                ).encode("utf-8")
            ).hexdigest()
            target_proof_digest = hashlib.sha256(
                repr(prepared_target_proofs).encode("utf-8")
            ).hexdigest()
            transport_occurrence = dispatches[0]._projection.occurrence
            frozen_latest_network_observations_uid = ""
            frozen_latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
            frozen_latest_network_plan: NetworkTransactionPlan | None = None
            if (
                transport_occurrence.network is not None
                and self._publishes_network_sensor_observations(transport_occurrence)
            ):
                frozen_latest_network_observations_uid = transport_occurrence.network.zeek_uid
                frozen_latest_network_observations = deepcopy(
                    transport_occurrence.network_observations
                )
                frozen_latest_network_plan = deepcopy(transport_occurrence.network)
            additional_retained_bytes = len(
                repr(
                    (
                        prepared_identifiers,
                        prepared_target_proofs,
                        member_digest,
                        target_proof_digest,
                        frozen_latest_network_observations_uid,
                        frozen_latest_network_observations,
                        frozen_latest_network_plan,
                        observation_deltas,
                        intent_request,
                        (
                            getattr(intent_token, "ledger_id", None),
                            getattr(intent_token, "preparation_id", None),
                            getattr(intent_token, "plan_digest", None),
                            getattr(intent_token, "_integrity", None),
                        ),
                    )
                ).encode("utf-8")
            )
            with self._deferred_session_publication_lock:
                if self._active_deferred_session_publication_batch_locked(carrier) is not record:
                    raise EventContractError(
                        "Deferred-session publication ownership changed during exact preflight"
                    )
                if (
                    self._deferred_session_publication_retained_bytes + additional_retained_bytes
                    > self._action_cohort_byte_capacity
                ):
                    raise StateError(
                        "Deferred-session publication retained-byte capacity is exhausted"
                    )
                record.exact_publication_batch = exact_batch
                record.prepared_identifiers = prepared_identifiers
                record.prepared_target_proofs = prepared_target_proofs
                record.member_digest = member_digest
                record.target_proof_digest = target_proof_digest
                record.frozen_latest_network_observations_uid = (
                    frozen_latest_network_observations_uid
                )
                record.frozen_latest_network_observations = frozen_latest_network_observations
                record.frozen_latest_network_plan = frozen_latest_network_plan
                record.observation_deltas = observation_deltas
                record.intent_ledger = intent_ledger
                record.intent_request = intent_request
                record.intent_token = intent_token
                record.retained_bytes += additional_retained_bytes
                self._deferred_session_publication_retained_bytes += additional_retained_bytes
                integrity = self._deferred_session_publication_batch_integrity(
                    carrier,
                    record,
                )
                carrier._integrity_token = integrity
                record.integrity_token = integrity
                record.state = "prepared"
                record.active_thread_id = None
            return carrier
        except BaseException as primary:
            cleanup_incomplete = False
            if intent_ledger is not None and intent_token is not None:
                try:
                    if intent_ledger.authenticates_batch_token(
                        intent_token,
                        request=intent_request,
                    ):
                        intent_ledger.cancel_batch(intent_token)
                except BaseException as cleanup_error:
                    primary.add_note(
                        "Deferred-session intent cleanup also failed with "
                        f"{type(cleanup_error).__module__}.{type(cleanup_error).__qualname__}"
                    )
                    try:
                        cleanup_incomplete = cleanup_incomplete or (
                            intent_ledger.authenticates_batch_token(
                                intent_token,
                                request=intent_request,
                            )
                        )
                    except BaseException:
                        cleanup_incomplete = True
            if exact_batch is not None and exact_batch.state in {"issued", "ready"}:
                try:
                    exact_batch.cancel()
                except BaseException as cleanup_error:
                    primary.add_note(
                        "Deferred-session exact preflight cleanup also failed with "
                        f"{type(cleanup_error).__module__}.{type(cleanup_error).__qualname__}"
                    )
                    cleanup_incomplete = cleanup_incomplete or exact_batch.state != "canceled"
            with self._deferred_session_publication_lock:
                if self._deferred_session_publication_batches.get(record.batch_id) is record:
                    if cleanup_incomplete:
                        record.exact_publication_batch = exact_batch
                        record.intent_ledger = intent_ledger
                        record.intent_request = intent_request
                        record.intent_token = intent_token
                        record.state = "cleanup_pending"
                        record.active_thread_id = None
                        integrity = self._deferred_session_publication_batch_integrity(
                            carrier,
                            record,
                        )
                        carrier._integrity_token = integrity
                        record.integrity_token = integrity
                        try:
                            object.__setattr__(
                                primary,
                                "deferred_session_publication_batch",
                                carrier,
                            )
                        except BaseException:
                            pass
                    else:
                        self._detach_deferred_session_publication_batch_locked(
                            record,
                            terminal_state="failed",
                        )
            raise

    def _build_deferred_session_recovery_shell(
        self,
        record: _PreparedDeferredSessionPublicationRecord,
    ) -> tuple[
        DeferredSessionPublicationReceipt,
        DeferredSessionPublicationResult,
        _ExactProjectionRecoveryRecord,
    ]:
        """Preallocate the exact postcanonical owner before State can commit."""

        exact_batch = record.exact_publication_batch
        if exact_batch is None:
            raise EventContractError(
                "Deferred-session recovery shell requires its exact source batch"
            )
        intent_publication_token = (
            record.expected_intent_receipt.publication_token
            if record.expected_intent_receipt is not None
            else ""
        )
        receipt = DeferredSessionPublicationReceipt(
            dispatcher_id=self._deferred_session_publication_dispatcher_id,
            receipt_id=secrets.token_hex(16),
            publication_token=secrets.token_hex(32),
            composition_token=record.composition_token,
            physical_transport_id=record.physical_transport_id,
            occurrence_ids=record.occurrence_ids,
            member_integrity_digest=record.member_digest,
            target_proof_digest=record.target_proof_digest,
            materialization_receipt_token="",
            intent_publication_token=intent_publication_token,
        )
        outcomes = tuple(
            ActionCohortProjectionOutcome(occurrence_id) for occurrence_id in record.occurrence_ids
        )
        result = DeferredSessionPublicationResult(
            receipt=receipt,
            materialization_receipt=None,
            identifiers=record.prepared_identifiers,
            projections=outcomes,
            target_proofs=record.prepared_target_proofs,
        )
        recovery = _ExactProjectionRecoveryRecord(
            kind="deferred_session",
            receipt=receipt,
            result=result,
            batch=exact_batch,
            outcome=outcomes[0],
            occurrence_ids=record.occurrence_ids,
            member_integrity_digest=record.member_digest,
            identifiers=self._flatten_deferred_session_identifiers(record.prepared_identifiers),
            outcomes=outcomes,
            member_identifiers=record.prepared_identifiers,
            target_proofs=record.prepared_target_proofs,
            owner_record=record,
            state="prepared",
        )
        return receipt, result, recovery

    def authenticates_prepared_deferred_session_publication_batch(
        self,
        batch: object,
        *,
        composition: object | None = None,
        coordinator: object | None = None,
    ) -> bool:
        """Authenticate every nested owner at the final precanonical barrier."""

        from evidenceforge.generation.intent_ledger import IntentExecutionBatchReceipt

        if type(batch) is not PreparedDeferredSessionPublicationBatch:
            return False
        owner_thread = get_ident()
        try:
            with self._deferred_session_publication_lock:
                record = self._active_deferred_session_publication_batch_locked(batch)
                if (composition is not None and record.composition is not composition) or (
                    coordinator is not None and record.coordinator is not coordinator
                ):
                    return False
                if record.state not in {"prepared", "precommit_authenticated"}:
                    return False
                if record.active_thread_id is not None:
                    return False
                prior_state = record.state
                record.state = "authenticating"
                record.active_thread_id = owner_thread
            composition = record.composition
            coordinator = record.coordinator
            if not coordinator.authenticates(composition):
                raise EventContractError("Deferred-session composition failed final authentication")
            if (
                composition.prepared_root is not record.root
                or composition.source_timing_preparation is not record.source_timing_preparation
                or composition.publication_order != record.dispatches
            ):
                raise EventContractError(
                    "Deferred-session composition changed its retained inner owners"
                )
            exact_batch = record.exact_publication_batch
            if exact_batch is None or exact_batch.state != "ready":
                raise EventContractError("Deferred-session exact source projection is not ready")
            exact_batch._require_authority()
            prepared_row_facts = exact_batch._prepared_row_facts()
            if record.all_suppressed:
                self._validate_deferred_session_all_suppressed_projection(
                    record.dispatches,
                    record.prepared_identifiers,
                    record.prepared_target_proofs,
                    prepared_row_facts=prepared_row_facts,
                )
            else:
                self._validate_deferred_session_target_proofs(
                    record.dispatches,
                    record.prepared_target_proofs,
                    prepared_row_facts=prepared_row_facts,
                )
            if record.intent_token is None:
                if any(
                    value is not None
                    for value in (
                        record.intent_ledger,
                        record.intent_request,
                        record.intent_claim_context,
                        record.intent_claimed,
                        record.expected_intent_receipt,
                    )
                ):
                    raise EventContractError(
                        "Deferred-session publication retained a partial intent owner"
                    )
            else:
                if (
                    record.intent_ledger is None
                    or record.intent_request is None
                    or not record.intent_ledger.authenticates_batch_token(
                        record.intent_token,
                        request=record.intent_request,
                    )
                ):
                    raise EventContractError(
                        "Deferred-session intent preparation failed final authentication"
                    )
                if record.intent_claimed is None:
                    intent_claim_context = record.intent_ledger.claimed_batch(record.intent_token)
                    intent_claimed = intent_claim_context.__enter__()
                    with self._deferred_session_publication_lock:
                        if (
                            self._active_deferred_session_publication_batch_locked(batch)
                            is not record
                        ):
                            raise EventContractError(
                                "Deferred-session intent claim changed bridge ownership"
                            )
                        record.intent_claim_context = intent_claim_context
                        record.intent_claimed = intent_claimed
                        integrity = self._deferred_session_publication_batch_integrity(
                            batch,
                            record,
                        )
                        batch._integrity_token = integrity
                        record.integrity_token = integrity
                elif record.intent_claim_context is None:
                    raise EventContractError(
                        "Deferred-session publication lost its intent claim context"
                    )
                intent_claimed = cast(
                    "PreparedIntentExecutionBatch",
                    record.intent_claimed,
                )
                expected_intent_receipt = intent_claimed.expected_receipt
                if (
                    type(expected_intent_receipt) is not IntentExecutionBatchReceipt
                    or not record.intent_ledger.authenticates_expected_batch_receipt(
                        expected_intent_receipt,
                        preparation=intent_claimed,
                    )
                ):
                    raise EventContractError(
                        "Deferred-session intent expected receipt failed authentication"
                    )
                intent_claimed.certify_composite_commit(expected_intent_receipt)
                with self._deferred_session_publication_lock:
                    if self._active_deferred_session_publication_batch_locked(batch) is not record:
                        raise EventContractError(
                            "Deferred-session intent receipt changed bridge ownership"
                        )
                    record.expected_intent_receipt = expected_intent_receipt
                    integrity = self._deferred_session_publication_batch_integrity(
                        batch,
                        record,
                    )
                    batch._integrity_token = integrity
                    record.integrity_token = integrity
            for prepared, member_lock, integrity in zip(
                record.dispatches,
                record.member_locks,
                record.member_integrity_tokens,
                strict=True,
            ):
                if prepared._lock is not member_lock:
                    raise EventContractError(
                        "Deferred-session publication member lost its exact lock"
                    )
                self.validate_prepared(prepared)
                with cast(AbstractContextManager[object], member_lock):
                    if (
                        prepared._lock is not member_lock
                        or prepared._consumed
                        or prepared._deferred_session_publication_batch_id != record.batch_id
                        or not hmac.compare_digest(prepared._integrity_token, integrity)
                    ):
                        raise EventContractError(
                            "Deferred-session publication member lost its exact claim"
                        )
            recovery_shell = (
                self._build_deferred_session_recovery_shell(record)
                if record.exact_recovery is None
                else None
            )
            if recovery_shell is None and (
                record.publication_receipt is None
                or record.publication_result is None
                or record.exact_recovery is None
                or record.exact_recovery.state != "prepared"
            ):
                raise EventContractError(
                    "Deferred-session publication recovery shell changed before precommit"
                )
            with self._action_cohort_lock:
                with self._deferred_session_publication_lock:
                    if self._active_deferred_session_publication_batch_locked(batch) is not record:
                        raise EventContractError(
                            "Deferred-session publication ownership changed during authentication"
                        )
                    if record.state != "authenticating" or record.active_thread_id != owner_thread:
                        raise EventContractError(
                            "Deferred-session publication authentication claim changed"
                        )
                    if not record.recovery_capacity_reserved:
                        if (
                            len(self._exact_projection_recoveries)
                            + self._exact_projection_recovery_reservations
                            >= self._exact_projection_recovery_capacity
                        ):
                            raise EventContractError(
                                "Deferred-session exact recovery capacity is exhausted"
                            )
                        self._exact_projection_recovery_reservations += 1
                        record.recovery_capacity_reserved = True
                    if not record.receipt_capacity_reserved:
                        effective_retained = (
                            self._deferred_session_publication_committed_receipts
                            + self._deferred_session_publication_receipt_reservations
                            - len(self._deferred_session_publication_receipt_eviction_reservations)
                        )
                        if effective_retained >= self._action_cohort_receipt_capacity:
                            eviction_id = next(
                                (
                                    receipt_id
                                    for receipt_id, retained_receipt in (
                                        self._deferred_session_publication_receipts.items()
                                    )
                                    if retained_receipt._published
                                    and receipt_id not in self._exact_projection_recoveries
                                    and receipt_id
                                    not in (
                                        self._deferred_session_publication_receipt_eviction_reservations
                                    )
                                ),
                                None,
                            )
                            if eviction_id is None:
                                raise EventContractError(
                                    "Deferred-session receipt capacity has no terminal eviction"
                                )
                            record.receipt_eviction_id = eviction_id
                            self._deferred_session_publication_receipt_eviction_reservations.add(
                                eviction_id
                            )
                        self._deferred_session_publication_receipt_reservations += 1
                        record.receipt_capacity_reserved = True
                    if recovery_shell is not None:
                        (
                            record.publication_receipt,
                            record.publication_result,
                            record.exact_recovery,
                        ) = recovery_shell
                        integrity = self._deferred_session_publication_batch_integrity(
                            batch,
                            record,
                        )
                        batch._integrity_token = integrity
                        record.integrity_token = integrity
                    record.state = "precommit_authenticated"
                    record.active_thread_id = None
            return True
        except BaseException:
            with self._deferred_session_publication_lock:
                trusted_batch_id = self._deferred_session_publication_locators.get(id(batch))
                retained = (
                    self._deferred_session_publication_batches.get(trusted_batch_id)
                    if type(trusted_batch_id) is int
                    else None
                )
                if (
                    retained is not None
                    and retained.carrier is batch
                    and retained is locals().get("record")
                    and retained.active_thread_id == owner_thread
                    and retained.state == "authenticating"
                ):
                    retained.state = locals().get("prior_state", "prepared")
                    retained.active_thread_id = None
            return False

    def _deferred_session_precommit_integrity(
        self,
        precommit: DeferredSessionPublicationPrecommit,
        record: _PreparedDeferredSessionPublicationRecord,
    ) -> str:
        """Bind one opaque lifecycle claim to the fully frozen dispatcher record."""

        exact_batch = record.exact_publication_batch
        payload = repr(
            (
                "deferred-session-precommit-v1",
                id(precommit),
                precommit.dispatcher_id,
                precommit.batch_id,
                precommit.composition_token,
                precommit.member_digest,
                precommit.target_proof_digest,
                precommit.all_suppressed,
                record.all_suppressed,
                record.integrity_token,
                id(record.carrier),
                id(exact_batch),
                getattr(getattr(exact_batch, "_token", None), "integrity", None),
                id(record.publication_receipt),
                id(record.publication_result),
                id(record.exact_recovery),
                id(record.materialization_receipt_shell),
                record.materialization_receipt_shell_digest,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _active_deferred_session_precommit_locked(
        self,
        precommit: DeferredSessionPublicationPrecommit,
    ) -> _PreparedDeferredSessionPublicationRecord:
        """Locate an exact original precommit without hashing mutable public fields."""

        if type(precommit) is not DeferredSessionPublicationPrecommit:
            raise EventContractError("Deferred-session precommit requires the exact opaque type")
        batch_id = self._deferred_session_publication_precommit_locators.get(id(precommit))
        record = (
            self._deferred_session_publication_batches.get(batch_id)
            if type(batch_id) is int
            else None
        )
        if record is None or record.precommit is not precommit:
            raise EventContractError("Deferred-session precommit is copied, foreign, or stale")
        bounded_strings = (
            precommit.dispatcher_id,
            precommit.composition_token,
            precommit.member_digest,
            precommit.target_proof_digest,
            precommit._integrity,
        )
        if (
            any(
                type(value) is not str
                or not value
                or len(value) > _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
                for value in bounded_strings
            )
            or type(precommit.batch_id) is not int
            or precommit.batch_id <= 0
            or type(precommit.all_suppressed) is not bool
            or precommit.dispatcher_id != self._deferred_session_publication_dispatcher_id
            or precommit.batch_id != record.batch_id
            or precommit.composition_token != record.composition_token
            or precommit.member_digest != record.member_digest
            or precommit.target_proof_digest != record.target_proof_digest
            or precommit.all_suppressed is not record.all_suppressed
            or not hmac.compare_digest(
                precommit._integrity,
                self._deferred_session_precommit_integrity(precommit, record),
            )
        ):
            raise EventContractError("Deferred-session precommit failed integrity validation")
        return record

    def prepare_deferred_session_publication_precommit(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
        *,
        composition: object,
        coordinator: object,
    ) -> DeferredSessionPublicationPrecommit:
        """Issue the immutable lifecycle claim over one fully frozen source batch."""

        if not self.authenticates_prepared_deferred_session_publication_batch(
            batch,
            composition=composition,
            coordinator=coordinator,
        ):
            raise EventContractError(
                "Deferred-session precommit source batch failed authentication"
            )
        with self._deferred_session_publication_lock:
            record = self._active_deferred_session_publication_batch_locked(batch)
            if record.state != "precommit_authenticated":
                raise EventContractError(
                    "Deferred-session source batch is not ready for lifecycle claim"
                )
            if record.precommit is not None:
                self._active_deferred_session_precommit_locked(record.precommit)
                return record.precommit
            precommit = DeferredSessionPublicationPrecommit(
                dispatcher_id=self._deferred_session_publication_dispatcher_id,
                batch_id=record.batch_id,
                composition_token=record.composition_token,
                member_digest=record.member_digest,
                target_proof_digest=record.target_proof_digest,
                all_suppressed=record.all_suppressed,
            )
            object.__setattr__(
                precommit,
                "_integrity",
                self._deferred_session_precommit_integrity(precommit, record),
            )
            record.precommit = precommit
            self._deferred_session_publication_precommit_locators[id(precommit)] = record.batch_id
            return precommit

    def claim_deferred_session_publication_precommit(
        self,
        precommit: DeferredSessionPublicationPrecommit,
    ) -> bool:
        """Revalidate and claim one immutable bridge seal at lifecycle's final fence."""

        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                try:
                    record = self._active_deferred_session_precommit_locked(precommit)
                except EventContractError:
                    return False
                batch = record.carrier
                recovery = record.exact_recovery
                receipt = record.publication_receipt
                materialization_shell = record.materialization_receipt_shell
                if (
                    record.state != "precommit_authenticated"
                    or recovery is None
                    or receipt is None
                    or materialization_shell is None
                    or len(record.materialization_receipt_shell_digest) != 64
                    or record.publication_result is not recovery.result
                    or recovery.receipt is not receipt
                    or recovery.state != "prepared"
                    or not record.recovery_capacity_reserved
                    or id(receipt) in self._exact_projection_recoveries
                ):
                    return False
                # Source timing, runtime, lifecycle, and application capabilities are
                # already claimed when lifecycle reaches this fence.  Re-running their
                # public "active preparation" validators here would reject that valid
                # transition.  Instead, the dispatcher-issued precommit pins the prior
                # full authentication and this final lock cohort recomputes every
                # mutable dispatch/root signature immediately before canonical commit.
                with ExitStack() as member_locks:
                    if len({id(lock) for lock in record.member_locks}) != len(record.member_locks):
                        return False
                    for member_lock in sorted(record.member_locks, key=id):
                        member_locks.enter_context(
                            cast(AbstractContextManager[object], member_lock)
                        )
                    try:
                        if (
                            self._active_deferred_session_precommit_locked(precommit) is not record
                            or self._active_deferred_session_publication_batch_locked(batch)
                            is not record
                        ):
                            return False
                        for prepared, member_lock, retained_integrity in zip(
                            record.dispatches,
                            record.member_locks,
                            record.member_integrity_tokens,
                            strict=True,
                        ):
                            current_integrity = self._prepared_dispatch_integrity(prepared)
                            if (
                                prepared._lock is not member_lock
                                or prepared._consumed
                                or prepared._deferred_session_publication_batch_id
                                != record.batch_id
                                or not hmac.compare_digest(
                                    prepared._integrity_token,
                                    retained_integrity,
                                )
                                or not hmac.compare_digest(
                                    prepared._integrity_token,
                                    current_integrity,
                                )
                            ):
                                return False
                        current_shell_digest = (
                            self._deferred_session_materialization_receipt_shell_digest(
                                record,
                                materialization_shell,
                            )
                        )
                        if not hmac.compare_digest(
                            current_shell_digest,
                            record.materialization_receipt_shell_digest,
                        ):
                            return False
                    except EventContractError:
                        return False
                    self._exact_projection_recoveries[id(receipt)] = recovery
                    self._exact_projection_recovery_reservations -= 1
                    record.recovery_capacity_reserved = False
                    recovery.state = "canonical_pending"
                    record.state = "canonical_claimed"
                    self._exact_projection_recovery_high_water = max(
                        self._exact_projection_recovery_high_water,
                        len(self._exact_projection_recoveries),
                    )
                    return True

    def bind_deferred_session_materialization_receipt_shell(
        self,
        precommit: DeferredSessionPublicationPrecommit,
        receipt: object,
    ) -> None:
        """Bind the preallocated lifecycle receipt identity before canonical claim."""

        from evidenceforge.generation.lifecycle_authority import (
            LifecyclePreparedNetworkReceipt,
        )

        if type(receipt) is not LifecyclePreparedNetworkReceipt:
            raise EventContractError(
                "Deferred-session materialization shell has an unsupported type"
            )
        with self._deferred_session_publication_lock:
            record = self._active_deferred_session_precommit_locked(precommit)
            if record.state != "precommit_authenticated":
                raise EventContractError(
                    "Deferred-session materialization shell missed the precommit fence"
                )
            authority = self._lifecycle_authority
            if authority is None or not (
                authority.authenticates_deferred_session_materialization_receipt_shell(
                    record.root,
                    record.source_timing_preparation,
                    receipt,
                )
            ):
                raise EventContractError(
                    "Deferred-session materialization shell failed lifecycle authentication"
                )
            shell_digest = self._deferred_session_materialization_receipt_shell_digest(
                record,
                receipt,
            )
            retained = record.materialization_receipt_shell
            if retained is not None and retained is not receipt:
                raise EventContractError("Deferred-session materialization shell was already bound")
            if retained is receipt:
                if not hmac.compare_digest(
                    record.materialization_receipt_shell_digest,
                    shell_digest,
                ):
                    raise EventContractError(
                        "Deferred-session materialization shell changed after binding"
                    )
                return
            record.materialization_receipt_shell = receipt
            record.materialization_receipt_shell_digest = shell_digest
            try:
                integrity = self._deferred_session_publication_batch_integrity(
                    record.carrier,
                    record,
                )
                record.carrier._integrity_token = integrity
                record.integrity_token = integrity
                object.__setattr__(
                    precommit,
                    "_integrity",
                    self._deferred_session_precommit_integrity(precommit, record),
                )
            except BaseException:
                record.materialization_receipt_shell = None
                record.materialization_receipt_shell_digest = ""
                raise

    def _deferred_session_materialization_receipt_shell_digest(
        self,
        record: _PreparedDeferredSessionPublicationRecord,
        receipt: object,
    ) -> str:
        """Return a local seal over one exact lifecycle-authenticated blank shell."""

        from evidenceforge.generation.lifecycle_authority import (
            LifecycleConnectionCompositeReceipt,
            LifecyclePreparedNetworkReceipt,
        )

        if type(receipt) is not LifecyclePreparedNetworkReceipt:
            raise EventContractError(
                "Deferred-session materialization shell must be the exact receipt type"
            )
        connection = receipt._connection_receipt
        expected_fingerprint = record.root.state_plan.physical_transport_fingerprint
        bounded_outer_strings = (
            receipt._runtime_publication_token,
            receipt._state_publication_token,
            receipt._transaction_id,
            receipt._result_digest,
            receipt._integrity_token,
        )
        if (
            any(
                type(value) is not str
                or not value
                or len(value) > _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
                for value in bounded_outer_strings
            )
            or receipt._runtime_publication_token != record.root.runtime_token.publication_token
            or receipt._state_publication_token != record.root.state_plan.publication_token
            or receipt._transaction_id != record.root.transaction.stable_id
            or receipt._materialization_mode is not record.root.state_plan.mode
            or type(receipt._lifecycle_mode) is not str
            or receipt._lifecycle_mode != record.root.runtime_token.lifecycle_mode
            or type(receipt._physical_transport) is not type(expected_fingerprint)
            or receipt._physical_transport != expected_fingerprint
            or receipt._timing_binding_token is not record.source_timing_preparation.binding_token
            or receipt._runtime_receipt is not None
            or receipt._timing_receipt is not None
            or type(connection) is not LifecycleConnectionCompositeReceipt
        ):
            raise EventContractError(
                "Deferred-session materialization shell changed its root binding"
            )
        bounded_connection_strings = (
            connection._state_publication_token,
            connection._transaction_id,
        )
        if (
            any(
                type(value) is not str
                or not value
                or len(value) > _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
                for value in bounded_connection_strings
            )
            or connection._state_publication_token != record.root.state_plan.publication_token
            or type(connection._prior_version) is not int
            or connection._prior_version != record.root.state_plan.expected_version
            or type(connection._committed_version) is not int
            or connection._committed_version != record.root.state_plan.expected_version + 1
            or connection._transaction_id != record.root.transaction.stable_id
            or type(connection._physical_transport) is not type(expected_fingerprint)
            or connection._physical_transport != expected_fingerprint
            or type(connection._materializes_connection) is not bool
            or connection._materializes_connection
            is not record.root.state_plan.materializes_connection
            or connection._lifecycle_receipt is not None
            or connection._application_proof is not None
            or type(connection._prerequisite_proofs) is not tuple
            or connection._prerequisite_proofs
            or connection._integrity_token != ""
        ):
            raise EventContractError(
                "Deferred-session materialization shell changed its connection binding"
            )
        payload = repr(
            (
                "deferred-session-materialization-shell-v1",
                id(receipt),
                receipt._runtime_publication_token,
                receipt._state_publication_token,
                receipt._transaction_id,
                receipt._materialization_mode,
                receipt._lifecycle_mode,
                receipt._physical_transport,
                receipt._result_digest,
                id(receipt._timing_binding_token),
                id(connection),
                connection._state_publication_token,
                connection._prior_version,
                connection._committed_version,
                connection._transaction_id,
                connection._physical_transport,
                connection._materializes_connection,
                connection._prerequisite_proofs,
                receipt._integrity_token,
            )
        ).encode("utf-8")
        return hmac.new(
            self._prepared_dispatch_secret,
            payload,
            hashlib.sha256,
        ).hexdigest()

    def release_deferred_session_publication_precommit(
        self,
        precommit: DeferredSessionPublicationPrecommit,
    ) -> None:
        """Return a failed lifecycle claim to its still-reversible batch owner."""

        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                batch_id = self._deferred_session_publication_precommit_locators.get(id(precommit))
                record = (
                    self._deferred_session_publication_batches.get(batch_id)
                    if type(batch_id) is int
                    else None
                )
                if record is None or record.precommit is not precommit:
                    raise EventContractError(
                        "Deferred-session precommit cleanup owner is foreign or stale"
                    )
                if record.state == "canonical_claimed":
                    recovery = record.exact_recovery
                    receipt = record.publication_receipt
                    if (
                        recovery is None
                        or receipt is None
                        or recovery.state != "canonical_pending"
                        or self._exact_projection_recoveries.get(id(receipt)) is not recovery
                    ):
                        raise EventContractError(
                            "Deferred-session precommit cleanup lost its recovery owner"
                        )
                    self._exact_projection_recoveries.pop(id(receipt))
                    self._exact_projection_recovery_reservations += 1
                    record.recovery_capacity_reserved = True
                    recovery.state = "prepared"
                    record.state = "precommit_authenticated"

    def _canonical_deferred_session_publication_record_locked(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
    ) -> _PreparedDeferredSessionPublicationRecord:
        """Locate the exact carrier after lifecycle crossed the canonical fence.

        Once the immutable precommit has been claimed, canonical State may already
        exist.  Recovery must therefore use the dispatcher-retained carrier identity
        and state transition rather than re-reading caller-mutable carrier fields or
        revalidating preparations that have legitimately committed.
        """

        if type(batch) is not PreparedDeferredSessionPublicationBatch:
            raise EventContractError(
                "Deferred-session canonical publication requires the exact opaque batch"
            )
        batch_id = self._deferred_session_publication_locators.get(id(batch))
        record = (
            self._deferred_session_publication_batches.get(batch_id)
            if type(batch_id) is int
            else None
        )
        if (
            record is None
            or record.carrier is not batch
            or record.precommit is None
            or record.state not in {"canonical_claimed", "publishing", "recovering"}
        ):
            raise EventContractError(
                "Deferred-session canonical publication carrier is foreign or stale"
            )
        return record

    def cancel_prepared_deferred_session_publication_batch(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
    ) -> bool:
        """Cancel one uncommitted exact projection reservation without source writes."""

        if type(batch) is not PreparedDeferredSessionPublicationBatch:
            raise TypeError("Deferred-session cancellation requires the exact opaque batch")
        owner_thread = get_ident()
        integrity_failure: EventContractError | None = None
        with self._deferred_session_publication_lock:
            try:
                record = self._active_deferred_session_publication_batch_locked(batch)
            except EventContractError as error:
                trusted_batch_id = self._deferred_session_publication_locators.get(id(batch))
                retained = (
                    self._deferred_session_publication_batches.get(trusted_batch_id)
                    if type(trusted_batch_id) is int
                    else None
                )
                if retained is None:
                    if (
                        type(batch._dispatcher_id) is not str
                        or batch._dispatcher_id != self._deferred_session_publication_dispatcher_id
                    ):
                        raise
                    return False
                if retained.carrier is not batch:
                    raise
                record = retained
                integrity_failure = error
            for prepared, member_lock, retained_integrity in zip(
                record.dispatches,
                record.member_locks,
                record.member_integrity_tokens,
                strict=True,
            ):
                with cast(AbstractContextManager[object], member_lock):
                    try:
                        member_changed = bool(
                            prepared._lock is not member_lock
                            or prepared._consumed
                            or prepared._deferred_session_publication_batch_id != record.batch_id
                            or not hmac.compare_digest(
                                prepared._integrity_token,
                                retained_integrity,
                            )
                            or not hmac.compare_digest(
                                prepared._integrity_token,
                                self._prepared_dispatch_integrity(prepared),
                            )
                        )
                    except BaseException:
                        member_changed = True
                if member_changed and integrity_failure is None:
                    integrity_failure = EventContractError(
                        "Deferred-session publication member changed before cancellation"
                    )
            if record.state not in {
                "prepared",
                "precommit_authenticated",
                "cleanup_pending",
            }:
                raise StateError("Active deferred-session publication cannot be cancelled")
            if (
                record.source_timing_preparation.committed
                or record.source_timing_preparation.receipt is not None
                or record.materialization_receipt is not None
            ):
                raise StateError("Committed deferred-session publication requires exact recovery")
            prior_state = record.state
            record.state = "cancelling"
            record.active_thread_id = owner_thread
            exact_batch = record.exact_publication_batch
            intent_ledger = record.intent_ledger
            intent_token = record.intent_token
            intent_claim_context = record.intent_claim_context
        if intent_claim_context is not None:
            cancellation = StateError("Deferred-session publication cancelled before root commit")
            try:
                intent_claim_context.__exit__(
                    type(cancellation),
                    cancellation,
                    cancellation.__traceback__,
                )
            except BaseException:
                try:
                    still_active = bool(
                        intent_ledger is not None
                        and intent_token is not None
                        and intent_ledger.authenticates_batch_token(
                            intent_token,
                            request=record.intent_request,
                        )
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    with self._deferred_session_publication_lock:
                        if (
                            self._deferred_session_publication_batches.get(record.batch_id)
                            is record
                            and record.active_thread_id == owner_thread
                        ):
                            record.state = prior_state
                            record.active_thread_id = None
                    raise
        elif intent_ledger is not None and intent_token is not None:
            try:
                if intent_ledger.authenticates_batch_token(
                    intent_token,
                    request=record.intent_request,
                ):
                    intent_ledger.cancel_batch(intent_token)
            except BaseException:
                try:
                    still_active = intent_ledger.authenticates_batch_token(
                        intent_token,
                        request=record.intent_request,
                    )
                except BaseException:
                    still_active = True
                if still_active:
                    with self._deferred_session_publication_lock:
                        if (
                            self._deferred_session_publication_batches.get(record.batch_id)
                            is record
                            and record.active_thread_id == owner_thread
                        ):
                            record.state = prior_state
                            record.active_thread_id = None
                    raise
        if exact_batch is not None and exact_batch.state in {"issued", "ready"}:
            try:
                exact_batch.cancel()
            except BaseException:
                if exact_batch.state != "canceled":
                    with self._deferred_session_publication_lock:
                        if (
                            self._deferred_session_publication_batches.get(record.batch_id)
                            is record
                            and record.active_thread_id == owner_thread
                        ):
                            record.state = prior_state
                            record.active_thread_id = None
                    raise
        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                if self._deferred_session_publication_batches.get(record.batch_id) is not record:
                    raise EventContractError("Deferred-session cancellation ownership changed")
                self._detach_deferred_session_publication_batch_locked(
                    record,
                    terminal_state="cancelled",
                )
        if integrity_failure is not None:
            raise EventContractError(
                "Deferred-session publication integrity failed; exact reservations were cancelled"
            ) from integrity_failure
        return True

    def deferred_session_publication_census(self) -> DeferredSessionPublicationCensus:
        """Return bounded retained bridge work without scanning source sinks."""

        with self._action_cohort_lock:
            recovery_reservations = self._exact_projection_recovery_reservations
            with self._deferred_session_publication_lock:
                return DeferredSessionPublicationCensus(
                    prepared_batches=len(self._deferred_session_publication_batches),
                    retained_members=self._deferred_session_publication_retained_members,
                    retained_bytes=self._deferred_session_publication_retained_bytes,
                    committed_receipts=self._deferred_session_publication_committed_receipts,
                    pending_receipts=len(self._deferred_session_publication_pending_receipts),
                    receipt_reservations=(self._deferred_session_publication_receipt_reservations),
                    receipt_eviction_reservations=len(
                        self._deferred_session_publication_receipt_eviction_reservations
                    ),
                    recovery_reservations=recovery_reservations,
                    preparation_capacity=self._action_cohort_preparation_capacity,
                    member_capacity=self._action_cohort_member_capacity,
                    retained_byte_capacity=self._action_cohort_byte_capacity,
                    receipt_capacity=self._action_cohort_receipt_capacity,
                )

    def _deferred_session_publication_receipt_integrity(
        self,
        receipt: DeferredSessionPublicationReceipt,
    ) -> str:
        """Authenticate one closed postcanonical source-publication receipt."""

        payload = repr(
            (
                "deferred-session-publication-receipt-v2",
                id(receipt),
                receipt.dispatcher_id,
                receipt.receipt_id,
                receipt.publication_token,
                receipt.composition_token,
                receipt.physical_transport_id,
                receipt.occurrence_ids,
                receipt.member_integrity_digest,
                receipt.target_proof_digest,
                receipt.materialization_receipt_token,
                receipt.intent_publication_token,
            )
        ).encode("utf-8")
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _deferred_session_publication_receipt_shape_is_valid(
        receipt: DeferredSessionPublicationReceipt,
    ) -> bool:
        """Reject hostile receipt fields before registry or HMAC work."""

        bounded_strings = (
            receipt.dispatcher_id,
            receipt.receipt_id,
            receipt.publication_token,
            receipt.composition_token,
            receipt.physical_transport_id,
            receipt.member_integrity_digest,
            receipt.target_proof_digest,
            receipt.materialization_receipt_token,
            receipt._integrity,
        )
        return bool(
            all(
                type(value) is str and 0 < len(value) <= _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
                for value in bounded_strings
            )
            and type(receipt.occurrence_ids) is tuple
            and 1 <= len(receipt.occurrence_ids) <= _MAX_DEFERRED_SESSION_PUBLICATION_MEMBERS
            and all(
                type(value) is str and 0 < len(value) <= _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
                for value in receipt.occurrence_ids
            )
            and len(set(receipt.occurrence_ids)) == len(receipt.occurrence_ids)
            and type(receipt.intent_publication_token) is str
            and len(receipt.intent_publication_token) <= _MAX_DEFERRED_SESSION_RECEIPT_STRING_CHARS
            and type(receipt._published) is bool
        )

    def authenticates_deferred_session_publication_receipt(
        self,
        receipt: object,
    ) -> bool:
        """Return whether this dispatcher retained one authentic terminal receipt."""

        if type(receipt) is not DeferredSessionPublicationReceipt:
            return False
        try:
            with self._deferred_session_publication_lock:
                retained = self._deferred_session_publication_receipts.get(id(receipt))
                if retained is not receipt:
                    return False
            if not self._deferred_session_publication_receipt_shape_is_valid(receipt):
                return False
            expected = self._deferred_session_publication_receipt_integrity(receipt)
            with self._deferred_session_publication_lock:
                return bool(
                    self._deferred_session_publication_receipts.get(id(receipt)) is receipt
                    and receipt.dispatcher_id == self._deferred_session_publication_dispatcher_id
                    and hmac.compare_digest(receipt._integrity, expected)
                    and receipt._published
                )
        except BaseException:
            return False

    def _prepare_deferred_session_dispatcher_ledgers(
        self,
        record: _PreparedDeferredSessionPublicationRecord,
    ) -> None:
        """Allocate all in-memory dispatcher replacements before exact sink admission."""

        binary_counts = self._binary_identity_counts.copy()
        for identity_kind in record.member_binary_identity_kinds:
            if identity_kind:
                binary_counts[identity_kind] += 1
        record.prepared_binary_counts = binary_counts
        record.prepared_latest_network_observations_uid = self._latest_network_observations_uid
        record.prepared_latest_network_observations = self._latest_network_observations
        record.prepared_latest_network_plan = self._latest_network_plan
        if record.frozen_latest_network_plan is not None:
            record.prepared_latest_network_observations_uid = (
                record.frozen_latest_network_observations_uid
            )
            record.prepared_latest_network_observations = record.frozen_latest_network_observations
            record.prepared_latest_network_plan = record.frozen_latest_network_plan

    def _commit_deferred_session_dispatcher_ledgers_no_fail(
        self,
        record: _PreparedDeferredSessionPublicationRecord,
    ) -> None:
        """Swap only preallocated ledgers exactly once before sink recovery begins."""

        if record.dispatcher_ledgers_committed:
            return
        self._binary_identity_counts = cast(Counter[str], record.prepared_binary_counts)
        self._latest_network_observations_uid = record.prepared_latest_network_observations_uid
        self._latest_network_observations = record.prepared_latest_network_observations
        self._latest_network_plan = record.prepared_latest_network_plan
        if not record.observation_committed:
            self._commit_action_cohort_observations_no_fail(record)
        record.dispatcher_ledgers_committed = True

    @staticmethod
    def _flatten_deferred_session_identifiers(
        identifiers: tuple[tuple[tuple[str, str], ...], ...],
    ) -> tuple[tuple[str, str], ...]:
        """Bind member ordinals into the generic exact-recovery result shape."""

        return tuple(
            (f"{member_ordinal}:{format_name}", value)
            for member_ordinal, member in enumerate(identifiers)
            for format_name, value in member
        )

    def _complete_deferred_session_exact_recovery(
        self,
        recovery: _ExactProjectionRecoveryRecord,
    ) -> None:
        """Consume the bridge carrier after engine-drainable exact release succeeds."""

        record = recovery.owner_record
        if type(record) is not _PreparedDeferredSessionPublicationRecord:
            raise EventContractError("Deferred-session exact recovery lost its bridge owner")
        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                if self._deferred_session_publication_batches.get(record.batch_id) is record:
                    for prepared, member_lock in zip(
                        record.dispatches,
                        record.member_locks,
                        strict=True,
                    ):
                        with cast(AbstractContextManager[object], member_lock):
                            prepared._consumed = True
                    self._detach_deferred_session_publication_batch_locked(
                        record,
                        terminal_state="published",
                    )

    def _complete_deferred_session_owner_tail(
        self,
        recovery: _ExactProjectionRecoveryRecord,
    ) -> None:
        """Resume every committed canonical owner before exact sink admission."""

        from evidenceforge.generation.intent_ledger import IntentExecutionBatchReceipt

        record = recovery.owner_record
        if (
            type(record) is not _PreparedDeferredSessionPublicationRecord
            or record.exact_recovery is not recovery
            or record.publication_receipt is not recovery.receipt
        ):
            raise EventContractError(
                "Deferred-session owner-tail recovery lost its exact bridge record"
            )
        receipt = cast(DeferredSessionPublicationReceipt, recovery.receipt)
        with self._publication_ledger_lock:
            with self._claimed_action_cohort_observations(record):
                self._prepare_deferred_session_dispatcher_ledgers(record)
                if record.intent_claimed is not None:
                    intent_claimed = record.intent_claimed
                    expected_intent_receipt = record.expected_intent_receipt
                    intent_ledger = record.intent_ledger
                    if (
                        type(expected_intent_receipt) is not IntentExecutionBatchReceipt
                        or intent_ledger is None
                        or record.intent_request is None
                        or not intent_ledger.authenticates_expected_batch_receipt(
                            expected_intent_receipt,
                            preparation=intent_claimed,
                        )
                    ):
                        raise EventContractError(
                            "Deferred-session owner-tail intent proof failed authentication"
                        )
                    if not intent_claimed.committed:
                        self._commit_exact_expected_owner(
                            intent_claimed.commit_no_fail,
                            expected=expected_intent_receipt,
                            terminal_authenticates=lambda: bool(
                                intent_claimed.committed
                                and intent_claimed.receipt is expected_intent_receipt
                                and intent_ledger.authenticates_batch_receipt(
                                    expected_intent_receipt,
                                    request=record.intent_request,
                                )
                            ),
                            label="Deferred-session intent owner",
                        )
                self._commit_exact_expected_owner(
                    lambda: self._commit_deferred_session_dispatcher_ledgers_no_fail(record),
                    expected=None,
                    terminal_authenticates=lambda: bool(
                        record.dispatcher_ledgers_committed and record.observation_committed
                    ),
                    label="Deferred-session dispatcher ledger owner",
                )
        if record.intent_claim_context is not None and not record.intent_claim_closed:
            try:
                record.intent_claim_context.__exit__(None, None, None)
            except BaseException:
                expected_intent_receipt = record.expected_intent_receipt
                intent_claimed = record.intent_claimed
                intent_ledger = record.intent_ledger
                if not (
                    type(expected_intent_receipt) is IntentExecutionBatchReceipt
                    and intent_claimed is not None
                    and intent_claimed.committed
                    and intent_claimed.receipt is expected_intent_receipt
                    and intent_ledger is not None
                    and intent_ledger.authenticates_batch_receipt(
                        expected_intent_receipt,
                        request=record.intent_request,
                    )
                ):
                    raise
            record.intent_claim_closed = True
        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                if (
                    self._deferred_session_publication_pending_receipts.get(id(receipt))
                    is not receipt
                    or self._exact_projection_recoveries.get(id(receipt)) is not recovery
                ):
                    raise EventContractError(
                        "Deferred-session owner-tail recovery registries changed"
                    )
                eviction_id = record.receipt_eviction_id
                evicted: DeferredSessionPublicationReceipt | None = None
                if eviction_id is not None:
                    if (
                        eviction_id
                        not in self._deferred_session_publication_receipt_eviction_reservations
                        or eviction_id in self._exact_projection_recoveries
                    ):
                        raise EventContractError(
                            "Deferred-session terminal receipt eviction changed"
                        )
                    evicted = self._deferred_session_publication_receipts.get(eviction_id)
                    if evicted is None or not evicted._published:
                        raise EventContractError(
                            "Deferred-session terminal receipt eviction was lost"
                        )
                self._deferred_session_publication_pending_receipts.pop(id(receipt))
                if eviction_id is not None:
                    self._deferred_session_publication_receipts.pop(eviction_id)
                    self._deferred_session_publication_receipt_eviction_reservations.remove(
                        eviction_id
                    )
                    self._deferred_session_publication_committed_receipts -= 1
                    record.receipt_eviction_id = None
                object.__setattr__(receipt, "_published", True)
                self._deferred_session_publication_receipts[id(receipt)] = receipt
                if record.receipt_capacity_reserved:
                    self._deferred_session_publication_receipt_reservations -= 1
                    record.receipt_capacity_reserved = False
                    self._deferred_session_publication_committed_receipts += 1

    def _deferred_session_owner_tail_terminal_authenticates(
        self,
        recovery: _ExactProjectionRecoveryRecord,
    ) -> bool:
        """Adopt a fully installed owner tail when its callback return is lost."""

        from evidenceforge.generation.intent_ledger import IntentExecutionBatchReceipt

        record = recovery.owner_record
        receipt = recovery.receipt
        result = recovery.result
        if (
            type(record) is not _PreparedDeferredSessionPublicationRecord
            or type(receipt) is not DeferredSessionPublicationReceipt
            or type(result) is not DeferredSessionPublicationResult
            or record.exact_recovery is not recovery
            or record.publication_receipt is not receipt
            or record.publication_result is not result
            or result.receipt is not receipt
            or result.materialization_receipt is not record.materialization_receipt
            or result.projections is not recovery.outcomes
            or result.identifiers is not recovery.member_identifiers
            or result.target_proofs is not recovery.target_proofs
            or not record.dispatcher_ledgers_committed
            or not record.observation_committed
            or not self.authenticates_deferred_session_publication_receipt(receipt)
        ):
            return False
        if record.intent_claimed is None:
            if any(
                value is not None
                for value in (
                    record.intent_claim_context,
                    record.expected_intent_receipt,
                )
            ):
                return False
        else:
            intent_receipt = record.expected_intent_receipt
            intent_ledger = record.intent_ledger
            if (
                type(intent_receipt) is not IntentExecutionBatchReceipt
                or intent_ledger is None
                or record.intent_request is None
                or not record.intent_claimed.committed
                or record.intent_claimed.receipt is not intent_receipt
                or not record.intent_claim_closed
                or not intent_ledger.authenticates_batch_receipt(
                    intent_receipt,
                    request=record.intent_request,
                )
            ):
                return False
        with self._action_cohort_lock:
            with self._deferred_session_publication_lock:
                return bool(
                    self._exact_projection_recoveries.get(id(receipt)) is recovery
                    and self._deferred_session_publication_receipts.get(id(receipt)) is receipt
                    and id(receipt) not in self._deferred_session_publication_pending_receipts
                    and not record.receipt_capacity_reserved
                    and record.receipt_eviction_id is None
                    and id(receipt)
                    not in self._deferred_session_publication_receipt_eviction_reservations
                    and self._deferred_session_publication_committed_receipts
                    == len(self._deferred_session_publication_receipts)
                )

    def publish_prepared_deferred_session_publication_batch(
        self,
        batch: PreparedDeferredSessionPublicationBatch,
        *,
        materialization_receipt: object,
    ) -> DeferredSessionPublicationResult:
        """Publish one exact transport-first tail from its authentic root receipt."""

        from evidenceforge.generation.lifecycle_authority import LifecyclePreparedNetworkReceipt

        if type(batch) is not PreparedDeferredSessionPublicationBatch:
            raise TypeError("Deferred-session publication requires the exact opaque batch")
        owner_thread = get_ident()
        with self._deferred_session_publication_lock:
            record = self._canonical_deferred_session_publication_record_locked(batch)
            recovery = record.exact_recovery
            if recovery is None or recovery.receipt is not record.publication_receipt:
                raise EventContractError(
                    "Deferred-session publication lost its preinstalled recovery owner"
                )
            receipt = cast(DeferredSessionPublicationReceipt, recovery.receipt)
            if record.state == "recovering":
                if record.materialization_receipt is not materialization_receipt:
                    raise EventContractError(
                        "Deferred-session recovery requires the original root receipt"
                    )
                resume_installed = True
            elif record.state == "canonical_claimed":
                if recovery.state != "canonical_pending":
                    raise EventContractError(
                        "Deferred-session canonical recovery is not awaiting its root receipt"
                    )
                if record.active_thread_id is not None:
                    raise EventContractError("Deferred-session publication is already active")
                record.state = "publishing"
                record.active_thread_id = owner_thread
                resume_installed = False
            else:
                raise EventContractError(
                    "Deferred-session publication lacks its canonical lifecycle claim"
                )
        if resume_installed:
            return cast(
                DeferredSessionPublicationResult,
                self._resume_exact_projection_recovery(
                    receipt,
                    expected_kind="deferred_session",
                ),
            )

        authority = self._lifecycle_authority
        timing_preparation = record.source_timing_preparation
        timing_receipt = timing_preparation.receipt
        if (
            authority is None
            or type(materialization_receipt) is not LifecyclePreparedNetworkReceipt
            or record.materialization_receipt_shell is not materialization_receipt
            or not timing_preparation.committed
            or timing_receipt is None
            or not self.source_timing_planner.authenticates_preparation_receipt(timing_receipt)
            or materialization_receipt.timing_binding_token != timing_preparation.binding_token
            or materialization_receipt.timing_receipt != timing_receipt
            or not authority.authenticates_prepared_network_receipt(
                record.root,
                materialization_receipt,
            )
        ):
            with self._deferred_session_publication_lock:
                if record.active_thread_id == owner_thread and record.state == "publishing":
                    record.state = "canonical_claimed"
                    record.active_thread_id = None
            raise EventContractError(
                "Deferred-session publication requires its authentic network/timing receipt"
            )

        exact_batch = record.exact_publication_batch
        if exact_batch is None or exact_batch.state != "ready":
            with self._deferred_session_publication_lock:
                if (
                    self._deferred_session_publication_batches.get(record.batch_id) is record
                    and record.exact_recovery is recovery
                    and record.active_thread_id == owner_thread
                    and record.state == "publishing"
                ):
                    record.state = "canonical_claimed"
                    record.active_thread_id = None
            raise EventContractError("Deferred-session exact projection is not recoverable")
        try:
            publication_result = cast(
                DeferredSessionPublicationResult,
                record.publication_result,
            )
            if (
                publication_result.receipt is not receipt
                or publication_result.projections is not recovery.outcomes
                or publication_result.target_proofs is not recovery.target_proofs
                or publication_result.identifiers is not recovery.member_identifiers
                or (
                    record.materialization_receipt is not None
                    and record.materialization_receipt is not materialization_receipt
                )
                or receipt.materialization_receipt_token
                not in {"", materialization_receipt.receipt_token}
            ):
                raise EventContractError("Deferred-session preinstalled recovery shell changed")
            object.__setattr__(
                receipt,
                "materialization_receipt_token",
                materialization_receipt.receipt_token,
            )
            object.__setattr__(
                receipt,
                "_integrity",
                self._deferred_session_publication_receipt_integrity(receipt),
            )
            object.__setattr__(
                publication_result,
                "materialization_receipt",
                materialization_receipt,
            )
            with self._action_cohort_lock:
                with self._deferred_session_publication_lock:
                    if (
                        self._canonical_deferred_session_publication_record_locked(batch)
                        is not record
                        or record.state != "publishing"
                        or record.active_thread_id != owner_thread
                    ):
                        raise EventContractError(
                            "Deferred-session publication ownership changed before recovery"
                        )
                    if (
                        record.recovery_capacity_reserved
                        or not record.receipt_capacity_reserved
                        or self._exact_projection_recoveries.get(id(receipt)) is not recovery
                        or recovery.state != "canonical_pending"
                        or id(receipt) in self._deferred_session_publication_receipts
                        or id(receipt) in self._deferred_session_publication_pending_receipts
                    ):
                        raise EventContractError(
                            "Deferred-session publication lost its precommitted capacity"
                        )
                    record.materialization_receipt = materialization_receipt
                    record.state = "recovering"
                    record.active_thread_id = None
                    self._deferred_session_publication_pending_receipts[id(receipt)] = receipt
                    recovery.state = "owner_pending"
        except BaseException:
            with self._deferred_session_publication_lock:
                if (
                    self._deferred_session_publication_batches.get(record.batch_id) is record
                    and record.exact_recovery is recovery
                    and record.active_thread_id == owner_thread
                ):
                    record.state = "canonical_claimed"
                    record.active_thread_id = None
            raise

        return cast(
            DeferredSessionPublicationResult,
            self._resume_exact_projection_recovery(
                receipt,
                expected_kind="deferred_session",
            ),
        )

    def _network_dependent_batch_integrity(
        self,
        batch: PreparedNetworkDependentBatch,
    ) -> str:
        """Authenticate one ordered plan/root/timing/dispatch batch preimage."""

        timing_token = batch._source_timing_preparation.binding_token
        audit_token = batch._audit_binding_token
        payload = repr(
            (
                "prepared-network-dependent-batch-v2",
                batch._dispatcher_token,
                self._lifecycle_ticket_signature(batch._root),
                batch._plan,
                (
                    type(timing_token).__module__,
                    type(timing_token).__qualname__,
                    getattr(timing_token, "preparation_id", None),
                    getattr(timing_token, "base_state_digest", None),
                    getattr(timing_token, "_integrity", None),
                ),
                (
                    id(audit_token),
                    type(audit_token).__module__,
                    type(audit_token).__qualname__,
                    getattr(audit_token, "_owner_id", None),
                    getattr(audit_token, "_preparation_id", None),
                    getattr(audit_token, "_cohort_digest", None),
                    getattr(audit_token, "_identity_digest", None),
                    getattr(audit_token, "_delta_digest", None),
                    getattr(audit_token, "_integrity", None),
                ),
                tuple(
                    (
                        id(prepared),
                        prepared.occurrence_id,
                        prepared._integrity_token,
                        self._prepared_dispatch_integrity(prepared),
                        prepared._consumed,
                        prepared._network_dependent_batch_id,
                    )
                    for prepared in batch._dispatches
                ),
            )
        ).encode()
        return hmac.new(self._prepared_dispatch_secret, payload, hashlib.sha256).hexdigest()

    def _active_network_dependent_batch_locked(
        self,
        batch: PreparedNetworkDependentBatch,
    ) -> _PreparedNetworkDependentBatchCapability:
        """Return one intact active batch or reject copied, foreign, or consumed carriers."""

        if type(batch) is not PreparedNetworkDependentBatch:
            raise EventContractError("Network-dependent batch must be the exact opaque type")
        if batch._dispatcher_token != id(self):
            raise EventContractError("Network-dependent batch belongs to another dispatcher")
        capability = self._network_dependent_batches.get(id(batch))
        if capability is None or batch._consumed:
            raise EventContractError("Network-dependent batch is stale or already consumed")
        expected = self._network_dependent_batch_integrity(batch)
        if (
            not hmac.compare_digest(batch._integrity_token, expected)
            or not hmac.compare_digest(capability.integrity_token, expected)
            or batch._root is not capability.root
            or batch._plan != capability.plan
            or batch._dispatches != capability.dispatches
            or batch._source_timing_preparation is not capability.source_timing_preparation
            or batch._audit_binding_token is not capability.audit_preparation.binding_token
        ):
            raise EventContractError("Network-dependent batch integrity validation failed")
        return capability

    def authenticates_prepared_network_dependent_batch(
        self,
        batch: PreparedNetworkDependentBatch,
    ) -> bool:
        """Authenticate every claimed member at the final precommit barrier."""

        from evidenceforge.generation.actions.command_effects import ExecutionEffectPlanError

        with self._network_dependent_batch_lock:
            try:
                capability = self._active_network_dependent_batch_locked(batch)
                audit = capability.execution_effect_audit
                audit_preparation = capability.audit_preparation
                if (
                    self._execution_effect_audit is not audit
                    or audit_preparation.binding_token is not batch._audit_binding_token
                    or not audit.authenticates_action_cohort_binding_token(
                        batch._audit_binding_token
                    )
                    or not audit.authenticates_action_cohort_preparation(
                        audit_preparation,
                        root_action_id=capability.root.transaction.stable_id,
                        entries=(),
                        owned_plans=(capability.plan,),
                        published_provenances=capability.published_provenances,
                    )
                ):
                    raise EventContractError(
                        "Network-dependent batch audit preparation failed authentication"
                    )
                for prepared in capability.dispatches:
                    self.validate_prepared(prepared)
                    with prepared._lock:
                        if prepared._consumed or prepared._network_dependent_batch_id != id(batch):
                            raise EventContractError(
                                "Network-dependent batch member is not exactly claimed"
                            )
                if capability.precommit_authenticated:
                    if (
                        capability.audit_claim_context is None
                        or capability.audit_claimed is not audit_preparation
                    ):
                        raise EventContractError(
                            "Network-dependent batch lost its claimed audit capability"
                        )
                    return True
                audit_claim_context = audit.claimed_action_cohort(audit_preparation)
                audit_claimed = audit_claim_context.__enter__()
                if audit_claimed is not audit_preparation:
                    claim_error = EventContractError(
                        "Network-dependent batch claimed a different audit preparation"
                    )
                    audit_claim_context.__exit__(
                        type(claim_error),
                        claim_error,
                        claim_error.__traceback__,
                    )
                    raise claim_error
            except (
                AttributeError,
                EventContractError,
                ExecutionEffectPlanError,
                StateError,
                TypeError,
                ValueError,
            ) as error:
                capability = self._network_dependent_batches.get(id(batch))
                if capability is not None and capability.audit_claim_context is not None:
                    capability.audit_claim_context.__exit__(
                        type(error),
                        error,
                        error.__traceback__,
                    )
                    self._network_dependent_batches[id(batch)] = replace(
                        capability,
                        audit_claim_context=None,
                        audit_claimed=None,
                        precommit_authenticated=False,
                    )
                return False
            self._network_dependent_batches[id(batch)] = replace(
                capability,
                audit_claim_context=audit_claim_context,
                audit_claimed=audit_claimed,
                precommit_authenticated=True,
            )
            return True

    def prepare_network_dependent_batch(
        self,
        root: object,
        plan: OwnedEffectOccurrencePlan,
        dispatches: tuple[PreparedDispatch, ...],
    ) -> PreparedNetworkDependentBatch:
        """Validate and claim one exact ordered HTTP multipart dependent batch."""

        from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot

        publications = tuple(dispatches)
        if type(root) is not PreparedNetworkTransactionRoot:
            raise EventContractError(
                "Network-dependent batch requires an exact prepared network root"
            )
        if (
            type(plan) is not OwnedEffectOccurrencePlan
            or plan.owner is not EffectOccurrenceOwner.HTTP_MULTIPART_LOCAL_READ
            or plan.kind is not EffectOccurrenceKind.FILE
            or plan.root_action_id != root.transaction.stable_id
            or plan.occurrence_count != len(publications)
            or not publications
        ):
            raise EventContractError(
                "Network-dependent batch plan does not match its exact multipart cardinality"
            )
        timing_preparation = publications[0]._source_timing_preparation
        if timing_preparation is None:
            raise EventContractError("Network-dependent batch requires shared source timing")
        occurrence_ids: set[str] = set()
        for ordinal, prepared in enumerate(publications):
            if not isinstance(prepared, PreparedDispatch):
                raise TypeError("Network-dependent batch contains a non-dispatch member")
            if (
                prepared._state_intent is not PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT
                or prepared._lifecycle_ticket is not root
                or prepared._source_timing_preparation is not timing_preparation
                or prepared._action_cohort_batch_id is not None
                or prepared._deferred_session_publication_batch_id is not None
                or prepared._artifact_publications
                or prepared._projection.mode == "deferred"
                or prepared._occurrence.effect_provenance != plan.provenance(ordinal)
                or prepared.occurrence_id in occurrence_ids
            ):
                raise EventContractError(
                    "Network-dependent batch member changed root, timing, order, or provenance"
                )
            occurrence_ids.add(prepared.occurrence_id)
            self.validate_prepared(prepared)

        execution_effect_audit = self._execution_effect_audit
        if execution_effect_audit is None:
            raise EventContractError(
                "Network-dependent batch requires the engine-owned execution-effect audit"
            )
        published_provenances = tuple(
            cast(EffectOccurrenceProvenance, prepared._occurrence.effect_provenance)
            for prepared in publications
        )
        audit_preparation = execution_effect_audit.prepare_action_cohort(
            root.transaction.stable_id,
            (),
            owned_plans=(plan,),
            published_provenances=published_provenances,
        )
        batch = PreparedNetworkDependentBatch(
            dispatcher_token=id(self),
            audit_binding_token=audit_preparation.binding_token,
            root=root,
            plan=plan,
            dispatches=publications,
            source_timing_preparation=timing_preparation,
        )
        claimed: list[PreparedDispatch] = []
        with self._network_dependent_batch_lock:
            try:
                for prepared in publications:
                    with prepared._lock:
                        if (
                            prepared._consumed
                            or prepared._network_dependent_batch_id is not None
                            or prepared._action_cohort_batch_id is not None
                            or prepared._deferred_session_publication_batch_id is not None
                        ):
                            raise EventContractError(
                                "Network-dependent dispatch is already claimed or published"
                            )
                        prepared._network_dependent_batch_id = id(batch)
                        claimed.append(prepared)
                batch._integrity_token = self._network_dependent_batch_integrity(batch)
                capability = _PreparedNetworkDependentBatchCapability(
                    batch_id=id(batch),
                    integrity_token=batch._integrity_token,
                    root=root,
                    plan=plan,
                    dispatches=publications,
                    source_timing_preparation=timing_preparation,
                    execution_effect_audit=execution_effect_audit,
                    audit_preparation=audit_preparation,
                    published_provenances=published_provenances,
                )
                self._network_dependent_batches[id(batch)] = capability
            except BaseException:
                for prepared in claimed:
                    with prepared._lock:
                        if prepared._network_dependent_batch_id == id(batch):
                            prepared._network_dependent_batch_id = None
                execution_effect_audit.cancel_action_cohort(audit_preparation)
                raise
        return batch

    def cancel_prepared_network_dependent_batch(
        self,
        batch: PreparedNetworkDependentBatch,
    ) -> bool:
        """Release one uncommitted dependent batch without audit or projection residue."""

        from evidenceforge.generation.actions.command_effects import ExecutionEffectPlanError

        if type(batch) is not PreparedNetworkDependentBatch:
            raise TypeError("Network-dependent cancellation requires the exact opaque batch")
        with self._network_dependent_batch_lock:
            capability = self._network_dependent_batches.pop(id(batch), None)
            if capability is None:
                if batch._dispatcher_token != id(self):
                    raise EventContractError(
                        "Network-dependent batch belongs to another dispatcher"
                    )
                return False
            for prepared in capability.dispatches:
                with prepared._lock:
                    if prepared._network_dependent_batch_id == id(batch):
                        prepared._network_dependent_batch_id = None
            if capability.audit_claim_context is not None:
                cancellation = StateError("Network-dependent batch cancelled before root commit")
                capability.audit_claim_context.__exit__(
                    type(cancellation),
                    cancellation,
                    cancellation.__traceback__,
                )
            else:
                try:
                    capability.execution_effect_audit.cancel_action_cohort(
                        capability.audit_preparation
                    )
                except ExecutionEffectPlanError:
                    # An authenticated preparation releases itself before reporting
                    # integrity drift; the batch must still release every member.
                    pass
            batch._consumed = True
            return True

    def publish_prepared_network_dependent_batch(
        self,
        batch: PreparedNetworkDependentBatch,
        *,
        materialization_receipt: object,
    ) -> tuple[dict[str, str], ...]:
        """Authenticate the outer root receipt, then publish one no-State dependent batch."""

        from evidenceforge.generation.lifecycle_authority import (
            LifecyclePreparedNetworkReceipt,
        )

        with self._network_dependent_batch_lock:
            if type(batch) is not PreparedNetworkDependentBatch:
                raise TypeError("Network-dependent publication requires the exact opaque batch")
            capability = self._network_dependent_batches.get(id(batch))
            if capability is None or not capability.precommit_authenticated:
                raise EventContractError(
                    "Network-dependent batch lacks its final precommit authentication"
                )
        timing_preparation = capability.source_timing_preparation
        timing_receipt = timing_preparation.receipt
        authority = self._lifecycle_authority
        if (
            authority is None
            or type(materialization_receipt) is not LifecyclePreparedNetworkReceipt
            or not timing_preparation.committed
            or timing_receipt is None
            or not self.source_timing_planner.authenticates_preparation_receipt(timing_receipt)
            or materialization_receipt.timing_binding_token != timing_preparation.binding_token
            or materialization_receipt.timing_receipt != timing_receipt
            or not authority.authenticates_prepared_network_receipt(
                capability.root,
                materialization_receipt,
            )
        ):
            raise EventContractError(
                "Network-dependent batch requires its authentic full network/timing receipt"
            )
        audit_claimed = cast(
            "PreparedExecutionEffectAuditCommit",
            capability.audit_claimed,
        )
        audit_claim_context = cast(
            "AbstractContextManager[PreparedExecutionEffectAuditCommit]",
            capability.audit_claim_context,
        )
        audit_claimed.commit_no_fail()
        audit_claim_context.__exit__(None, None, None)
        with self._network_dependent_batch_lock:
            self._network_dependent_batches.pop(id(batch), None)
            for prepared in capability.dispatches:
                with prepared._lock:
                    prepared._network_dependent_batch_id = None
                    prepared._consumed = True
            batch._consumed = True

        # Every fallible builder, State binding, timing decision, and receipt check is above.
        # The claimed audit cohort committed the exact plan/publication parity in one fixed-size
        # update. The root already owns every process frontier, so this tail is projection-only.
        results: list[dict[str, str]] = []
        for prepared in capability.dispatches:
            event = prepared._occurrence
            if prepared._binary_identity_kind:
                with self._publication_ledger_lock:
                    self._binary_identity_counts[prepared._binary_identity_kind] += 1
            self._record_intent_occurrence(
                event,
                authored_intent_id=prepared._authored_intent_id,
            )
            results.append(
                self._publish_prepared_projection(
                    prepared._projection,
                    authored_intent_id=prepared._authored_intent_id,
                )
            )
        return tuple(results)

    def _apply_prepared_state_and_lifecycle(self, event: CanonicalOccurrence) -> None:
        """Apply one compatibility state intent after every preparation gate has passed."""

        lifecycle_prepared = True
        lifecycle_strict = self._enforce_lifecycle_authority or (
            self._lifecycle_strict_predicate(event)
            if self._lifecycle_strict_predicate is not None
            else False
        )
        if self._lifecycle_shadow is not None:
            try:
                self._lifecycle_shadow.prepare(event)
            except StateError as exc:
                self._lifecycle_shadow.record_violation(event, "prepare", exc)
                lifecycle_prepared = False
                if lifecycle_strict:
                    raise
        if self._lifecycle_shadow is not None and lifecycle_prepared and lifecycle_strict:
            try:
                self._lifecycle_shadow.enforce_pre_apply(event)
            except StateError as exc:
                self._lifecycle_shadow.record_violation(event, "prepare", exc)
                raise
        self.state_manager.apply(event)
        if self._lifecycle_shadow is not None and lifecycle_prepared:
            if lifecycle_strict:
                self._lifecycle_shadow.observe_post_apply(event)
            else:
                try:
                    self._lifecycle_shadow.commit(event)
                except StateError as exc:
                    self._lifecycle_shadow.record_violation(event, "commit", exc)

    def _record_effect_publication(self, event: CanonicalOccurrence) -> None:
        """Record the independent file/registry denominator after canonical state accepts."""

        if self._execution_effect_audit is not None:
            if event.file is not None:
                self._execution_effect_audit.record_published_effect_occurrence(
                    event.effect_provenance,
                    effect_kind=EffectOccurrenceKind.FILE,
                )
            if event.registry is not None:
                self._execution_effect_audit.record_published_effect_occurrence(
                    event.effect_provenance,
                    effect_kind=EffectOccurrenceKind.REGISTRY,
                )

    def _record_intent_occurrence(
        self,
        event: CanonicalOccurrence,
        *,
        authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
    ) -> None:
        """Record one accepted authored occurrence before source suppression/projection."""

        intent_id = self._freeze_authored_intent_id(authored_intent_id)
        if intent_id and self.intent_execution_ledger is not None:
            occurrence_key = (
                event.contract_seal.occurrence.occurrence_key
                if event.contract_seal.occurrence is not None
                else None
            )
            self.intent_execution_ledger.record_occurrence(
                intent_id,
                occurrence_key,
                event.timestamp,
            )

    @staticmethod
    def _source_native_network_occurrence(event: CanonicalOccurrence) -> CanonicalOccurrence:
        """Hide an internal failed-attempt close from source-native duration fields."""

        network = event.network
        if network is None or network.conn_state not in {"REJ", "S0"} or network.duration is None:
            return event
        return replace(
            event,
            network=replace(
                network,
                duration=None,
                closed_at=None,
            ),
        )

    def _prepare_projection(
        self,
        event: CanonicalOccurrence,
        *,
        allowed_formats: frozenset[str] | None = None,
    ) -> _PreparedProjection:
        """Freeze every observation, timing, and projection decision without rendering."""

        event = self._source_native_network_occurrence(event)
        if self._is_suppressed(event.timestamp):
            return _PreparedProjection(
                mode="suppressed",
                occurrence=event,
                initial_statuses=(("all", "out_of_window"),),
            )
        if self.collection_deployment is not None:
            filtered_formats: set[str] = set()
            targets = self._build_projection_targets(
                event,
                filtered_formats_out=filtered_formats,
                allowed_formats=allowed_formats,
            )
            targets = self._apply_deployment_admission(event, targets)
            targets = self._apply_projection_topology(event, targets)
            targets = self._apply_projection_missingness(event, targets)
            finalized_event, targets = self._finalize_projection_timing(event, targets)
            return _PreparedProjection(
                mode="compiled",
                occurrence=finalized_event,
                initial_statuses=tuple(
                    (format_name, "filtered") for format_name in sorted(filtered_formats)
                ),
                compiled_targets=tuple(targets),
            )
        return self._prepare_legacy_projection(event, allowed_formats=allowed_formats)

    def _prepare_legacy_projection(
        self,
        event: CanonicalOccurrence,
        *,
        allowed_formats: frozenset[str] | None = None,
    ) -> _PreparedProjection:
        """Freeze the direct-emitter compatibility projection without publishing it."""

        event = self.source_timing_planner.initialize_event(event)
        filtered_formats: set[str] = set()
        matching_emitters = self._get_matching_emitters(
            event,
            filtered_formats=filtered_formats,
        )
        if allowed_formats is not None:
            matching_emitters = [
                target for target in matching_emitters if target[0] in allowed_formats
            ]
        decisions = {
            format_name: self.observation_policy.decide(format_name, event)
            for format_name, _emitter in matching_emitters
        }
        decisions = {
            format_name: (
                ObservationDecision(status="visible")
                if self._runtime_owns_format_timing(event, format_name)
                and decision.status != "dropped"
                else decision
            )
            for format_name, decision in decisions.items()
        }
        self._enforce_source_observation_contracts(event, decisions)
        observed_formats = {
            format_name
            for format_name, decision in decisions.items()
            if decision.status != "dropped"
        }
        event = replace(event, _observed_formats=frozenset(observed_formats))
        if event.network is not None:
            if event.network_observations_planned:
                planned_observations = event.network_observations
            else:
                planned_observations = self.network_observation_planner.plan(
                    event,
                    observed_formats,
                )
                event = replace(
                    event,
                    network_observations=planned_observations,
                    network_observations_planned=bool(planned_observations),
                )
            event = replace(
                event,
                network_observations=self._admit_network_sensor_observations(event),
            )
        decisions = {
            format_name: (
                ObservationDecision(status="visible")
                if self._runtime_owns_format_timing(event, format_name)
                and decision.status != "dropped"
                else decision
            )
            for format_name, decision in decisions.items()
        }

        targets: list[_LegacyProjectionTarget] = []
        for format_name, emitter in matching_emitters:
            decision = decisions[format_name]
            if decision.status == "dropped":
                targets.append(
                    _LegacyProjectionTarget(
                        format_name=format_name,
                        emitter=emitter,
                        status="dropped",
                    )
                )
                continue
            status: ObservationStatus = (
                "delayed" if decision.delay.total_seconds() > 0 else "visible"
            )
            planned_event = self.source_timing_planner.plan_event(
                event,
                format_name=format_name,
                observation_delay=decision.delay,
                output_end_time=self.output_end_time,
            )
            if not self._admit_source_event(planned_event, format_name):
                targets.append(
                    _LegacyProjectionTarget(
                        format_name=format_name,
                        emitter=emitter,
                        status="out_of_window",
                    )
                )
                continue
            targets.append(
                _LegacyProjectionTarget(
                    format_name=format_name,
                    emitter=emitter,
                    status=status,
                    occurrence=replace(planned_event, _source_observation_status=status),
                )
            )
        return _PreparedProjection(
            mode="legacy",
            occurrence=event,
            initial_statuses=tuple(
                (format_name, "filtered") for format_name in sorted(filtered_formats)
            ),
            legacy_targets=tuple(targets),
        )

    def _publish_prepared_projection(
        self,
        projection: _PreparedProjection,
        *,
        authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
    ) -> dict[str, str]:
        """Render an exact frozen projection and record only accepted publication truth."""

        event = projection.occurrence
        identifiers_by_format: dict[str, str] = {}
        if event.network is not None and self._publishes_network_sensor_observations(event):
            with self._publication_ledger_lock:
                self._latest_network_observations_uid = event.network.zeek_uid
                self._latest_network_observations = event.network_observations
                self._latest_network_plan = event.network
        for format_name, status in projection.initial_statuses:
            self._record_observation(
                event,
                format_name,
                status,
                authored_intent_id=authored_intent_id,
            )
        if projection.mode == "suppressed":
            return identifiers_by_format
        if projection.mode == "compiled":
            self._render_projection_targets(
                event,
                list(projection.compiled_targets),
                identifiers_by_format,
                authored_intent_id=authored_intent_id,
            )
            return identifiers_by_format
        if projection.mode != "legacy":
            raise EventContractError("Prepared dispatch contains an unknown projection mode")
        matching_emitters = [
            (target.format_name, target.emitter) for target in projection.legacy_targets
        ]
        self._initialize_network_identifiers(
            event,
            matching_emitters,
            identifiers_by_format,
        )
        for target in projection.legacy_targets:
            if target.occurrence is None:
                self._record_observation(
                    event,
                    target.format_name,
                    target.status,
                    authored_intent_id=authored_intent_id,
                )
                continue
            self.source_timing_planner.record_admitted_source_event(
                target.occurrence,
                target.format_name,
            )
            self._record_admitted_network_identifier(
                target.occurrence,
                target.format_name,
                identifiers_by_format,
            )
            self._record_observation(
                event,
                target.format_name,
                target.status,
                authored_intent_id=authored_intent_id,
            )
            target.emitter.emit(target.occurrence)
        return identifiers_by_format

    def _publish_action_cohort_projection(
        self,
        projection: _PreparedProjection,
    ) -> dict[str, str]:
        """Render one cohort projection after its timing/intent owners committed."""

        event = projection.occurrence
        identifiers_by_format: dict[str, str] = {}
        if projection.mode == "suppressed":
            return identifiers_by_format
        if projection.mode == "compiled":
            self._render_projection_targets(
                event,
                list(projection.compiled_targets),
                identifiers_by_format,
                authored_intent_id=None,
                record_source_timing=False,
                record_observations=False,
            )
            return identifiers_by_format
        if projection.mode != "legacy":
            raise EventContractError("Prepared dispatch contains an unknown projection mode")
        matching_emitters = [
            (target.format_name, target.emitter) for target in projection.legacy_targets
        ]
        self._initialize_network_identifiers(
            event,
            matching_emitters,
            identifiers_by_format,
        )
        for target in projection.legacy_targets:
            if target.occurrence is None:
                continue
            self._record_admitted_network_identifier(
                target.occurrence,
                target.format_name,
                identifiers_by_format,
            )
            target.emitter.emit(target.occurrence)
        return identifiers_by_format

    def _dispatch_legacy_projections(
        self,
        event: CanonicalOccurrence,
        network_identifiers_by_format: dict[str, str],
    ) -> dict[str, str]:
        """Retain the pre-deployment projection path for direct dispatcher callers."""

        event = self.source_timing_planner.initialize_event(event)
        matching_emitters = self._get_matching_emitters(event)
        decisions = {
            format_name: self.observation_policy.decide(format_name, event)
            for format_name, _emitter in matching_emitters
        }
        decisions = {
            format_name: (
                ObservationDecision(status="visible")
                if self._runtime_owns_format_timing(event, format_name)
                and decision.status != "dropped"
                else decision
            )
            for format_name, decision in decisions.items()
        }
        self._enforce_source_observation_contracts(event, decisions)
        observed_formats = {
            format_name
            for format_name, decision in decisions.items()
            if decision.status != "dropped"
        }
        event = replace(event, _observed_formats=frozenset(observed_formats))
        if event.network is not None:
            if event.network_observations_planned:
                planned_observations = event.network_observations
            else:
                planned_observations = self.network_observation_planner.plan(
                    event,
                    observed_formats,
                )
                event = replace(
                    event,
                    network_observations=planned_observations,
                    network_observations_planned=bool(planned_observations),
                )
            event = replace(
                event,
                network_observations=self._admit_network_sensor_observations(event),
            )
            if self._publishes_network_sensor_observations(event):
                with self._publication_ledger_lock:
                    self._latest_network_observations_uid = event.network.zeek_uid
                    self._latest_network_observations = event.network_observations
                    self._latest_network_plan = event.network
            self._initialize_network_identifiers(
                event,
                matching_emitters,
                network_identifiers_by_format,
            )
        decisions = {
            format_name: (
                ObservationDecision(status="visible")
                if self._runtime_owns_format_timing(event, format_name)
                and decision.status != "dropped"
                else decision
            )
            for format_name, decision in decisions.items()
        }
        for format_name, emitter in matching_emitters:
            decision = decisions[format_name]
            if decision.status == "dropped":
                self._record_observation(event, format_name, "dropped")
                continue
            event_to_emit = event
            status: ObservationStatus = "visible"
            if decision.delay.total_seconds() > 0:
                status = "delayed"
            event_to_emit = self.source_timing_planner.plan_event(
                event_to_emit,
                format_name=format_name,
                observation_delay=decision.delay,
                output_end_time=self.output_end_time,
            )
            if not self._admit_source_event(event_to_emit, format_name):
                self._record_observation(event, format_name, "out_of_window")
                continue
            self.source_timing_planner.record_admitted_source_event(
                event_to_emit,
                format_name,
            )
            self._record_admitted_network_identifier(
                event_to_emit,
                format_name,
                network_identifiers_by_format,
            )
            self._record_observation(event, format_name, status)
            event_to_emit = replace(event_to_emit, _source_observation_status=status)
            emitter.emit(event_to_emit)
        return network_identifiers_by_format

    def _dispatch_compiled_projections(
        self,
        event: CanonicalOccurrence,
        network_identifiers_by_format: dict[str, str],
    ) -> dict[str, str]:
        """Advance exact source targets through the ordered collection stages."""

        targets = self._build_projection_targets(event)
        targets = self._apply_deployment_admission(event, targets)
        targets = self._apply_projection_topology(event, targets)
        targets = self._apply_projection_missingness(event, targets)
        event, targets = self._finalize_projection_timing(event, targets)
        self._render_projection_targets(
            event,
            targets,
            network_identifiers_by_format,
        )
        return network_identifiers_by_format

    def _build_projection_targets(
        self,
        event: CanonicalOccurrence,
        *,
        filtered_formats_out: set[str] | None = None,
        allowed_formats: frozenset[str] | None = None,
    ) -> list[_ProjectionTarget]:
        """Build exact host/sensor targets without scanning deployment buckets."""

        deployment = self.collection_deployment
        assert deployment is not None
        from evidenceforge.generation.source_deployment_compiler import (
            exact_source_instance_id,
        )

        targets: list[_ProjectionTarget] = []
        filtered_formats: set[str] = set()
        target_formats: set[str] = set()
        for format_name, emitter in self.emitters.items():
            if allowed_formats is not None and format_name not in allowed_formats:
                continue
            if not emitter.can_handle(event):
                continue
            descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
            routes: list[tuple[str, ProjectionRole]] = []
            if descriptor.owner is SourceOwnerKind.HOST:
                routes = self._host_projection_routes(format_name, emitter, event)
            elif event.local_only:
                filtered_formats.add(format_name)
            else:
                routes = self._sensor_projection_routes(format_name, descriptor.family, event)
                if not routes:
                    filtered_formats.add(format_name)

            seen_ordinals: set[int] = set()
            for owner_name, role in routes:
                source_instance = exact_source_instance_id(descriptor.family, owner_name)
                ordinal = deployment.ordinal_for_instance(source_instance)
                if ordinal is None and descriptor.owner is SourceOwnerKind.SENSOR:
                    sensor = (
                        self.visibility_engine.get_sensor(owner_name)
                        if self.visibility_engine is not None
                        else None
                    )
                    if sensor is not None:
                        source_instance = exact_source_instance_id(
                            descriptor.family,
                            sensor.name,
                        )
                        ordinal = deployment.ordinal_for_instance(source_instance)
                if ordinal is None or ordinal in seen_ordinals:
                    filtered_formats.add(format_name)
                    continue
                source = deployment.source_by_ordinal(ordinal)
                if format_name not in source.formats:
                    filtered_formats.add(format_name)
                    continue
                seen_ordinals.add(ordinal)
                required, optional = self._projection_capabilities(
                    event,
                    format_name,
                    role,
                )
                targets.append(
                    _ProjectionTarget(
                        format_name=format_name,
                        emitter=emitter,
                        source_ordinal=ordinal,
                        role=role,
                        required_capabilities=required,
                        optional_capabilities=optional,
                    )
                )
                target_formats.add(format_name)

        for format_name in sorted(filtered_formats):
            if format_name not in target_formats:
                if filtered_formats_out is None:
                    self._record_observation(event, format_name, "filtered")
                else:
                    filtered_formats_out.add(format_name)
        return targets

    def _host_projection_routes(
        self,
        format_name: str,
        emitter: LogEmitter,
        event: CanonicalOccurrence,
    ) -> list[tuple[str, ProjectionRole]]:
        """Return renderer-owned host routes without consulting mutable registries."""

        if format_name == "ecar" and event.event_type == "connection":
            routes: list[tuple[str, ProjectionRole]] = []
            if event.src_host is not None:
                routes.append((event.src_host.hostname, ProjectionRole.SOURCE_ENDPOINT))
            if event.dst_host is not None and (
                event.src_host is None
                or event.dst_host.hostname.casefold() != event.src_host.hostname.casefold()
            ):
                routes.append((event.dst_host.hostname, ProjectionRole.DESTINATION_ENDPOINT))
            return routes

        host = None
        if format_name == "windows_event_security":
            candidate = emitter._get_host(event)
            host = candidate if isinstance(getattr(candidate, "hostname", None), str) else None
            host = host or event.src_host or event.dst_host
        elif format_name == "syslog":
            candidate = emitter._linux_host(event)
            host = candidate if isinstance(getattr(candidate, "hostname", None), str) else None
            if host is None:
                host = next(
                    (
                        candidate
                        for candidate in (event.src_host, event.dst_host)
                        if candidate is not None and candidate.os_category == "linux"
                    ),
                    None,
                )
        elif format_name in {"web_access"}:
            host = event.dst_host
        elif format_name == "proxy_access":
            proxy = event.protocol.proxy
            proxy_name = str(getattr(proxy, "proxy_fqdn", "") or "").casefold()
            for candidate in (event.dst_host, event.src_host):
                if candidate is None:
                    continue
                aliases = {
                    candidate.hostname.casefold(),
                    str(candidate.fqdn or "").casefold(),
                }
                if proxy_name and proxy_name in aliases:
                    host = candidate
                    break
            host = host or event.dst_host or event.src_host
        elif format_name == "ecar":
            if event.event_type in {
                "logon",
                "machine_logon",
                "logoff",
                "failed_logon",
                "ssh_session",
                "smb_file_read",
                "smb_file_write",
                "smb_file_rename",
                "smb_file_delete",
                "smb_directory_enumeration",
            }:
                host = event.dst_host or event.src_host
            else:
                host = event.src_host or event.dst_host
        else:
            host = event.src_host or event.dst_host
        return [(host.hostname, ProjectionRole.HOST)] if host is not None else []

    def _sensor_projection_routes(
        self,
        format_name: str,
        family: str,
        event: CanonicalOccurrence,
    ) -> list[tuple[str, ProjectionRole]]:
        """Resolve topology candidates to exact logical sensor IDs with O(1) lookups."""

        del family
        routes_by_owner: dict[str, tuple[str, str]] = {}
        for sensor_identity in event._sensor_hostnames_by_format.get(format_name, ()):
            sensor = (
                self.visibility_engine.get_sensor(sensor_identity)
                if self.visibility_engine is not None
                else None
            )
            owner = str(sensor.name if sensor is not None else sensor_identity)
            normalized = owner.casefold()
            routes_by_owner.setdefault(normalized, (sensor_identity.casefold(), owner))
        return [
            (owner, ProjectionRole.SENSOR)
            for _sensor_identity, owner in sorted(routes_by_owner.values())
        ]

    @staticmethod
    def _projection_capabilities(
        event: CanonicalOccurrence,
        format_name: str,
        role: ProjectionRole,
    ) -> tuple[CollectionCapability, CollectionCapability]:
        """Return hard admission and optional enrichment capability masks."""

        analyzer_capabilities = {
            "zeek_dns": CollectionCapability.DNS | CollectionCapability.DNS_ANALYZER,
            "zeek_http": CollectionCapability.HTTP | CollectionCapability.HTTP_ANALYZER,
            "zeek_ssl": CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "zeek_x509": CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "zeek_ocsp": CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "zeek_files": CollectionCapability.FILE | CollectionCapability.FILE_ANALYZER,
            "zeek_pe": CollectionCapability.FILE | CollectionCapability.FILE_ANALYZER,
            "zeek_smb_files": CollectionCapability.SMB
            | CollectionCapability.FILE
            | CollectionCapability.SMB_ANALYZER
            | CollectionCapability.FILE_ANALYZER,
            "zeek_smb_mapping": CollectionCapability.SMB | CollectionCapability.SMB_ANALYZER,
            "snort_alert": CollectionCapability.IDS,
        }
        optional = CollectionCapability.OPTIONAL_FIELDS
        if event.identity_plan is not None or event.process is not None:
            optional |= CollectionCapability.COHERENT_ACTOR
        if format_name in _NETWORK_FORMATS:
            return (
                CollectionCapability.NETWORK
                | analyzer_capabilities.get(format_name, CollectionCapability.NONE),
                optional,
            )
        if format_name in {"proxy_access", "web_access"}:
            return CollectionCapability.NETWORK | CollectionCapability.HTTP, optional

        required = CollectionCapability.NONE
        event_type = str(event.event_type)
        if event_type in {"connection", "wfp_connection"}:
            required |= CollectionCapability.NETWORK
        if event_type in {
            "process_create",
            "system_process_create",
            "process_terminate",
            "process_access",
            "create_remote_thread",
            "bash_command",
        }:
            required |= CollectionCapability.PROCESS
        if event_type in {
            "logon",
            "machine_logon",
            "logoff",
            "failed_logon",
            "ssh_session",
        }:
            required |= CollectionCapability.AUTHENTICATION
        if event_type in {"logon", "machine_logon", "logoff", "ssh_session"}:
            required |= CollectionCapability.SESSION
        if event.file is not None or event_type.startswith("smb_file_"):
            required |= CollectionCapability.FILE
        if event_type.startswith("smb_"):
            required |= CollectionCapability.SMB
        if event.registry is not None:
            required |= CollectionCapability.REGISTRY
        if event.service is not None:
            required |= CollectionCapability.SERVICE
        if event.scheduled_task is not None:
            required |= CollectionCapability.TASK
        if event.account_management is not None or event.group_membership is not None:
            required |= CollectionCapability.ACCOUNT
        if event_type == "ssh_session" and format_name == "syslog":
            required |= CollectionCapability.SSH
        if role is ProjectionRole.SOURCE_ENDPOINT:
            required |= CollectionCapability.SOURCE_ENDPOINT
        elif role is ProjectionRole.DESTINATION_ENDPOINT:
            required |= CollectionCapability.DESTINATION_ENDPOINT

        return required, optional

    def _apply_deployment_admission(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
    ) -> list[_ProjectionTarget]:
        """Apply exact source enabled/window/capability policy by dense ordinal."""

        deployment = self.collection_deployment
        assert deployment is not None
        return [
            replace(
                target,
                envelope=deployment.projection_envelope_by_ordinal(
                    occurrence_id=event.occurrence_id,
                    target_id=(f"{target.format_name}:{target.role.value}:{target.source_ordinal}"),
                    source_ordinal=target.source_ordinal,
                    canonical_time=event.timestamp,
                    requested_capabilities=target.required_capabilities,
                    optional_capabilities=target.optional_capabilities,
                    role=target.role,
                ),
            )
            for target in targets
        ]

    def _apply_projection_topology(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
    ) -> list[_ProjectionTarget]:
        """Fence exact sensor targets against the frozen topology projection."""

        routed_by_format = {
            format_name: frozenset(sensor.casefold() for sensor in sensor_identities)
            for format_name, sensor_identities in event._sensor_hostnames_by_format.items()
        }
        result: list[_ProjectionTarget] = []
        for target in targets:
            envelope = target.envelope
            assert envelope is not None
            visible = True
            if target.role is ProjectionRole.SENSOR:
                routed = routed_by_format.get(target.format_name, frozenset())
                visible = envelope.source.hostname in routed
                if not visible and self.visibility_engine is not None:
                    sensor = self.visibility_engine.get_sensor(envelope.source.hostname)
                    visible = bool(
                        sensor is not None
                        and (
                            sensor.name.casefold() in routed
                            or str(sensor.hostname or "").casefold() in routed
                        )
                    )
            result.append(replace(target, topology_visible=visible))
        return result

    def _apply_projection_missingness(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
    ) -> list[_ProjectionTarget]:
        """Sample coherent loss independently for every exact source instance."""

        deployment = self.collection_deployment
        assert deployment is not None
        result: list[_ProjectionTarget] = []
        for target in targets:
            envelope = target.envelope
            assert envelope is not None
            if not envelope.admitted or not target.topology_visible:
                result.append(target)
                continue
            policy = deployment.policy_by_ordinal(target.source_ordinal)
            decision = self.observation_policy.decide_projection(
                target.format_name,
                event,
                source_instance=envelope.source.source_instance,
                source_hostname=envelope.source.hostname,
                missingness=policy.missingness_for(target.format_name),
                format_specific=target.format_name in policy.format_missingness,
            )
            if self._runtime_owns_projection_timing(event, target) and decision.status != "dropped":
                # The migrated timing runtime owns source delay. Collection policy
                # decides only whether this exact source can see the occurrence.
                decision = ObservationDecision(status="visible")
            result.append(replace(target, decision=decision))
        return self._enforce_compiled_source_contracts(event, result)

    @staticmethod
    def _runtime_owns_projection_timing(
        event: CanonicalOccurrence,
        target: _ProjectionTarget,
    ) -> bool:
        """Return whether timing is finalized by the engine-owned runtime."""

        return EventDispatcher._runtime_owns_format_timing(event, target.format_name)

    @staticmethod
    def _runtime_owns_format_timing(
        event: CanonicalOccurrence,
        format_name: str,
    ) -> bool:
        """Return whether runtime timing replaces observation delay for one format."""

        from evidenceforge.generation.network_observation import (
            network_observation_owns_format_timing,
        )

        if format_name == "ecar":
            return event.event_type in {
                "process_create",
                "system_process_create",
                "process_terminate",
                "connection",
            }
        if format_name == "windows_event_sysmon":
            return event.event_type in {
                "process_create",
                "system_process_create",
                "process_terminate",
            }
        return network_observation_owns_format_timing(event, format_name)

    def _enforce_compiled_source_contracts(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
    ) -> list[_ProjectionTarget]:
        """Preserve companions within one source without coupling distinct sensors."""

        grouped: dict[str, dict[str, ObservationDecision]] = {}
        for target in targets:
            if target.decision is None or target.envelope is None:
                continue
            grouped.setdefault(target.envelope.source.source_instance, {})[target.format_name] = (
                target.decision
            )
        for decisions in grouped.values():
            self._enforce_source_observation_contracts(event, decisions)

        if _is_successful_remote_interactive_transport(event) and any(
            target.format_name == "ecar"
            and target.decision is not None
            and target.decision.status != "dropped"
            for target in targets
        ):
            for decisions in grouped.values():
                for format_name in ("zeek_conn", "cisco_asa"):
                    decision = decisions.get(format_name)
                    if decision is not None and decision.status == "dropped":
                        decisions[format_name] = ObservationDecision(status="visible")

        return [
            replace(
                target,
                decision=(
                    grouped[target.envelope.source.source_instance][target.format_name]
                    if target.envelope is not None and target.decision is not None
                    else target.decision
                ),
            )
            for target in targets
        ]

    def _finalize_projection_timing(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
    ) -> tuple[CanonicalOccurrence, list[_ProjectionTarget]]:
        """Finalize occurrence-local source timing and admitted sensor observations."""

        event = self.source_timing_planner.initialize_event(event)
        observed_formats = {
            target.format_name
            for target in targets
            if target.envelope is not None
            and target.envelope.admitted
            and target.topology_visible
            and target.decision is not None
            and target.decision.status != "dropped"
        }
        event = replace(event, _observed_formats=frozenset(observed_formats))
        if event.network is not None:
            formats_by_sensor: dict[str, set[str]] = {}
            sensor_identity_by_key: dict[str, str] = {}
            for target in targets:
                envelope = target.envelope
                decision = target.decision
                if (
                    envelope is None
                    or target.role is not ProjectionRole.SENSOR
                    or not envelope.admitted
                    or not target.topology_visible
                    or decision is None
                    or decision.status == "dropped"
                ):
                    continue
                sensor_key = envelope.source.hostname.casefold()
                sensor_identity_by_key.setdefault(sensor_key, envelope.source.hostname)
                formats_by_sensor.setdefault(sensor_key, set()).add(target.format_name)
            if event.network_observations_planned:
                planned = event.network_observations
            else:
                planned = self.network_observation_planner.plan(
                    event,
                    observed_formats,
                    sensor_formats={
                        sensor_identity_by_key[sensor_key]: formats
                        for sensor_key, formats in formats_by_sensor.items()
                    },
                )
            observations: list[NetworkSensorObservation] = []
            for observation in planned:
                allowed = formats_by_sensor.get(observation.sensor_identity.casefold(), set())
                visible = observation.visible_formats & allowed
                if visible:
                    observations.append(replace(observation, visible_formats=frozenset(visible)))
            event = replace(
                event,
                network_observations=tuple(observations),
                network_observations_planned=bool(planned),
            )
            event = replace(
                event,
                network_observations=self._admit_network_sensor_observations(event),
            )
        targets = [
            replace(target, decision=ObservationDecision(status="visible"))
            if target.decision is not None
            and target.decision.status != "dropped"
            and self._runtime_owns_format_timing(event, target.format_name)
            else target
            for target in targets
        ]
        base_source_timing = event.source_timing
        planned_targets: list[_ProjectionTarget] = []
        for target in targets:
            envelope = target.envelope
            decision = target.decision
            if (
                envelope is None
                or not envelope.admitted
                or not target.topology_visible
                or decision is None
                or decision.status == "dropped"
            ):
                planned_targets.append(target)
                continue
            planning_event = replace(
                event,
                source_timing=deepcopy(base_source_timing),
            )
            planned_event = self.source_timing_planner.plan_event(
                planning_event,
                format_name=target.format_name,
                observation_delay=decision.delay,
                source_instance=envelope.source.source_instance,
                source_hostname=envelope.source.hostname,
                projection_role=target.role.value,
                output_end_time=self._projection_output_end(envelope),
            )
            planned_targets.append(
                replace(
                    target,
                    projected_timestamp=planned_event.timestamp,
                    source_timing=deepcopy(planned_event.source_timing),
                )
            )

        finalized_targets: list[_ProjectionTarget] = []
        for target in planned_targets:
            envelope = target.envelope
            decision = target.decision
            if (
                envelope is None
                or not envelope.admitted
                or not target.topology_visible
                or decision is None
                or decision.status == "dropped"
            ):
                finalized_targets.append(target)
                continue
            target_observations = event.network_observations
            if target.role is ProjectionRole.SENSOR:
                sensor_identity = envelope.source.hostname
                target_observations = tuple(
                    self._delay_sensor_observation(observation, decision.delay)
                    for observation in event.network_observations
                    if observation.sensor_identity.casefold() == sensor_identity
                    and target.format_name in observation.visible_formats
                )
            timing_snapshot = target.source_timing
            if timing_snapshot is None:
                raise RuntimeError("projection timing must be frozen after source planning")
            projected_event = replace(
                event,
                timestamp=target.projected_timestamp or event.timestamp,
                source_timing=timing_snapshot,
                network_observations=target_observations,
            )
            observed_time = self._projection_admission_time(projected_event, target)
            finalized_targets.append(
                replace(
                    target,
                    envelope=envelope.with_observed_time(observed_time),
                    source_timing=timing_snapshot,
                    network_observations=target_observations,
                )
            )
        return event, finalized_targets

    def _render_projection_targets(
        self,
        event: CanonicalOccurrence,
        targets: list[_ProjectionTarget],
        identifiers_by_format: dict[str, str],
        *,
        authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
        record_source_timing: bool = True,
        record_observations: bool = True,
    ) -> None:
        """Render finalized envelopes; emitters receive no mutable registry handle."""

        statuses: dict[str, ObservationStatus] = {}
        for target in targets:
            if event.network is not None and target.format_name in _NETWORK_FORMATS:
                # A blank value preserves the planned-but-suppressed correlation contract.
                identifiers_by_format.setdefault(target.format_name, "")
            envelope = target.envelope
            assert envelope is not None
            if not envelope.admitted:
                status: ObservationStatus = (
                    "out_of_window"
                    if envelope.admission is ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW
                    else "filtered"
                )
                self._merge_projection_status(statuses, target.format_name, status)
                continue
            if not target.topology_visible:
                self._merge_projection_status(statuses, target.format_name, "filtered")
                continue
            decision = target.decision
            if decision is None or decision.status == "dropped":
                self._merge_projection_status(statuses, target.format_name, "dropped")
                continue

            status = "delayed" if decision.delay.total_seconds() > 0 else "visible"
            if target.source_timing is None or target.projected_timestamp is None:
                raise RuntimeError("projection timing must be frozen before rendering")
            event_to_emit = replace(
                event,
                timestamp=target.projected_timestamp,
                source_timing=target.source_timing,
                network_observations=(
                    target.network_observations
                    if target.network_observations is not None
                    else event.network_observations
                ),
            )
            if not self._admit_projection_target(event_to_emit, target):
                self._merge_projection_status(
                    statuses,
                    target.format_name,
                    "out_of_window",
                )
                continue

            if envelope.observed_time is None:
                raise RuntimeError("projection envelope must be finalized before rendering")
            event_to_emit = replace(
                event_to_emit,
                _source_observation_status=status,
                _projection_envelope=envelope,
            )
            if record_source_timing:
                self.source_timing_planner.record_admitted_source_event(
                    event_to_emit,
                    target.format_name,
                )
            self._record_admitted_network_identifier(
                event_to_emit,
                target.format_name,
                identifiers_by_format,
            )
            target.emitter.emit(event_to_emit)
            self._merge_projection_status(statuses, target.format_name, status)

        if record_observations:
            for format_name, status in statuses.items():
                self._record_observation(
                    event,
                    format_name,
                    status,
                    authored_intent_id=authored_intent_id,
                )

    @staticmethod
    def _merge_projection_status(
        statuses: dict[str, ObservationStatus],
        format_name: str,
        status: ObservationStatus,
    ) -> None:
        """Retain one aggregate status per format with bounded memory."""

        previous = statuses.get(format_name)
        if previous is None or (
            _OBSERVATION_STATUS_PRECEDENCE[status] > _OBSERVATION_STATUS_PRECEDENCE[previous]
        ):
            statuses[format_name] = status

    def _projection_admission_time(
        self,
        event: CanonicalOccurrence,
        target: _ProjectionTarget,
    ) -> datetime:
        """Return the exact row time represented by one finalized target."""

        if target.format_name == "ecar" and event.event_type == "connection":
            from evidenceforge.generation.source_timing import ecar_flow_render_key

            if target.role is ProjectionRole.SOURCE_ENDPOINT and event.src_host is not None:
                key = ecar_flow_render_key("outbound", event.src_host.hostname)
            elif target.role is ProjectionRole.DESTINATION_ENDPOINT and event.dst_host is not None:
                key = ecar_flow_render_key("inbound", event.dst_host.hostname)
            else:
                key = ""
            if key and event.source_timing is not None:
                observed_time = event.source_timing.finalized_times.get(key)
                if observed_time is not None:
                    return observed_time
        if event.event_type in {"process_create", "system_process_create", "process_terminate"}:
            host = event.src_host or event.dst_host
            if host is not None and event.source_timing is not None:
                lifecycle = "terminate" if event.event_type == "process_terminate" else "create"
                if target.format_name == "ecar":
                    from evidenceforge.generation.source_timing import (
                        ecar_process_render_key,
                    )

                    observed_time = event.source_timing.finalized_times.get(
                        ecar_process_render_key(lifecycle, host.hostname)
                    )
                    if observed_time is not None:
                        return observed_time
                if target.format_name == "windows_event_sysmon":
                    from evidenceforge.generation.source_timing import (
                        sysmon_process_render_key,
                    )

                    observed_time = event.source_timing.finalized_times.get(
                        sysmon_process_render_key(lifecycle, host.hostname)
                    )
                    if observed_time is not None:
                        return observed_time
        return self.source_timing_planner.admission_time(event, target.format_name)

    def _projection_output_end(self, envelope: ProjectionEnvelope) -> datetime | None:
        """Return the strictest exclusive end for one compiled source projection."""

        deployment_end = (
            envelope.collection_window.end if envelope.collection_window is not None else None
        )
        if self.output_end_time is None:
            return deployment_end
        if deployment_end is None:
            return self.output_end_time
        return min(self.output_end_time, deployment_end)

    def _admit_projection_target(
        self,
        event: CanonicalOccurrence,
        target: _ProjectionTarget,
    ) -> bool:
        """Apply output-window admission to one exact finalized source row."""

        envelope = target.envelope
        if envelope is None or envelope.observed_time is None:
            return False
        if (
            event.network_observations_planned
            and target.format_name in _NETWORK_FORMATS
            and not any(
                target.format_name in observation.visible_formats
                for observation in event.network_observations
            )
        ):
            return False
        visible_time = envelope.observed_time
        output_end = self._projection_output_end(envelope)
        lifecycle = event.lifecycle
        if lifecycle is not None:
            source_start = visible_time + self._timestamp_delta(
                lifecycle.canonical_start,
                event.timestamp,
            )
            if output_end is not None and not self._is_before(
                source_start,
                output_end,
            ):
                return False
        if self.output_start_time is not None and self._is_before(
            visible_time,
            self.output_start_time,
        ):
            return False
        return output_end is None or self._is_before(
            visible_time,
            output_end,
        )

    @staticmethod
    def _delay_sensor_observation(
        observation: NetworkSensorObservation,
        delay: timedelta,
    ) -> NetworkSensorObservation:
        """Shift one frozen sensor interval by its exact collection delay."""

        if delay <= timedelta(0):
            return observation
        nat = observation.nat
        if nat is not None:
            nat = replace(
                nat,
                built_time=nat.built_time + delay,
                teardown_time=(
                    nat.teardown_time + delay if nat.teardown_time is not None else None
                ),
            )
        return replace(
            observation,
            observed_start_time=observation.observed_start_time + delay,
            observed_close_time=(
                observation.observed_close_time + delay
                if observation.observed_close_time is not None
                else None
            ),
            firewall_teardown_time=(
                observation.firewall_teardown_time + delay
                if observation.firewall_teardown_time is not None
                else None
            ),
            nat=nat,
        )

    def _derive_occurrence_key(
        self,
        event: OccurrenceBuilder,
        *,
        authored_intent_id: str | None,
    ) -> SemanticOccurrenceKey:
        """Derive stable action-relative identity without dispatch-order state."""

        identity = event.identity_plan
        network = event.network
        lifecycle = event.lifecycle
        auth = event.auth
        process = event.process
        file_context = event.file
        registry = event.registry
        syslog = event.syslog
        owner_key = (
            lifecycle.group_id
            if lifecycle is not None
            else network.stable_id
            if network is not None
            else identity.object_id
            if identity is not None and identity.object_id
            else identity.actor_id
            if identity is not None and identity.actor_id
            else event.storyline_cluster_id
            or authored_intent_id
            or stable_uuid(
                "canonical-action-owner",
                event.event_type,
                getattr(event.src_host, "hostname", ""),
                getattr(event.dst_host, "hostname", ""),
                event.timestamp.isoformat(),
            )
        )
        action_id = stable_uuid("canonical-action", owner_key)
        phase = lifecycle.phase if lifecycle is not None else ""
        role = {
            "start": OccurrenceRole.PRIMARY,
            "dependent": OccurrenceRole.DEPENDENT,
            "closure": OccurrenceRole.CLOSURE,
        }.get(phase, OccurrenceRole.PRIMARY)
        instance_key = stable_uuid(
            "canonical-occurrence-instance",
            event.event_type,
            event.timestamp.isoformat(),
            getattr(event.src_host, "hostname", ""),
            getattr(event.dst_host, "hostname", ""),
            network.stable_id if network is not None else "",
            identity.object_id if identity is not None else "",
            identity.actor_id if identity is not None else "",
            getattr(auth, "logon_id", ""),
            getattr(auth, "username", ""),
            getattr(auth, "source_ip", ""),
            getattr(auth, "source_port", ""),
            getattr(process, "pid", ""),
            getattr(process, "start_time", ""),
            getattr(file_context, "path", ""),
            getattr(file_context, "action", ""),
            getattr(registry, "key", ""),
            getattr(registry, "value", ""),
            getattr(syslog, "app_name", ""),
            getattr(syslog, "pid", ""),
            getattr(syslog, "message", ""),
        )
        return SemanticOccurrenceKey(
            action_id=action_id,
            role=role,
            instance_key=instance_key,
        )

    def _initialize_network_identifiers(
        self,
        event: CanonicalOccurrence,
        matching_emitters: list[tuple[str, LogEmitter]],
        identifiers_by_format: dict[str, str],
    ) -> None:
        """Mark planned network formats suppressed until source admission succeeds."""

        network = event.network
        if network is None or not event.network_observations_planned:
            return
        for format_name, _emitter in matching_emitters:
            if format_name not in _NETWORK_FORMATS:
                continue
            identifiers_by_format[format_name] = ""

    def _record_admitted_network_identifier(
        self,
        event: CanonicalOccurrence,
        format_name: str,
        identifiers_by_format: dict[str, str],
    ) -> None:
        """Publish the observation-owned identifier after final source admission."""

        network = event.network
        if network is None or format_name not in _NETWORK_FORMATS:
            return
        identifier = next(
            (
                observation.connection_uid
                for observation in event.network_observations
                if format_name in observation.visible_formats
            ),
            None,
        )
        if identifier is not None:
            # A format-level compatibility API can expose only one identifier.
            # Targets are rendered in exact sensor-host order, so retain the
            # first admitted identifier just as the legacy multiplex path did.
            if not identifiers_by_format.get(format_name):
                identifiers_by_format[format_name] = identifier

    def _admit_network_sensor_observations(
        self,
        event: CanonicalOccurrence,
    ) -> tuple[NetworkSensorObservation, ...]:
        """Apply half-open end admission independently to sensor observations."""

        if self.output_end_time is None or event.lifecycle is None:
            return event.network_observations
        if event.lifecycle.phase == "closure":
            return event.network_observations
        return tuple(
            observation
            for observation in event.network_observations
            if self._is_before(observation.observed_start_time, self.output_end_time)
        )

    def _admit_source_event(self, event: CanonicalOccurrence, format_name: str) -> bool:
        """Return whether final source-visible timing admits this rendered event."""

        if (
            event.network_observations_planned
            and format_name in _NETWORK_FORMATS
            and not any(
                format_name in observation.visible_formats
                for observation in event.network_observations
            )
        ):
            return False
        visible_time = self.source_timing_planner.admission_time(event, format_name)
        lifecycle = event.lifecycle
        if lifecycle is None:
            return self.output_end_time is None or self._is_before(
                visible_time,
                self.output_end_time,
            )

        source_start = visible_time + self._timestamp_delta(
            lifecycle.canonical_start,
            event.timestamp,
        )
        if self.output_end_time is not None and not self._is_before(
            source_start,
            self.output_end_time,
        ):
            return False
        if self.output_start_time is not None and self._is_before(
            visible_time,
            self.output_start_time,
        ):
            return False
        return self.output_end_time is None or self._is_before(
            visible_time,
            self.output_end_time,
        )

    @staticmethod
    def _is_before(timestamp: datetime, gate: datetime) -> bool:
        """Compare timestamps after normalizing timezone awareness."""

        ts = timestamp
        normalized_gate = gate
        if ts.tzinfo is not None and normalized_gate.tzinfo is None:
            ts = ts.replace(tzinfo=None)
        elif ts.tzinfo is None and normalized_gate.tzinfo is not None:
            normalized_gate = normalized_gate.replace(tzinfo=None)
        return ts < normalized_gate

    @staticmethod
    def _timestamp_delta(later: datetime, earlier: datetime) -> timedelta:
        """Return a delta after aligning naive/aware canonical timestamps."""

        normalized_later = later
        normalized_earlier = earlier
        if normalized_later.tzinfo is not None and normalized_earlier.tzinfo is None:
            normalized_earlier = normalized_earlier.replace(tzinfo=normalized_later.tzinfo)
        elif normalized_later.tzinfo is None and normalized_earlier.tzinfo is not None:
            normalized_later = normalized_later.replace(tzinfo=normalized_earlier.tzinfo)
        return normalized_later - normalized_earlier

    def _enforce_source_observation_contracts(
        self,
        event: CanonicalOccurrence,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Preserve source-local parent rows when child observations survive."""
        self._promote_zeek_parent(decisions, "zeek_conn", _ZEEK_CONN_DEPENDENTS)
        self._promote_zeek_parent(decisions, "zeek_files", _ZEEK_FILES_DEPENDENTS)
        self._promote_zeek_parent(decisions, "zeek_conn", {"zeek_files"})
        self._preserve_zeek_ocsp_transaction_companions(event, decisions)
        self._preserve_zeek_tls_certificate_companions(event, decisions)
        self._preserve_remote_interactive_transport_companions(event, decisions)

    @staticmethod
    def _preserve_zeek_ocsp_transaction_companions(
        event: CanonicalOccurrence,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Apply one Zeek observation decision to an OCSP HTTP/file/response group."""
        if (
            event.protocol.ocsp is None
            or event.protocol.http is None
            or event.protocol.primary_file_transfer is None
        ):
            return
        formats = ("zeek_http", "zeek_files", "zeek_ocsp")
        anchor = next((decisions[name] for name in formats if name in decisions), None)
        if anchor is None:
            return
        for format_name in formats:
            if format_name in decisions:
                decisions[format_name] = anchor

    @staticmethod
    def _preserve_remote_interactive_transport_companions(
        event: CanonicalOccurrence,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Keep successful SSH/RDP network rows when endpoint transport telemetry survives."""

        if not _is_successful_remote_interactive_transport(event):
            return
        endpoint_decision = decisions.get("ecar")
        if endpoint_decision is None or endpoint_decision.status == "dropped":
            return
        for format_name in ("zeek_conn", "cisco_asa"):
            decision = decisions.get(format_name)
            if decision is not None and decision.status == "dropped":
                decisions[format_name] = ObservationDecision(status="visible")

    @staticmethod
    def _preserve_zeek_tls_certificate_companions(
        event: CanonicalOccurrence,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Keep TLS certificate files/x509/ssl rows source-local coherent."""
        if event.protocol.ssl is None or (
            event.protocol.leaf_certificate is None and not event.protocol.x509_chain
        ):
            return
        certificate_formats = ("zeek_files", "zeek_x509")
        anchor = next(
            (
                decisions[format_name]
                for format_name in certificate_formats
                if format_name in decisions and decisions[format_name].status != "dropped"
            ),
            None,
        )
        if anchor is None:
            return
        for format_name in ("zeek_ssl", *certificate_formats):
            decision = decisions.get(format_name)
            if decision is not None and decision.status == "dropped":
                decisions[format_name] = ObservationDecision(
                    status=anchor.status,
                    delay=anchor.delay,
                )

    @staticmethod
    def _promote_zeek_parent(
        decisions: dict[str, ObservationDecision],
        parent_format: str,
        child_formats: set[str],
    ) -> None:
        parent_decision = decisions.get(parent_format)
        if parent_decision is None or parent_decision.status != "dropped":
            return
        for child_format in child_formats:
            child_decision = decisions.get(child_format)
            if child_decision is None or child_decision.status == "dropped":
                continue
            decisions[parent_format] = ObservationDecision(
                status=child_decision.status,
                delay=child_decision.delay,
            )
            return

    def dispatch_raw(self, request: RawProjectionRequest) -> None:
        """Route a source-local request without creating a canonical occurrence.

        ``target_format`` must match a key in the configured emitters.
        """
        if self._is_suppressed(request.timestamp):
            self._record_raw_observation(request, "out_of_window")
            return
        if self.output_end_time is not None and not self._is_before(
            request.timestamp,
            self.output_end_time,
        ):
            self._record_raw_observation(request, "out_of_window")
            return
        emitter = self.emitters.get(request.target_format)
        if emitter is None:
            raise KeyError(f"Unknown emitter: {request.target_format!r}")
        if request.local_only and request.target_format in _NETWORK_FORMATS:
            self._record_raw_observation(request, "filtered")
            return
        decision = self.observation_policy.decide_raw(request)
        if decision.status == "dropped":
            self._record_raw_observation(request, "dropped")
            return
        emitter.emit_raw(request.data)
        self._record_raw_observation(request, decision.status)

    def _record_raw_observation(
        self,
        request: RawProjectionRequest,
        status: ObservationStatus,
    ) -> None:
        """Record raw visibility without claiming a canonical occurrence."""

        if request.storyline_cluster_id:
            self._record_cluster_observation(
                request.target_format,
                status,
                cluster_id=request.storyline_cluster_id,
                timestamp=request.timestamp,
            )

    def _finalize_network_routing(self, event: OccurrenceBuilder) -> None:
        """Resolve sensor routing and NAT while the private builder is still mutable."""

        if event.network is None or self.visibility_engine is None:
            return
        is_link_local = event.network.link_local
        is_fw_deny = event.firewall is not None and event.firewall.action == "deny"
        if is_link_local:
            event._visible_network_formats = set(
                self.visibility_engine.get_log_formats_for_link_local(event.network.src_ip)
            )
            sensors = self.visibility_engine.get_link_local_sensors(event.network.src_ip)
        elif is_fw_deny:
            event._visible_network_formats = set(
                self.visibility_engine.get_log_formats_for_source_only(
                    event.network.src_ip,
                    event.network.dst_ip,
                )
            )
            sensors = self.visibility_engine.get_source_side_sensors(
                event.network.src_ip,
                event.network.dst_ip,
            )
        else:
            event._visible_network_formats = set(
                self.visibility_engine.get_log_formats_for_connection(
                    event.network.src_ip,
                    event.network.dst_ip,
                )
            )
            sensors = self.visibility_engine.get_observing_sensors(
                event.network.src_ip,
                event.network.dst_ip,
            )
        format_to_sensors: dict[str, list[str]] = {}
        for sensor in sensors:
            hostname = sensor.hostname or sensor.name
            for format_name in expand_formats(sensor.log_formats):
                format_to_sensors.setdefault(format_name, []).append(hostname)
        event._sensor_hostnames_by_format = format_to_sensors

        if not is_link_local and not is_fw_deny and event.nat is None:
            event.nat = self.visibility_engine.compute_nat(
                event.network.src_ip,
                event.network.dst_ip,
                event.network.src_port,
                event.network.dst_port,
            )

    def _get_matching_emitters(
        self,
        event: CanonicalOccurrence,
        *,
        filtered_formats: set[str] | None = None,
    ) -> list[tuple[str, LogEmitter]]:
        """Two-layer filtering: format eligibility + network visibility."""
        visible_formats: set[str] | None = None
        if event.network is not None and self.visibility_engine is not None:
            visible_formats = set(event._visible_network_formats)

        matched = []
        for format_name, emitter in self.emitters.items():
            if not emitter.can_handle(event):
                continue
            # Host-local events (same src/dst IP) are invisible to network sensors
            if event.local_only and format_name in _NETWORK_FORMATS:
                if filtered_formats is None:
                    self._record_observation(event, format_name, "filtered")
                else:
                    filtered_formats.add(format_name)
                continue
            # Network visibility filter: only applies to network-format emitters
            if visible_formats is not None and format_name in _NETWORK_FORMATS:
                if format_name not in visible_formats:
                    if filtered_formats is None:
                        self._record_observation(event, format_name, "filtered")
                    else:
                        filtered_formats.add(format_name)
                    continue
            matched.append((format_name, emitter))
        return matched

    def _record_observation(
        self,
        event: CanonicalOccurrence,
        format_name: str,
        status: ObservationStatus,
        *,
        authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
    ) -> None:
        """Record source evidence status for storyline/red-herring ground truth."""
        cluster_id = event.storyline_cluster_id
        if not cluster_id:
            return
        self._record_cluster_observation(
            format_name,
            status,
            cluster_id=cluster_id,
            timestamp=event.timestamp,
            authored_intent_id=authored_intent_id,
        )

    def _record_cluster_observation(
        self,
        format_name: str,
        status: ObservationStatus,
        *,
        cluster_id: str | None = None,
        timestamp: datetime | None = None,
        authored_intent_id: object = _CURRENT_AUTHORED_INTENT,
    ) -> None:
        """Record source evidence status for the active or supplied cluster."""
        cluster_id = cluster_id or self.storyline_cluster_id
        if not cluster_id:
            return
        source = source_family_for_format(format_name)
        with self._source_evidence_lock:
            cluster = self._source_evidence_status.setdefault(cluster_id, {})
            source_counts = cluster.setdefault(source, ObservationSummary())
            source_counts.record(status)
            self._source_evidence_version += 1
        intent_id = self._freeze_authored_intent_id(authored_intent_id)
        if intent_id and self.intent_execution_ledger is not None:
            self.intent_execution_ledger.record_observation(
                intent_id,
                source,
                status,
                timestamp,
            )

    def reconcile_ids_policy_filtering(
        self,
        cluster_id: str,
        *,
        emitted_visible: int,
        emitted_delayed: int,
        policy_filtered: int,
    ) -> None:
        """Replace pre-policy IDS admissions with finalized alert-level counts."""
        if not cluster_id:
            return
        with self._source_evidence_lock:
            cluster = self._source_evidence_status.setdefault(cluster_id, {})
            summary = cluster.setdefault("ids", ObservationSummary())
            summary.visible = emitted_visible
            summary.delayed = emitted_delayed
            summary.filtered += policy_filtered
            self._source_evidence_version += 1
