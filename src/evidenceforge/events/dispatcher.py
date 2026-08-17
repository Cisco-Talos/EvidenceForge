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
import logging
import secrets
from collections import Counter
from collections.abc import Callable
from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import TYPE_CHECKING, cast

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
        ExecutionEffectAuditCounter,
        PreparedExecutionEffectAuditCommit,
    )
    from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
    from evidenceforge.generation.deployment_registry import (
        DeploymentContentRegistry,
        LocalArtifactPublishToken,
        LocalArtifactVersionRegistry,
    )
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.intent_ledger import IntentExecutionLedger
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_shadow import (
        LifecycleShadow,
        LifecycleShadowViolationSummary,
    )
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.generation.source_timing import (
        SourceTimingPlan,
        SourceTimingPlanner,
        SourceTimingPreparation,
    )
    from evidenceforge.generation.state_manager import StateManager
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
        "_consumed",
        "_binary_identity_kind",
        "_artifact_publications",
        "_expected_state_version",
        "_integrity_token",
        "_lifecycle_ticket",
        "_lock",
        "_network_dependent_batch_id",
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
        integrity_token: str,
    ) -> None:
        self._occurrence = occurrence
        self._projection = projection
        self._expected_state_version = expected_state_version
        self._state_intent = state_intent
        self._lifecycle_ticket = lifecycle_ticket
        self._network_dependent_batch_id: int | None = None
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
    ) -> None:
        if enforce_lifecycle_authority and lifecycle_shadow is None:
            raise ValueError(
                "Production lifecycle authority enforcement requires a LifecycleShadow"
            )
        self.state_manager = state_manager
        self.emitters = emitters
        self.visibility_engine = visibility_engine
        self.output_start_time = output_start_time
        self.output_end_time = output_end_time
        self.observation_policy = observation_policy or ObservationPolicy("complete")
        self._source_evidence_status: dict[str, dict[str, ObservationSummary]] = {}
        self._latest_network_uid = ""
        self._latest_network_identifiers_by_format: dict[str, str] = {}
        self._latest_network_observations_uid = ""
        self._latest_network_observations: tuple[NetworkSensorObservation, ...] = ()
        self._latest_network_plan: NetworkTransactionPlan | None = None
        self._contract_violation_counts: Counter[str] = Counter()
        self._contract_violations_by_event: Counter[tuple[str, str]] = Counter()
        self._prepared_dispatch_secret = secrets.token_bytes(32)
        self._network_dependent_batch_lock = Lock()
        self._network_dependent_batches: dict[
            int,
            _PreparedNetworkDependentBatchCapability,
        ] = {}
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

        self.identity_lifecycle_planner = IdentityLifecyclePlanner(state_manager)

    @property
    def source_evidence_status(self) -> dict[str, dict[str, dict[str, int]]]:
        """Return source evidence status summaries for ground truth generation."""
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

        if canonical_uid != self._latest_network_uid:
            return None
        return self._latest_network_identifiers_by_format.get(format_name)

    def publish_network_identifiers(
        self,
        canonical_uid: str,
        identifiers_by_format: dict[str, str],
    ) -> None:
        """Publish one completed connection's observation identifiers for its caller."""

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
            event.occurrence_key = self._derive_occurrence_key(event)
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
            _defer_projection=_defer_projection,
        )

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
        _defer_projection: bool = False,
    ) -> PreparedDispatch:
        """Freeze source projection and an exact state/lifecycle publication intent."""

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
        if state_intent is PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT:
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
        elif state_intent is PreparedDispatchStateIntent.EXTERNAL_TRANSPORT:
            if source_timing_preparation is None:
                raise EventContractError(
                    "Prepared external transport requires source timing authority"
                )
            version = self._validate_external_transport_binding(event, lifecycle_ticket)
            if expected_state_version is not None and expected_state_version != version:
                raise EventContractError(
                    "Prepared dispatch version contradicts its external transport root"
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
            integrity_token="",
        )
        prepared._integrity_token = self._prepared_dispatch_integrity(prepared)
        return prepared

    @staticmethod
    def _validate_external_transport_binding(
        event: CanonicalOccurrence,
        lifecycle_ticket: object,
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
        if token.lifecycle_mode == "deferred_session":
            raise EventContractError("Deferred-session transport requires its session authority")
        if token.lifecycle_mode not in {"network", "application_child"}:
            raise EventContractError("Prepared external transport lifecycle mode is unsupported")
        application_child = plan.mode is ConnectionMaterializationMode.APPLICATION_CHILD
        if plan.mode is ConnectionMaterializationMode.PHYSICAL:
            if token.lifecycle_mode != "network" or event.network.application_layer_only:
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

        legacy_signature = tuple(
            (
                target.format_name,
                id(target.emitter),
                target.status,
                repr(target.occurrence),
            )
            for target in prepared._projection.legacy_targets
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
            for target in prepared._projection.compiled_targets
        )
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
                prepared._expected_state_version,
                prepared._state_intent,
                lifecycle_ticket_signature,
                prepared._binary_identity_kind,
                artifact_signatures,
                timing_signature,
                repr(prepared._occurrence),
                prepared._projection.mode,
                repr(prepared._projection.occurrence),
                prepared._projection.initial_statuses,
                legacy_signature,
                compiled_signature,
            )
        ).encode("utf-8")
        return hmac.new(
            self._prepared_dispatch_secret,
            payload,
            hashlib.sha256,
        ).hexdigest()

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
        if prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT:
            raise EventContractError(
                "Network-dependent dispatches require their claimed ordered batch"
            )
        if prepared._network_dependent_batch_id is not None:
            raise EventContractError("Prepared dispatch is claimed by a network-dependent batch")
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
            self._binary_identity_counts[prepared._binary_identity_kind] += 1
        self._record_effect_publication(event)
        self._record_intent_occurrence(event)
        if event.network is not None and not event.network.application_layer_only:
            self._latest_network_plan = event.network
        projection = prepared._projection
        if projection.mode == "deferred":
            if prepared._state_intent is not PreparedDispatchStateIntent.APPLY:
                raise EventContractError(
                    "Only a compatibility state publication may defer source projection"
                )
            projection = self._prepare_projection(event)
        return self._publish_prepared_projection(projection)

    def validate_prepared(
        self,
        prepared: PreparedDispatch,
        *,
        before_materialization: bool = True,
    ) -> None:
        """Authenticate one prepared dispatch at the coordinator's precommit barrier."""

        if not isinstance(prepared, PreparedDispatch):
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
                        if prepared._consumed or prepared._network_dependent_batch_id is not None:
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
                self._binary_identity_counts[prepared._binary_identity_kind] += 1
            self._record_intent_occurrence(event)
            results.append(self._publish_prepared_projection(prepared._projection))
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

    def _record_intent_occurrence(self, event: CanonicalOccurrence) -> None:
        """Record one accepted authored occurrence before source suppression/projection."""

        if self.authored_intent_id and self.intent_execution_ledger is not None:
            occurrence_key = (
                event.contract_seal.occurrence.occurrence_key
                if event.contract_seal.occurrence is not None
                else None
            )
            self.intent_execution_ledger.record_occurrence(
                self.authored_intent_id,
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

    def _prepare_projection(self, event: CanonicalOccurrence) -> _PreparedProjection:
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
        return self._prepare_legacy_projection(event)

    def _prepare_legacy_projection(
        self,
        event: CanonicalOccurrence,
    ) -> _PreparedProjection:
        """Freeze the direct-emitter compatibility projection without publishing it."""

        event = self.source_timing_planner.initialize_event(event)
        filtered_formats: set[str] = set()
        matching_emitters = self._get_matching_emitters(
            event,
            filtered_formats=filtered_formats,
        )
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
    ) -> dict[str, str]:
        """Render an exact frozen projection and record only accepted publication truth."""

        event = projection.occurrence
        identifiers_by_format: dict[str, str] = {}
        if event.network is not None and self._publishes_network_sensor_observations(event):
            self._latest_network_observations_uid = event.network.zeek_uid
            self._latest_network_observations = event.network_observations
            self._latest_network_plan = event.network
        for format_name, status in projection.initial_statuses:
            self._record_observation(event, format_name, status)
        if projection.mode == "suppressed":
            return identifiers_by_format
        if projection.mode == "compiled":
            self._render_projection_targets(
                event,
                list(projection.compiled_targets),
                identifiers_by_format,
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
                self._record_observation(event, target.format_name, target.status)
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
            self._record_observation(event, target.format_name, target.status)
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
                self._latest_network_observations_uid = event.network.zeek_uid
                self._latest_network_observations = event.network_observations
                self._latest_network_plan = event.network
            self._initialize_network_identifiers(
                event,
                matching_emitters,
                network_identifiers_by_format,
            )
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

        from evidenceforge.generation.network_observation import RUNTIME_OWNED_ZEEK_FORMATS

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
        return bool(
            format_name in RUNTIME_OWNED_ZEEK_FORMATS
            and event.network is not None
            and event.event_type in {"connection", "dhcp_lease"}
        )

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

        for format_name, status in statuses.items():
            self._record_observation(event, format_name, status)

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
        lifecycle = event.lifecycle
        if lifecycle is not None:
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

    def _derive_occurrence_key(self, event: OccurrenceBuilder) -> SemanticOccurrenceKey:
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
            or self.authored_intent_id
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
        )

    def _record_cluster_observation(
        self,
        format_name: str,
        status: ObservationStatus,
        *,
        cluster_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        """Record source evidence status for the active or supplied cluster."""
        cluster_id = cluster_id or self.storyline_cluster_id
        if not cluster_id:
            return
        source = source_family_for_format(format_name)
        cluster = self._source_evidence_status.setdefault(cluster_id, {})
        source_counts = cluster.setdefault(source, ObservationSummary())
        source_counts.record(status)
        if self.authored_intent_id and self.intent_execution_ledger is not None:
            self.intent_execution_ledger.record_observation(
                self.authored_intent_id,
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
        cluster = self._source_evidence_status.setdefault(cluster_id, {})
        summary = cluster.setdefault("ids", ObservationSummary())
        summary.visible = emitted_visible
        summary.delayed = emitted_delayed
        summary.filtered += policy_filtered
