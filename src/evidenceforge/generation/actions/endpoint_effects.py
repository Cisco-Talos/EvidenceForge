# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free plans for process-owned file, registry, and transfer effects.

The action owns planning and exact reconciliation only.  Source-native rendering
continues to consume canonical occurrences, and protocol managers remain the
owners of SMB/HTTP/SSH channel state.  A production adapter must resolve one
exact process binding, preflight the complete immutable plan, stage all required
occurrences, and publish them atomically before returning outcomes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Protocol, TypeAlias

from evidenceforge.events.content_identity import canonical_native_path
from evidenceforge.events.contracts import OccurrenceRole
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    EffectActorRef,
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ExecutionEffectReconciliation,
    FileEffectAction,
    FileEffectIntent,
    RegistryEffectAction,
    RegistryEffectIntent,
    TransferEffectIntent,
)
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc

_MAX_EFFECT_NODES = 64
_MAX_EFFECT_OCCURRENCES = 4096

EndpointEffectIntent: TypeAlias = FileEffectIntent | RegistryEffectIntent | TransferEffectIntent


class EndpointStateDisposition(StrEnum):
    """How a file or registry mutation reaches an explicit final state."""

    NONE = "none"
    DURABLE_FINAL = "durable_final"
    EPHEMERAL = "ephemeral"


@dataclass(frozen=True, slots=True)
class PreparedProcessEffectActor:
    """Allocation-free root-process identity used before PID publication."""

    hostname: str
    image: str
    command_line: str
    username: str
    logon_id: str
    lifecycle_id: str
    started_at: datetime
    session_deadline: datetime | None = None

    def __post_init__(self) -> None:
        text_fields = {
            "hostname": self.hostname,
            "image": self.image,
            "username": self.username,
            "lifecycle_id": self.lifecycle_id,
        }
        empty = next((name for name, value in text_fields.items() if not value.strip()), None)
        if empty is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"prepared endpoint effect actor {empty} cannot be empty",
            )
        started_at = ensure_utc(self.started_at)
        session_deadline = (
            ensure_utc(self.session_deadline) if self.session_deadline is not None else None
        )
        if session_deadline is not None and session_deadline <= started_at:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "prepared endpoint effect actor session deadline must follow process start",
            )
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "session_deadline", session_deadline)

    @property
    def stable_id(self) -> str:
        """Return the PID-independent identity of the prepared root intent."""

        return stable_uuid(
            "prepared-endpoint-effect-actor",
            self.hostname.casefold(),
            self.image.casefold(),
            self.command_line,
            self.username,
            self.logon_id,
            self.lifecycle_id,
            self.started_at.isoformat(),
        )


@dataclass(frozen=True, slots=True)
class PreparedFileEffectPayload:
    """Source-native fields frozen for one planned file occurrence."""

    path: str
    action: FileEffectAction
    artifact_publication: LocalArtifactPublishToken | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.path.strip() or not isinstance(self.action, FileEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "prepared file payload requires an exact path and action",
            )
        publication = self.artifact_publication
        if publication is None:
            return
        if self.action not in {FileEffectAction.CREATE, FileEffectAction.MODIFY}:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "only file create/modify effects may publish a runtime artifact version",
            )
        artifact = publication.record.artifact
        expected_path = canonical_native_path(self.path, artifact.platform)
        if canonical_native_path(artifact.native_path, artifact.platform) != expected_path:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared artifact publication path drifted from its file effect",
            )


@dataclass(frozen=True, slots=True)
class PreparedRegistryEffectPayload:
    """Source-native fields frozen for one planned registry occurrence."""

    key: str
    value_name: str
    value: str
    value_type: str
    action: RegistryEffectAction

    def __post_init__(self) -> None:
        if (
            not self.key.strip()
            or not self.value_name.strip()
            or not self.value_type.strip()
            or not isinstance(self.action, RegistryEffectAction)
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "prepared registry payload requires exact key/value/type/action fields",
            )


EndpointEffectPayload: TypeAlias = PreparedFileEffectPayload | PreparedRegistryEffectPayload


@dataclass(frozen=True, slots=True)
class ExactProcessEffectActor:
    """Immutable process identity and lifecycle fence for endpoint effects."""

    hostname: str
    pid: int
    process_object_id: str
    lifecycle_id: str
    image: str
    command_line: str
    username: str
    logon_id: str
    started_at: datetime
    closes_at: datetime | None = None

    def __post_init__(self) -> None:
        text_fields = {
            "hostname": self.hostname,
            "process_object_id": self.process_object_id,
            "lifecycle_id": self.lifecycle_id,
            "image": self.image,
            "username": self.username,
        }
        empty = next((name for name, value in text_fields.items() if not value.strip()), None)
        if empty is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"endpoint effect actor {empty} cannot be empty",
            )
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "endpoint effect actor PID must be a positive integer",
            )
        started_at = ensure_utc(self.started_at)
        closes_at = ensure_utc(self.closes_at) if self.closes_at is not None else None
        if closes_at is not None and closes_at <= started_at:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "endpoint effect actor close must follow process start",
            )
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "closes_at", closes_at)

    @property
    def stable_id(self) -> str:
        """Return identity for this exact process instance, not only its PID."""

        return stable_uuid(
            "endpoint-effect-actor",
            self.hostname.casefold(),
            self.pid,
            self.process_object_id,
            self.lifecycle_id,
            self.started_at.isoformat(),
        )


@dataclass(frozen=True, slots=True)
class EndpointEffectSpec:
    """One bounded endpoint-effect node and its canonical occurrence schedule."""

    intent: EndpointEffectIntent
    occurrence_times: tuple[datetime, ...]
    instance_key: str
    role: OccurrenceRole = OccurrenceRole.DEPENDENT
    requirement: EffectRequirement = EffectRequirement.REQUIRED
    depends_on: tuple[str, ...] = ()
    state_disposition: EndpointStateDisposition = EndpointStateDisposition.NONE
    retention_deadline: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.intent, (FileEffectIntent, RegistryEffectIntent, TransferEffectIntent)
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported endpoint effect intent {type(self.intent).__name__}",
            )
        if not self.instance_key.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "endpoint effect instance_key cannot be empty",
            )
        if self.role not in {OccurrenceRole.DEPENDENT, OccurrenceRole.CLOSURE}:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "process-owned endpoint effects must be dependent or closure nodes",
            )
        occurrence_times = tuple(ensure_utc(value) for value in self.occurrence_times)
        if len(occurrence_times) != self.intent.occurrence_cardinality:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect occurrence schedule must exactly match intent cardinality",
            )
        if tuple(sorted(occurrence_times)) != occurrence_times:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect occurrence schedule must be monotonic",
            )
        dependencies = tuple(self.depends_on)
        if len(dependencies) != len(set(dependencies)) or any(
            not dependency.strip() for dependency in dependencies
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "endpoint effect dependencies must be unique nonempty instance keys",
            )
        if self.instance_key in dependencies:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.CYCLIC_DEPENDENCY,
                "endpoint effect cannot depend on itself",
            )
        retention_deadline = (
            ensure_utc(self.retention_deadline) if self.retention_deadline is not None else None
        )
        mutates_state = _intent_mutates_endpoint_state(self.intent)
        if mutates_state and self.state_disposition == EndpointStateDisposition.NONE:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "file/registry create or modify effects require an explicit final-state disposition",
            )
        if not mutates_state and self.state_disposition != EndpointStateDisposition.NONE:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "read/delete/transfer effects cannot declare retained mutation state",
            )
        if self.state_disposition == EndpointStateDisposition.DURABLE_FINAL:
            if retention_deadline is None or retention_deadline <= occurrence_times[-1]:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "durable endpoint state requires a bounded retention deadline after its effect",
                )
        elif retention_deadline is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "only durable endpoint state may carry a retention deadline",
            )
        object.__setattr__(self, "occurrence_times", occurrence_times)
        object.__setattr__(self, "depends_on", dependencies)
        object.__setattr__(self, "retention_deadline", retention_deadline)


@dataclass(frozen=True, slots=True)
class PreparedEndpointEffect:
    """One allocation-free effect specification plus frozen native payload."""

    spec: EndpointEffectSpec
    event_type: str
    payload: EndpointEffectPayload

    def __post_init__(self) -> None:
        if not self.event_type.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint effect requires a source-native event type",
            )
        intent = self.spec.intent
        if isinstance(intent, FileEffectIntent):
            if not isinstance(self.payload, PreparedFileEffectPayload) or (
                self.payload.path != intent.path or self.payload.action != intent.action
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared file payload drifted from its exact effect intent",
                )
            return
        if isinstance(intent, RegistryEffectIntent):
            if not isinstance(self.payload, PreparedRegistryEffectPayload) or (
                self.payload.key.casefold() != intent.key.casefold()
                or self.payload.value_name.casefold() != intent.value_name.casefold()
                or self.payload.action != intent.action
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared registry payload drifted from its exact effect intent",
                )
            return
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_INTENT,
            "prepared process endpoint payloads support only file and registry effects",
        )


@dataclass(frozen=True, slots=True)
class PreparedProcessEndpointEffectPlan:
    """PID-independent root binding, effect DAG, schedules, and native payloads."""

    root_anchor: ActionAnchor
    actor: PreparedProcessEffectActor
    window_end: datetime
    retention_horizon_end: datetime
    effects: tuple[PreparedEndpointEffect, ...]
    source: str = "process_execution_endpoint_effects"
    execution_plan: ExecutionEffectPlan | None = field(default=None, compare=False, repr=False)
    suppressed_instance_keys: tuple[str, ...] = field(
        default=(),
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.root_anchor.family != "process_execution":
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint effects require the exact process-execution root anchor",
            )
        if not self.source.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint effect source cannot be empty",
            )
        effects = tuple(sorted(tuple(self.effects), key=lambda item: item.spec.instance_key))
        if not effects or len(effects) > _MAX_EFFECT_NODES:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                f"prepared endpoint effects require 1..{_MAX_EFFECT_NODES} nodes",
            )
        specs = tuple(item.spec for item in effects)
        total_occurrences = sum(spec.intent.occurrence_cardinality for spec in specs)
        if total_occurrences > _MAX_EFFECT_OCCURRENCES:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                f"prepared endpoint effects cannot exceed {_MAX_EFFECT_OCCURRENCES} occurrences",
            )
        window_end = ensure_utc(self.window_end)
        horizon_end = ensure_utc(self.retention_horizon_end)
        if window_end <= self.actor.started_at or horizon_end < window_end:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint root/window/retention interval is invalid",
            )

        suppressed: list[str] = []
        for spec in specs:
            reason = _endpoint_spec_admission_error(
                spec,
                anchor_time=self.actor.started_at,
                window_end=window_end,
                retention_horizon_end=horizon_end,
                actor_end=self.actor.session_deadline,
            )
            if reason is None:
                continue
            if spec.requirement != EffectRequirement.OPTIONAL:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    reason,
                )
            suppressed.append(spec.instance_key)

        expected_plan = _build_endpoint_effect_graph(self.anchor, specs)
        candidate = self.execution_plan
        if candidate is not None and candidate != expected_plan:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process endpoint effect graph drifted from its exact intent",
            )
        object.__setattr__(self, "effects", effects)
        object.__setattr__(self, "window_end", window_end)
        object.__setattr__(self, "retention_horizon_end", horizon_end)
        object.__setattr__(self, "execution_plan", expected_plan)
        object.__setattr__(self, "suppressed_instance_keys", tuple(sorted(suppressed)))

    @property
    def stable_id(self) -> str:
        """Return a worker/order-stable identity independent of the future PID."""

        effect_keys = tuple(
            (
                item.spec.instance_key,
                item.spec.intent.semantic_key,
                item.spec.requirement.value,
                tuple(timestamp.isoformat() for timestamp in item.spec.occurrence_times),
            )
            for item in self.effects
        )
        return stable_uuid(
            "prepared-process-endpoint-effects",
            self.root_anchor.stable_id,
            self.actor.stable_id,
            self.window_end.isoformat(),
            effect_keys,
            self.source,
        )

    @property
    def anchor(self) -> ActionAnchor:
        """Return the action anchor shared with the later exact-PID binding."""

        return ActionAnchor(
            family="process_owned_endpoint_effect",
            stable_id=self.stable_id,
            source=self.source,
        )

    @property
    def specs(self) -> tuple[EndpointEffectSpec, ...]:
        """Return all required, admitted optional, and explicitly suppressed specs."""

        return tuple(item.spec for item in self.effects)

    @property
    def admitted_effects(self) -> tuple[PreparedEndpointEffect, ...]:
        """Return effects that own source-native occurrences in this output window."""

        suppressed = frozenset(self.suppressed_instance_keys)
        return tuple(item for item in self.effects if item.spec.instance_key not in suppressed)

    @property
    def earliest_admitted_occurrence(self) -> datetime | None:
        """Return the first admitted occurrence, or ``None`` when all optionals omit."""

        values = tuple(
            timestamp for item in self.admitted_effects for timestamp in item.spec.occurrence_times
        )
        return min(values) if values else None

    @property
    def latest_admitted_occurrence(self) -> datetime | None:
        """Return the last admitted occurrence, or ``None`` when all optionals omit."""

        values = tuple(
            timestamp for item in self.admitted_effects for timestamp in item.spec.occurrence_times
        )
        return max(values) if values else None


@dataclass(frozen=True, slots=True)
class EndpointEffectOccurrence:
    """One derived canonical occurrence with exact actor and subject identity."""

    node_id: str
    ordinal: int
    timestamp: datetime
    occurrence_id: str
    subject_id: str
    actor_process_object_id: str
    actor_lifecycle_id: str


@dataclass(frozen=True, slots=True)
class EndpointEffectExecutionPlan:
    """Frozen process binding, effect DAG, schedules, and retention horizon."""

    actor: ExactProcessEffectActor
    effects: ExecutionEffectPlan
    specs: tuple[EndpointEffectSpec, ...]
    window_end: datetime
    retention_horizon_end: datetime
    durable_node_ids: tuple[str, ...]
    suppressed_instance_keys: tuple[str, ...] = ()

    def occurrences(self) -> Iterator[EndpointEffectOccurrence]:
        """Stream exact occurrences without retaining per-occurrence history."""

        nodes_by_instance = {node.instance_key: node for node in self.effects.nodes}
        suppressed = frozenset(self.suppressed_instance_keys)
        for spec in self.specs:
            if spec.instance_key in suppressed:
                continue
            node = nodes_by_instance[spec.instance_key]
            subject_id = stable_uuid(
                "endpoint-effect-subject",
                self.actor.hostname.casefold(),
                spec.intent.kind,
                spec.intent.semantic_key,
            )
            for ordinal, timestamp in enumerate(spec.occurrence_times):
                yield EndpointEffectOccurrence(
                    node_id=node.node_id,
                    ordinal=ordinal,
                    timestamp=timestamp,
                    occurrence_id=stable_uuid(
                        "endpoint-effect-occurrence",
                        self.effects.action_id,
                        node.node_id,
                        ordinal,
                        timestamp.isoformat(),
                    ),
                    subject_id=subject_id,
                    actor_process_object_id=self.actor.process_object_id,
                    actor_lifecycle_id=self.actor.lifecycle_id,
                )


@dataclass(frozen=True, slots=True)
class EndpointEffectPreparedCommit:
    """Bounded staged outcomes that are validated before atomic publication."""

    action_id: str
    actor_id: str
    outcomes: tuple[EffectExecutionOutcome, ...]
    commit_token: str

    @classmethod
    def create(
        cls,
        plan: EndpointEffectExecutionPlan,
        outcomes: tuple[EffectExecutionOutcome, ...],
    ) -> EndpointEffectPreparedCommit:
        """Freeze one staging result and its exact action-relative token."""

        normalized = tuple(outcomes)
        token = stable_uuid(
            "endpoint-effect-prepared-commit",
            plan.effects.action_id,
            plan.actor.stable_id,
            tuple(
                sorted(
                    (
                        outcome.node_id,
                        outcome.status.value,
                        outcome.child_action_id,
                        outcome.canonical_occurrence_count,
                    )
                    for outcome in normalized
                )
            ),
        )
        return cls(
            action_id=plan.effects.action_id,
            actor_id=plan.actor.stable_id,
            outcomes=normalized,
            commit_token=token,
        )


@dataclass(frozen=True, slots=True)
class ProcessOwnedEndpointEffectRequest:
    """Intent for one atomic group of process-owned endpoint consequences."""

    actor: ExactProcessEffectActor
    anchor_time: datetime
    window_end: datetime
    retention_horizon_end: datetime
    specs: tuple[EndpointEffectSpec, ...]
    source: str = "activity_generator"
    action_stable_id: str = ""
    suppressed_instance_keys: tuple[str, ...] = ()
    execution_plan: EndpointEffectExecutionPlan | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        anchor_time = ensure_utc(self.anchor_time)
        window_end = ensure_utc(self.window_end)
        retention_horizon_end = ensure_utc(self.retention_horizon_end)
        specs = tuple(sorted(tuple(self.specs), key=lambda spec: spec.instance_key))
        if not specs or len(specs) > _MAX_EFFECT_NODES:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                f"endpoint effect requests require 1..{_MAX_EFFECT_NODES} effect nodes",
            )
        total_occurrences = sum(spec.intent.occurrence_cardinality for spec in specs)
        if total_occurrences > _MAX_EFFECT_OCCURRENCES:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                f"endpoint effect requests cannot exceed {_MAX_EFFECT_OCCURRENCES} occurrences",
            )
        if anchor_time < self.actor.started_at or window_end <= anchor_time:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect anchor/window must lie after exact process start",
            )
        if retention_horizon_end < window_end:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint retention horizon cannot precede the output-window end",
            )
        suppressed = tuple(sorted(tuple(self.suppressed_instance_keys)))
        spec_by_key = {spec.instance_key: spec for spec in specs}
        if len(spec_by_key) != len(specs):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.DUPLICATE_NODE_ID,
                "endpoint effect request instance keys must be unique",
            )
        if len(suppressed) != len(set(suppressed)) or any(
            key not in spec_by_key or spec_by_key[key].requirement != EffectRequirement.OPTIONAL
            for key in suppressed
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "only planned optional endpoint effects may be explicitly suppressed",
            )
        if self.action_stable_id and not self.action_stable_id.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect action_stable_id cannot be blank",
            )
        object.__setattr__(self, "anchor_time", anchor_time)
        object.__setattr__(self, "window_end", window_end)
        object.__setattr__(self, "retention_horizon_end", retention_horizon_end)
        object.__setattr__(self, "specs", specs)
        object.__setattr__(self, "suppressed_instance_keys", suppressed)
        expected = build_process_owned_endpoint_effect_plan(self)
        candidate = self.execution_plan
        if candidate is not None and candidate != expected:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process-owned endpoint effect plan drifted from the exact request",
            )
        object.__setattr__(self, "execution_plan", expected)

    @property
    def stable_id(self) -> str:
        """Return order-stable action identity from exact actor and effect intent."""

        if self.action_stable_id:
            return self.action_stable_id

        spec_keys = tuple(
            sorted(
                (
                    spec.instance_key,
                    spec.intent.semantic_key,
                    spec.role.value,
                    spec.requirement.value,
                    spec.state_disposition.value,
                    tuple(value.isoformat() for value in spec.occurrence_times),
                    tuple(sorted(spec.depends_on)),
                )
                for spec in self.specs
            )
        )
        return stable_uuid(
            "process-owned-endpoint-effect",
            self.actor.stable_id,
            self.anchor_time.isoformat(),
            self.window_end.isoformat(),
            spec_keys,
            self.source,
        )


class ProcessOwnedEndpointEffectExecutor(Protocol):
    """Adapter that validates exact state, then atomically publishes effects."""

    def _preflight_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
        anchor: ActionAnchor,
    ) -> EndpointEffectExecutionPlan:
        """Validate the frozen actor binding without allocating canonical state."""
        ...

    def _prepare_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
    ) -> EndpointEffectPreparedCommit:
        """Stage immutable occurrences and outcomes without publishing state."""
        ...

    def _commit_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
        prepared: EndpointEffectPreparedCommit,
    ) -> None:
        """Atomically publish one fully reconciled prepared commit."""
        ...


class ProcessOwnedEndpointEffectActionBundle:
    """Preflight and reconcile process-owned file/registry/transfer effects."""

    def __init__(
        self,
        executor: ProcessOwnedEndpointEffectExecutor,
        request: ProcessOwnedEndpointEffectRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable root action anchor."""

        return ActionAnchor(
            family="process_owned_endpoint_effect",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def plan_execution(self) -> EndpointEffectExecutionPlan:
        """Validate exact process authority before any canonical mutation."""

        candidate = self._executor._preflight_process_owned_endpoint_effects(
            self._request,
            self.anchor,
        )
        expected = self._request.execution_plan
        if expected is None or not isinstance(candidate, EndpointEffectExecutionPlan):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect preflight must return EndpointEffectExecutionPlan",
            )
        if candidate != expected or candidate.effects.anchor != self.anchor:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "endpoint effect preflight drifted from the frozen request plan",
            )
        return candidate

    def execute(self) -> ExecutionEffectReconciliation:
        """Reconcile staged effects before one atomic publication."""

        plan = self.plan_execution()
        request = replace(self._request, execution_plan=plan)
        prepared = self._executor._prepare_process_owned_endpoint_effects(request)
        if not isinstance(prepared, EndpointEffectPreparedCommit):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "endpoint effect preparation must return EndpointEffectPreparedCommit",
            )
        expected_prepared = EndpointEffectPreparedCommit.create(plan, prepared.outcomes)
        if (
            prepared.action_id != plan.effects.action_id
            or prepared.actor_id != plan.actor.stable_id
            or prepared.commit_token != expected_prepared.commit_token
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "endpoint effect prepared commit does not match its frozen action and actor",
            )
        outcomes = prepared.outcomes
        nodes_by_id = {node.node_id: node for node in plan.effects.nodes}
        for outcome in outcomes:
            node = nodes_by_id.get(outcome.node_id)
            if node is None:
                continue
            if outcome.status in {EffectOutcomeStatus.REALIZED, EffectOutcomeStatus.LINKED} and (
                outcome.canonical_occurrence_count != node.intent.occurrence_cardinality
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE,
                    "endpoint effect outcome must report exact canonical occurrence cardinality",
                    node_id=node.node_id,
                )
        reconciliation = plan.effects.reconcile(outcomes)
        reconciliation.require_complete()
        self._executor._commit_process_owned_endpoint_effects(request, prepared)
        return reconciliation


def build_process_owned_endpoint_effect_plan(
    request: ProcessOwnedEndpointEffectRequest,
) -> EndpointEffectExecutionPlan:
    """Build and validate the immutable endpoint-effect graph without state allocation."""

    anchor = ActionAnchor(
        family="process_owned_endpoint_effect",
        stable_id=request.stable_id,
        source=request.source,
    )
    effects = _build_endpoint_effect_graph(anchor, request.specs)
    base_nodes = {node.instance_key: node for node in effects.nodes}
    window_end = ensure_utc(request.window_end)
    horizon_end = ensure_utc(request.retention_horizon_end)
    actor_end = request.actor.closes_at
    suppressed = frozenset(request.suppressed_instance_keys)
    for spec in request.specs:
        reason = _endpoint_spec_admission_error(
            spec,
            anchor_time=request.anchor_time,
            window_end=window_end,
            retention_horizon_end=horizon_end,
            actor_end=actor_end,
        )
        if reason is not None and spec.instance_key not in suppressed:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                reason,
            )
        if reason is None and spec.instance_key in suppressed:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "admitted optional endpoint effect cannot carry a suppressed outcome",
            )
    _validate_ephemeral_closures(request.specs)
    durable_node_ids = tuple(
        base_nodes[spec.instance_key].node_id
        for spec in request.specs
        if spec.state_disposition == EndpointStateDisposition.DURABLE_FINAL
    )
    return EndpointEffectExecutionPlan(
        actor=request.actor,
        effects=effects,
        specs=request.specs,
        window_end=window_end,
        retention_horizon_end=horizon_end,
        durable_node_ids=durable_node_ids,
        suppressed_instance_keys=request.suppressed_instance_keys,
    )


def bind_prepared_process_endpoint_effect_plan(
    prepared: PreparedProcessEndpointEffectPlan,
    actor: ExactProcessEffectActor,
) -> ProcessOwnedEndpointEffectRequest:
    """Bind a validated PID-independent plan to its newly allocated exact process."""

    expected = prepared.actor
    if (
        actor.hostname.casefold() != expected.hostname.casefold()
        or actor.image != expected.image
        or actor.command_line != expected.command_line
        or actor.username != expected.username
        or actor.logon_id != expected.logon_id
        or actor.lifecycle_id != expected.lifecycle_id
        or actor.started_at != expected.started_at
    ):
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_ACTOR,
            "allocated process identity drifted from its prepared endpoint actor",
        )
    return ProcessOwnedEndpointEffectRequest(
        actor=actor,
        anchor_time=expected.started_at,
        window_end=prepared.window_end,
        retention_horizon_end=prepared.retention_horizon_end,
        specs=prepared.specs,
        source=prepared.source,
        action_stable_id=prepared.stable_id,
        suppressed_instance_keys=prepared.suppressed_instance_keys,
    )


def _build_endpoint_effect_graph(
    anchor: ActionAnchor,
    specs: tuple[EndpointEffectSpec, ...],
) -> ExecutionEffectPlan:
    """Build one stable root-process effect graph from already-frozen specs."""

    specs_by_key: dict[str, EndpointEffectSpec] = {}
    base_nodes: dict[str, ExecutionEffectNode] = {}
    for spec in specs:
        if spec.instance_key in specs_by_key:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.DUPLICATE_NODE_ID,
                f"duplicate endpoint effect instance key {spec.instance_key!r}",
            )
        specs_by_key[spec.instance_key] = spec
        base_nodes[spec.instance_key] = ExecutionEffectNode.create(
            anchor,
            spec.intent,
            role=spec.role,
            requirement=spec.requirement,
            actor=EffectActorRef.root_process(),
            instance_key=spec.instance_key,
        )

    nodes: list[ExecutionEffectNode] = []
    for spec in specs:
        missing = tuple(sorted(set(spec.depends_on) - specs_by_key.keys()))
        if missing:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.MISSING_DEPENDENCY,
                f"endpoint effect dependencies are missing: {', '.join(missing)}",
            )
        node = base_nodes[spec.instance_key]
        nodes.append(
            replace(
                node,
                depends_on=tuple(base_nodes[key].node_id for key in sorted(spec.depends_on)),
            )
        )
    return ExecutionEffectPlan(anchor=anchor, nodes=tuple(nodes))


def _endpoint_spec_admission_error(
    spec: EndpointEffectSpec,
    *,
    anchor_time: datetime,
    window_end: datetime,
    retention_horizon_end: datetime,
    actor_end: datetime | None,
) -> str | None:
    """Return the exact admission contradiction for one effect, if any."""

    if any(
        timestamp < anchor_time or timestamp >= window_end for timestamp in spec.occurrence_times
    ):
        return "endpoint effect occurrence escapes its exact process/output interval"
    if actor_end is not None and any(timestamp >= actor_end for timestamp in spec.occurrence_times):
        return "endpoint effect occurrence is at or after exact process/session closure"
    if spec.retention_deadline is not None and spec.retention_deadline > retention_horizon_end:
        return "durable endpoint effect retention exceeds the bounded registry horizon"
    return None


def _intent_mutates_endpoint_state(intent: EndpointEffectIntent) -> bool:
    """Return whether an intent creates or changes retained endpoint state."""

    return (
        isinstance(intent, FileEffectIntent)
        and intent.action in {FileEffectAction.CREATE, FileEffectAction.MODIFY}
    ) or (
        isinstance(intent, RegistryEffectIntent)
        and intent.action in {RegistryEffectAction.CREATE, RegistryEffectAction.MODIFY}
    )


def _closure_matches(
    mutation: EndpointEffectIntent,
    closure: EndpointEffectIntent,
) -> bool:
    """Return whether one delete intent closes the exact mutated subject."""

    if isinstance(mutation, FileEffectIntent) and isinstance(closure, FileEffectIntent):
        return closure.action == FileEffectAction.DELETE and closure.path == mutation.path
    if isinstance(mutation, RegistryEffectIntent) and isinstance(closure, RegistryEffectIntent):
        return (
            closure.action == RegistryEffectAction.DELETE
            and closure.key.casefold() == mutation.key.casefold()
            and closure.value_name.casefold() == mutation.value_name.casefold()
        )
    return False


def _validate_ephemeral_closures(specs: tuple[EndpointEffectSpec, ...]) -> None:
    """Require every ephemeral mutation to own one exact post-order delete."""

    for mutation in specs:
        if mutation.state_disposition != EndpointStateDisposition.EPHEMERAL:
            continue
        matches = tuple(
            closure
            for closure in specs
            if closure.role == OccurrenceRole.CLOSURE
            and mutation.instance_key in closure.depends_on
            and _closure_matches(mutation.intent, closure.intent)
        )
        if len(matches) != 1:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "ephemeral endpoint mutation requires exactly one dependent delete closure",
            )
        closure = matches[0]
        if closure.intent.occurrence_cardinality != mutation.intent.occurrence_cardinality:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "ephemeral endpoint mutation and delete closure cardinality must match",
            )
        if any(
            close_time <= mutation_time
            for mutation_time, close_time in zip(
                mutation.occurrence_times,
                closure.occurrence_times,
                strict=True,
            )
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "ephemeral endpoint delete closure must follow every matching mutation",
            )


__all__ = [
    "EndpointEffectPayload",
    "EndpointEffectExecutionPlan",
    "EndpointEffectIntent",
    "EndpointEffectOccurrence",
    "EndpointEffectPreparedCommit",
    "EndpointEffectSpec",
    "EndpointStateDisposition",
    "ExactProcessEffectActor",
    "PreparedEndpointEffect",
    "PreparedFileEffectPayload",
    "PreparedProcessEffectActor",
    "PreparedProcessEndpointEffectPlan",
    "PreparedRegistryEffectPayload",
    "ProcessOwnedEndpointEffectActionBundle",
    "ProcessOwnedEndpointEffectExecutor",
    "ProcessOwnedEndpointEffectRequest",
    "bind_prepared_process_endpoint_effect_plan",
    "build_process_owned_endpoint_effect_plan",
]
