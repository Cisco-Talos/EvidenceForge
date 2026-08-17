# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed, allocation-free planning contracts for process-owned command effects.

This module deliberately contains no generation or rendering behavior.  It gives
process, storyline, baseline, and shell adapters one immutable vocabulary for
declaring required and optional consequences before any PID or canonical state is
allocated.  Execution integration belongs to the owning action bundles.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from heapq import heapify, heappop, heappush
from threading import Lock, get_ident
from typing import TypeAlias

from evidenceforge.events.contracts import (
    EffectOccurrenceDisposition,
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    EffectOccurrenceProvenance,
    OccurrenceRole,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.exceptions import GenerationError
from evidenceforge.utils.rng import stable_uuid

DEFAULT_EXECUTION_EFFECT_AUDIT_PREPARATION_CAPACITY = 4096


class ExecutionEffectPlanErrorCode(StrEnum):
    """Stable machine-readable reason an execution-effect contract was rejected."""

    INVALID_INTENT = "invalid_intent"
    INVALID_PLAN = "invalid_plan"
    INVALID_NODE = "invalid_node"
    UNSTABLE_NODE_ID = "unstable_node_id"
    DUPLICATE_NODE_ID = "duplicate_node_id"
    MISSING_DEPENDENCY = "missing_dependency"
    INVALID_ACTOR = "invalid_actor"
    INVALID_PHASE_EDGE = "invalid_phase_edge"
    CYCLIC_DEPENDENCY = "cyclic_dependency"
    DUPLICATE_OUTCOME = "duplicate_outcome"
    INVALID_OUTCOME = "invalid_outcome"
    RECONCILIATION_INCOMPLETE = "reconciliation_incomplete"


class ExecutionEffectPlanError(GenerationError):
    """A typed execution-effect plan or reconciliation contract failed."""

    def __init__(
        self,
        code: ExecutionEffectPlanErrorCode,
        message: str,
        *,
        node_id: str = "",
    ) -> None:
        self.code = code
        self.node_id = node_id
        location = f" node={node_id}" if node_id else ""
        super().__init__(f"{code.value}:{location} {message}")


class EffectRequirement(StrEnum):
    """How execution must account for one planned effect."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    EXTERNALLY_OWNED = "externally_owned"


class EffectKind(StrEnum):
    """Closed first-wave command-effect families."""

    CHILD_PROCESS = "child_process"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    SCANNER = "scanner"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    SESSION = "session"
    TRANSFER = "transfer"
    WINDOWS_AUDIT = "windows_audit"


class EffectActorKind(StrEnum):
    """Symbolic actor binding resolved only after action planning."""

    ROOT_PROCESS = "root_process"
    EFFECT_PROCESS = "effect_process"
    SESSION = "session"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class EffectActorRef:
    """Symbolic actor for an effect node.

    ``EFFECT_PROCESS`` references another node whose intent creates a child
    process.  Other actor kinds resolve from the root execution request and do
    not carry a node reference.
    """

    kind: EffectActorKind
    node_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EffectActorKind):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"unsupported effect actor kind {self.kind!r}",
                node_id=self.node_id,
            )
        if self.kind == EffectActorKind.EFFECT_PROCESS and (
            not isinstance(self.node_id, str) or not self.node_id
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "effect_process actor references require a node_id",
            )
        if self.kind != EffectActorKind.EFFECT_PROCESS and self.node_id:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"{self.kind.value} actor references cannot carry a node_id",
                node_id=self.node_id,
            )

    @classmethod
    def root_process(cls) -> EffectActorRef:
        """Return a reference to the root process allocated during execution."""

        return cls(EffectActorKind.ROOT_PROCESS)

    @classmethod
    def effect_process(cls, node_id: str) -> EffectActorRef:
        """Return a reference to a child process created by another effect node."""

        return cls(EffectActorKind.EFFECT_PROCESS, node_id=node_id)

    @classmethod
    def session(cls) -> EffectActorRef:
        """Return a reference to the root request's owning session."""

        return cls(EffectActorKind.SESSION)

    @classmethod
    def system(cls) -> EffectActorRef:
        """Return a reference to the target system identity."""

        return cls(EffectActorKind.SYSTEM)


ROOT_PROCESS_ACTOR = EffectActorRef.root_process()


class FileEffectAction(StrEnum):
    """Canonical file operation requested by a command effect."""

    READ = "read"
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class RegistryEffectAction(StrEnum):
    """Canonical registry operation requested by a command effect."""

    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class ScheduledTaskEffectAction(StrEnum):
    """Scheduled-task operation requested by a command effect."""

    CREATE = "create"
    DELETE = "delete"
    DISABLE = "disable"
    ENABLE = "enable"


class ServiceEffectAction(StrEnum):
    """Service operation requested by a command effect."""

    INSTALL = "install"
    START = "start"
    STOP = "stop"
    DELETE = "delete"


class SessionEffectAction(StrEnum):
    """Canonical lifecycle operation for a planned authentication session."""

    START = "start"
    CLOSE = "close"


class WindowsAuditEffectKind(StrEnum):
    """Administrative Windows audit consequences not owned by task/service intents."""

    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"
    ACCOUNT_CHANGED = "account_changed"
    EXPLICIT_CREDENTIALS = "explicit_credentials"
    GROUP_MEMBERSHIP_CHANGED = "group_membership_changed"
    LOG_CLEARED = "log_cleared"


def _validate_text(value: str, field_name: str) -> None:
    """Reject empty semantic fields before they participate in stable identity."""

    if not isinstance(value, str) or not value.strip():
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_INTENT,
            f"{field_name} cannot be empty",
        )


def _validate_cardinality(value: int) -> None:
    """Require a positive, non-boolean canonical occurrence estimate."""

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_INTENT,
            "occurrence_cardinality must be a positive integer",
        )


_FAILURE_REASON_MAX_CHARS = 160


def _bounded_failure_reason(value: str, *, node_id: str = "") -> str:
    """Normalize one actionable failure reason to a bounded diagnostic string."""

    if not isinstance(value, str) or not value.strip():
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
            "failed outcomes require a non-empty reason",
            node_id=node_id,
        )
    normalized = " ".join(value.split())
    if len(normalized) <= _FAILURE_REASON_MAX_CHARS:
        return normalized
    return normalized[: _FAILURE_REASON_MAX_CHARS - 1].rstrip() + "…"


@dataclass(frozen=True, slots=True)
class ChildProcessEffectIntent:
    """Intent to create one process whose identity may own later effects."""

    image: str
    command_line: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        _validate_text(self.image, "image")
        _validate_text(self.command_line, "command_line")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.CHILD_PROCESS

    @property
    def semantic_key(self) -> str:
        """Return stable process semantics independent of plan ordering."""

        return stable_uuid("command-effect-intent", self.kind, self.image, self.command_line)


@dataclass(frozen=True, slots=True)
class FileEffectIntent:
    """Intent for one process-owned local file operation."""

    action: FileEffectAction
    path: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.action, FileEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported file effect action {self.action!r}",
            )
        _validate_text(self.path, "path")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.FILE

    @property
    def semantic_key(self) -> str:
        """Return stable file-operation semantics."""

        return stable_uuid("command-effect-intent", self.kind, self.action, self.path)


@dataclass(frozen=True, slots=True)
class RegistryEffectIntent:
    """Intent for one process-owned Windows registry operation."""

    action: RegistryEffectAction
    key: str
    value_name: str = ""
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.action, RegistryEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported registry effect action {self.action!r}",
            )
        _validate_text(self.key, "key")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.REGISTRY

    @property
    def semantic_key(self) -> str:
        """Return stable case-insensitive registry semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.action,
            self.key.casefold(),
            self.value_name.casefold(),
        )


@dataclass(frozen=True, slots=True)
class NetworkEffectIntent:
    """Intent for one process-owned network transaction."""

    destination: str
    destination_port: int
    protocol: str = "tcp"
    service: str = ""
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        _validate_text(self.destination, "destination")
        _validate_text(self.protocol, "protocol")
        if not 1 <= self.destination_port <= 65_535:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "destination_port must be between 1 and 65535",
            )
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.NETWORK

    @property
    def semantic_key(self) -> str:
        """Return stable network-target semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.protocol.casefold(),
            self.destination.casefold(),
            self.destination_port,
            self.service.casefold(),
        )


@dataclass(frozen=True, slots=True)
class TransferEffectIntent:
    """Intent for a transfer whose transport and endpoint artifacts share ownership."""

    protocol: str
    source_path: str
    destination: str
    destination_path: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        _validate_text(self.protocol, "protocol")
        _validate_text(self.source_path, "source_path")
        _validate_text(self.destination, "destination")
        _validate_text(self.destination_path, "destination_path")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.TRANSFER

    @property
    def semantic_key(self) -> str:
        """Return stable end-to-end transfer semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.protocol.casefold(),
            self.source_path,
            self.destination.casefold(),
            self.destination_path,
        )


@dataclass(frozen=True, slots=True)
class ScannerEffectIntent:
    """Intent for one bounded scanner command expansion."""

    tool: str
    target: str
    probe_count: int

    def __post_init__(self) -> None:
        _validate_text(self.tool, "tool")
        _validate_text(self.target, "target")
        _validate_cardinality(self.probe_count)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.SCANNER

    @property
    def occurrence_cardinality(self) -> int:
        """Return the bounded probe count supplied by the scanner planner."""

        return self.probe_count

    @property
    def semantic_key(self) -> str:
        """Return stable scanner target semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.tool.casefold(),
            self.target.casefold(),
        )


@dataclass(frozen=True, slots=True)
class ScheduledTaskEffectIntent:
    """Intent for one scheduled-task administrative consequence."""

    action: ScheduledTaskEffectAction
    task_name: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.action, ScheduledTaskEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported scheduled-task effect action {self.action!r}",
            )
        _validate_text(self.task_name, "task_name")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.SCHEDULED_TASK

    @property
    def semantic_key(self) -> str:
        """Return stable case-insensitive task semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.action,
            self.task_name.casefold(),
        )


@dataclass(frozen=True, slots=True)
class ServiceEffectIntent:
    """Intent for one Windows or Linux service administrative consequence."""

    action: ServiceEffectAction
    service_name: str
    image: str = ""
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.action, ServiceEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported service effect action {self.action!r}",
            )
        _validate_text(self.service_name, "service_name")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.SERVICE

    @property
    def semantic_key(self) -> str:
        """Return stable case-insensitive service semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.action,
            self.service_name.casefold(),
            self.image.casefold(),
        )


@dataclass(frozen=True, slots=True)
class SessionEffectIntent:
    """Intent for one typed authentication-session lifecycle transition."""

    action: SessionEffectAction
    session_kind: str
    principal: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.action, SessionEffectAction):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported session effect action {self.action!r}",
            )
        _validate_text(self.session_kind, "session_kind")
        _validate_text(self.principal, "principal")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.SESSION

    @property
    def semantic_key(self) -> str:
        """Return stable case-insensitive session transition semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.action,
            self.session_kind.casefold(),
            self.principal.casefold(),
        )


@dataclass(frozen=True, slots=True)
class WindowsAuditEffectIntent:
    """Intent for one command-derived Windows administrative audit consequence."""

    audit_kind: WindowsAuditEffectKind
    semantic_target: str
    occurrence_cardinality: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.audit_kind, WindowsAuditEffectKind):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported Windows audit effect kind {self.audit_kind!r}",
            )
        _validate_text(self.semantic_target, "semantic_target")
        _validate_cardinality(self.occurrence_cardinality)

    @property
    def kind(self) -> EffectKind:
        """Return the closed effect kind."""

        return EffectKind.WINDOWS_AUDIT

    @property
    def semantic_key(self) -> str:
        """Return stable case-insensitive audit-target semantics."""

        return stable_uuid(
            "command-effect-intent",
            self.kind,
            self.audit_kind,
            self.semantic_target.casefold(),
        )


CommandEffectIntent: TypeAlias = (
    ChildProcessEffectIntent
    | FileEffectIntent
    | NetworkEffectIntent
    | RegistryEffectIntent
    | ScannerEffectIntent
    | ScheduledTaskEffectIntent
    | ServiceEffectIntent
    | SessionEffectIntent
    | TransferEffectIntent
    | WindowsAuditEffectIntent
)

_INTENT_TYPES = (
    ChildProcessEffectIntent,
    FileEffectIntent,
    NetworkEffectIntent,
    RegistryEffectIntent,
    ScannerEffectIntent,
    ScheduledTaskEffectIntent,
    ServiceEffectIntent,
    SessionEffectIntent,
    TransferEffectIntent,
    WindowsAuditEffectIntent,
)

_EFFECT_ROLES = frozenset(
    {
        OccurrenceRole.PREREQUISITE,
        OccurrenceRole.DEPENDENT,
        OccurrenceRole.CLOSURE,
    }
)
_ROLE_RANK = {
    OccurrenceRole.PREREQUISITE: 0,
    OccurrenceRole.DEPENDENT: 1,
    OccurrenceRole.CLOSURE: 2,
}


def stable_effect_node_id(
    action_id: str,
    intent: CommandEffectIntent,
    role: OccurrenceRole,
    instance_key: str,
) -> str:
    """Return deterministic node identity independent of tuple or dispatch order."""

    return stable_uuid(
        "execution-effect-node",
        action_id,
        role,
        intent.kind,
        intent.semantic_key,
        instance_key,
    )


@dataclass(frozen=True, slots=True)
class ExecutionEffectNode:
    """One immutable semantic node in a command execution/effect DAG."""

    node_id: str
    intent: CommandEffectIntent
    role: OccurrenceRole
    requirement: EffectRequirement
    actor: EffectActorRef = ROOT_PROCESS_ACTOR
    depends_on: tuple[str, ...] = ()
    instance_key: str = "default"

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "node_id cannot be empty",
            )
        if not isinstance(self.intent, _INTENT_TYPES):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                f"unsupported command-effect intent {type(self.intent).__name__}",
                node_id=self.node_id,
            )
        if not isinstance(self.role, OccurrenceRole):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                f"unsupported effect role {self.role!r}",
                node_id=self.node_id,
            )
        if self.role not in _EFFECT_ROLES:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                f"effect role must be one of {sorted(role.value for role in _EFFECT_ROLES)}",
                node_id=self.node_id,
            )
        if not isinstance(self.requirement, EffectRequirement):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                f"unsupported effect requirement {self.requirement!r}",
                node_id=self.node_id,
            )
        if not isinstance(self.actor, EffectActorRef):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"unsupported effect actor reference {self.actor!r}",
                node_id=self.node_id,
            )
        if not isinstance(self.instance_key, str) or not self.instance_key:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "instance_key cannot be empty",
                node_id=self.node_id,
            )
        dependencies = tuple(self.depends_on)
        if any(not isinstance(dependency, str) or not dependency for dependency in dependencies):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "depends_on entries must be non-empty node ID strings",
                node_id=self.node_id,
            )
        if len(dependencies) != len(set(dependencies)):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "depends_on cannot contain duplicate node IDs",
                node_id=self.node_id,
            )
        if self.node_id in dependencies:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.CYCLIC_DEPENDENCY,
                "an effect node cannot depend on itself",
                node_id=self.node_id,
            )
        object.__setattr__(self, "depends_on", dependencies)

    @classmethod
    def create(
        cls,
        anchor: ActionAnchor,
        intent: CommandEffectIntent,
        *,
        role: OccurrenceRole = OccurrenceRole.DEPENDENT,
        requirement: EffectRequirement = EffectRequirement.REQUIRED,
        actor: EffectActorRef = ROOT_PROCESS_ACTOR,
        depends_on: tuple[str, ...] = (),
        instance_key: str = "default",
    ) -> ExecutionEffectNode:
        """Build one node with stable action-relative semantic identity."""

        return cls(
            node_id=stable_effect_node_id(anchor.action_id, intent, role, instance_key),
            intent=intent,
            role=role,
            requirement=requirement,
            actor=actor,
            depends_on=depends_on,
            instance_key=instance_key,
        )

    def expected_node_id(self, action_id: str) -> str:
        """Return the identity this node must have under ``action_id``."""

        return stable_effect_node_id(action_id, self.intent, self.role, self.instance_key)

    @property
    def predecessor_ids(self) -> tuple[str, ...]:
        """Return explicit and actor-derived DAG predecessors in stable order."""

        predecessors = set(self.depends_on)
        if self.actor.kind == EffectActorKind.EFFECT_PROCESS:
            predecessors.add(self.actor.node_id)
        return tuple(sorted(predecessors))


@dataclass(frozen=True, slots=True)
class ExecutionEffectPlanSummary:
    """Compact allocation-free summary of one validated plan."""

    action_id: str
    node_count: int
    required_count: int
    optional_count: int
    externally_owned_count: int
    estimated_occurrences: int

    def as_dict(self) -> dict[str, str | int]:
        """Return a compact manifest-friendly mapping."""

        return {
            "action_id": self.action_id,
            "node_count": self.node_count,
            "required_count": self.required_count,
            "optional_count": self.optional_count,
            "externally_owned_count": self.externally_owned_count,
            "estimated_occurrences": self.estimated_occurrences,
        }


@dataclass(frozen=True, slots=True)
class ExecutionEffectPlan:
    """Validated immutable command-effect graph rooted at one action anchor."""

    anchor: ActionAnchor
    nodes: tuple[ExecutionEffectNode, ...] = ()
    _ordered_ids: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.anchor, ActionAnchor):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                f"unsupported action anchor {self.anchor!r}",
            )
        if (
            not isinstance(self.anchor.family, str)
            or not self.anchor.family
            or not isinstance(self.anchor.stable_id, str)
            or not self.anchor.stable_id
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                "execution-effect plans require a non-empty action family and stable_id",
            )
        nodes = tuple(self.nodes)
        object.__setattr__(self, "nodes", nodes)
        invalid_node = next(
            (node for node in nodes if not isinstance(node, ExecutionEffectNode)),
            None,
        )
        if invalid_node is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_NODE,
                f"unsupported effect node {invalid_node!r}",
            )
        node_counts = Counter(node.node_id for node in nodes)
        duplicates = sorted(node_id for node_id, count in node_counts.items() if count > 1)
        if duplicates:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.DUPLICATE_NODE_ID,
                "duplicate effect node IDs: " + _compact_ids(duplicates),
                node_id=duplicates[0],
            )
        for node in nodes:
            if node.node_id != node.expected_node_id(self.anchor.action_id):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.UNSTABLE_NODE_ID,
                    "node_id does not match its action-relative semantic identity",
                    node_id=node.node_id,
                )
        object.__setattr__(self, "_ordered_ids", self._validate_and_order_node_ids())

    @property
    def action_id(self) -> str:
        """Return the stable root action identity."""

        return self.anchor.action_id

    @property
    def ordered_nodes(self) -> tuple[ExecutionEffectNode, ...]:
        """Return deterministic topological order independent of input tuple order."""

        nodes_by_id = {node.node_id: node for node in self.nodes}
        return tuple(nodes_by_id[node_id] for node_id in self._ordered_ids)

    @property
    def prerequisites(self) -> tuple[ExecutionEffectNode, ...]:
        """Return ordered effects that must execute before the root process."""

        return tuple(
            node for node in self.ordered_nodes if node.role == OccurrenceRole.PREREQUISITE
        )

    @property
    def dependents(self) -> tuple[ExecutionEffectNode, ...]:
        """Return ordered effects causally dependent on root execution."""

        return tuple(node for node in self.ordered_nodes if node.role == OccurrenceRole.DEPENDENT)

    @property
    def closures(self) -> tuple[ExecutionEffectNode, ...]:
        """Return ordered action closure effects."""

        return tuple(node for node in self.ordered_nodes if node.role == OccurrenceRole.CLOSURE)

    @property
    def estimated_occurrences(self) -> int:
        """Return root plus all conservatively estimated canonical occurrences."""

        return 1 + sum(node.intent.occurrence_cardinality for node in self.nodes)

    @property
    def summary(self) -> ExecutionEffectPlanSummary:
        """Return compact plan counts without retaining another graph view."""

        requirement_counts = Counter(node.requirement for node in self.nodes)
        return ExecutionEffectPlanSummary(
            action_id=self.action_id,
            node_count=len(self.nodes),
            required_count=requirement_counts[EffectRequirement.REQUIRED],
            optional_count=requirement_counts[EffectRequirement.OPTIONAL],
            externally_owned_count=requirement_counts[EffectRequirement.EXTERNALLY_OWNED],
            estimated_occurrences=self.estimated_occurrences,
        )

    def reconcile(
        self,
        outcomes: tuple[EffectExecutionOutcome, ...],
        *,
        unplanned_failures: tuple[UnplannedEffectFailure, ...] = (),
    ) -> ExecutionEffectReconciliation:
        """Reconcile every planned node with an explicit execution outcome."""

        normalized_outcomes = tuple(outcomes)
        normalized_unplanned_failures = tuple(unplanned_failures)
        invalid_unplanned_failure = next(
            (
                failure
                for failure in normalized_unplanned_failures
                if not isinstance(failure, UnplannedEffectFailure)
            ),
            None,
        )
        if invalid_unplanned_failure is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                f"unsupported unplanned effect failure {invalid_unplanned_failure!r}",
            )
        outcome_counts = Counter(outcome.node_id for outcome in normalized_outcomes)
        duplicate_outcomes = sorted(
            node_id for node_id, count in outcome_counts.items() if count > 1
        )
        if duplicate_outcomes:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.DUPLICATE_OUTCOME,
                "duplicate effect outcomes: " + _compact_ids(duplicate_outcomes),
                node_id=duplicate_outcomes[0],
            )

        nodes_by_id = {node.node_id: node for node in self.nodes}
        outcomes_by_id = {outcome.node_id: outcome for outcome in normalized_outcomes}
        missing = tuple(sorted(nodes_by_id.keys() - outcomes_by_id.keys()))
        unexpected = tuple(sorted(outcomes_by_id.keys() - nodes_by_id.keys()))
        missing_required = tuple(
            node_id
            for node_id in missing
            if nodes_by_id[node_id].requirement != EffectRequirement.OPTIONAL
        )
        failed = tuple(
            sorted(
                node_id
                for node_id in nodes_by_id.keys() & outcomes_by_id.keys()
                if outcomes_by_id[node_id].status == EffectOutcomeStatus.FAILED
            )
        )
        invalid: list[str] = []
        policy_invalid: list[str] = []
        cardinality_mismatches: list[str] = []
        for node_id in sorted(nodes_by_id.keys() & outcomes_by_id.keys()):
            node = nodes_by_id[node_id]
            outcome = outcomes_by_id[node_id]
            if outcome.status == EffectOutcomeStatus.FAILED:
                continue
            allowed = {
                EffectRequirement.REQUIRED: {
                    EffectOutcomeStatus.REALIZED,
                    EffectOutcomeStatus.LINKED,
                },
                EffectRequirement.OPTIONAL: {
                    EffectOutcomeStatus.REALIZED,
                    EffectOutcomeStatus.LINKED,
                    EffectOutcomeStatus.SUPPRESSED,
                },
                EffectRequirement.EXTERNALLY_OWNED: {EffectOutcomeStatus.LINKED},
            }[node.requirement]
            if outcome.status not in allowed:
                invalid.append(node_id)
                policy_invalid.append(node_id)
                continue
            expected_cardinality = node.intent.occurrence_cardinality
            reports_occurrences = outcome.status in {
                EffectOutcomeStatus.REALIZED,
                EffectOutcomeStatus.LINKED,
            }
            exact_count_required = isinstance(node.intent, ScannerEffectIntent) or (
                expected_cardinality > 1
                and node.requirement
                in {EffectRequirement.REQUIRED, EffectRequirement.EXTERNALLY_OWNED}
            )
            if reports_occurrences and (
                (exact_count_required and outcome.canonical_occurrence_count is None)
                or (
                    outcome.canonical_occurrence_count is not None
                    and outcome.canonical_occurrence_count != expected_cardinality
                )
            ):
                invalid.append(node_id)
                cardinality_mismatches.append(node_id)

        return ExecutionEffectReconciliation(
            action_id=self.action_id,
            plan_summary=self.summary,
            outcomes=tuple(sorted(normalized_outcomes, key=lambda outcome: outcome.node_id)),
            missing_node_ids=missing,
            missing_required_node_ids=missing_required,
            unexpected_node_ids=unexpected,
            invalid_outcome_node_ids=tuple(invalid),
            policy_invalid_outcome_node_ids=tuple(policy_invalid),
            cardinality_mismatch_node_ids=tuple(cardinality_mismatches),
            failed_outcome_node_ids=failed,
            unplanned_failures=normalized_unplanned_failures,
            audited_occurrence_node_ids=tuple(
                sorted(
                    node.node_id
                    for node in self.nodes
                    if isinstance(node.intent, (FileEffectIntent, RegistryEffectIntent))
                )
            ),
        )

    def _validate_and_order_node_ids(self) -> tuple[str, ...]:
        """Validate references and phase edges, then topologically sort the DAG."""

        nodes_by_id = {node.node_id: node for node in self.nodes}
        incoming: dict[str, set[str]] = {}
        outgoing: dict[str, set[str]] = defaultdict(set)
        for node in self.nodes:
            if (
                node.role == OccurrenceRole.PREREQUISITE
                and node.actor.kind == EffectActorKind.ROOT_PROCESS
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "prerequisite effects cannot use a root process that is not allocated yet",
                    node_id=node.node_id,
                )
            predecessors = set(node.predecessor_ids)
            for predecessor_id in sorted(predecessors):
                predecessor = nodes_by_id.get(predecessor_id)
                if predecessor is None:
                    code = (
                        ExecutionEffectPlanErrorCode.INVALID_ACTOR
                        if node.actor.kind == EffectActorKind.EFFECT_PROCESS
                        and node.actor.node_id == predecessor_id
                        else ExecutionEffectPlanErrorCode.MISSING_DEPENDENCY
                    )
                    raise ExecutionEffectPlanError(
                        code,
                        f"referenced predecessor {predecessor_id!r} is not in the plan",
                        node_id=node.node_id,
                    )
                if (
                    node.actor.kind == EffectActorKind.EFFECT_PROCESS
                    and node.actor.node_id == predecessor_id
                    and not isinstance(predecessor.intent, ChildProcessEffectIntent)
                ):
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                        "effect_process actors must reference a child-process effect node",
                        node_id=node.node_id,
                    )
                if _ROLE_RANK[predecessor.role] > _ROLE_RANK[node.role]:
                    raise ExecutionEffectPlanError(
                        ExecutionEffectPlanErrorCode.INVALID_PHASE_EDGE,
                        f"{node.role.value} effect cannot depend on later "
                        f"{predecessor.role.value} effect {predecessor_id}",
                        node_id=node.node_id,
                    )
                outgoing[predecessor_id].add(node.node_id)
            incoming[node.node_id] = predecessors

        ready = [
            (_ROLE_RANK[nodes_by_id[node_id].role], node_id)
            for node_id, edges in incoming.items()
            if not edges
        ]
        heapify(ready)
        queued = {node_id for _rank, node_id in ready}
        ordered: list[str] = []
        while ready:
            _rank, node_id = heappop(ready)
            queued.discard(node_id)
            ordered.append(node_id)
            for dependent_id in sorted(outgoing.get(node_id, ())):
                incoming[dependent_id].discard(node_id)
                if not incoming[dependent_id] and dependent_id not in queued:
                    heappush(
                        ready,
                        (_ROLE_RANK[nodes_by_id[dependent_id].role], dependent_id),
                    )
                    queued.add(dependent_id)

        if len(ordered) != len(nodes_by_id):
            cyclic = sorted(node_id for node_id, edges in incoming.items() if edges)
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.CYCLIC_DEPENDENCY,
                "effect dependency cycle involves: " + _compact_ids(cyclic),
                node_id=cyclic[0] if cyclic else "",
            )
        return tuple(ordered)


class EffectOutcomeStatus(StrEnum):
    """Observed execution disposition for one planned effect node."""

    REALIZED = "realized"
    LINKED = "linked"
    SUPPRESSED = "suppressed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class EffectExecutionOutcome:
    """Compact execution or external-link result for one effect node."""

    node_id: str
    status: EffectOutcomeStatus
    child_action_id: str = ""
    completed_at: datetime | None = None
    reason: str = ""
    canonical_occurrence_count: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "effect outcomes require a node_id",
            )
        if not isinstance(self.status, EffectOutcomeStatus):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                f"unsupported effect outcome status {self.status!r}",
                node_id=self.node_id,
            )
        if self.completed_at is not None and not isinstance(self.completed_at, datetime):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "completed_at must be a datetime when supplied",
                node_id=self.node_id,
            )
        if self.canonical_occurrence_count is not None and (
            isinstance(self.canonical_occurrence_count, bool)
            or not isinstance(self.canonical_occurrence_count, int)
            or self.canonical_occurrence_count < 0
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "canonical_occurrence_count must be a non-negative integer when supplied",
                node_id=self.node_id,
            )
        if self.status == EffectOutcomeStatus.LINKED and (
            not isinstance(self.child_action_id, str) or not self.child_action_id
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "linked outcomes require child_action_id",
                node_id=self.node_id,
            )
        if self.status == EffectOutcomeStatus.FAILED:
            object.__setattr__(
                self,
                "reason",
                _bounded_failure_reason(self.reason, node_id=self.node_id),
            )
        elif self.status == EffectOutcomeStatus.SUPPRESSED and (
            not isinstance(self.reason, str) or not self.reason.strip()
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "suppressed outcomes require a reason",
                node_id=self.node_id,
            )


@dataclass(frozen=True, slots=True)
class UnplannedEffectFailure:
    """Actionable failure for an emitted effect that has no planned node."""

    effect_kind: EffectKind
    canonical_occurrence_count: int
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.effect_kind, EffectKind):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                f"unsupported unplanned effect kind {self.effect_kind!r}",
            )
        if (
            isinstance(self.canonical_occurrence_count, bool)
            or not isinstance(self.canonical_occurrence_count, int)
            or self.canonical_occurrence_count <= 0
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_OUTCOME,
                "unplanned canonical_occurrence_count must be a positive integer",
            )
        object.__setattr__(self, "reason", _bounded_failure_reason(self.reason))


@dataclass(frozen=True, slots=True)
class ExecutionEffectResultSummary:
    """Small count-only execution summary suitable for manifests and probes."""

    action_id: str
    planned_count: int
    estimated_occurrences: int
    realized_count: int
    realized_occurrence_count: int
    linked_count: int
    suppressed_count: int
    failed_count: int
    missing_count: int
    unexpected_count: int
    unplanned_failure_count: int
    invalid_count: int
    complete: bool

    def as_dict(self) -> dict[str, str | int | bool]:
        """Return a compact manifest-friendly mapping."""

        return {
            "action_id": self.action_id,
            "planned_count": self.planned_count,
            "estimated_occurrences": self.estimated_occurrences,
            "realized_count": self.realized_count,
            "realized_occurrence_count": self.realized_occurrence_count,
            "linked_count": self.linked_count,
            "suppressed_count": self.suppressed_count,
            "failed_count": self.failed_count,
            "missing_count": self.missing_count,
            "unexpected_count": self.unexpected_count,
            "unplanned_failure_count": self.unplanned_failure_count,
            "invalid_count": self.invalid_count,
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class ExecutionEffectReconciliation:
    """Detailed plan/outcome reconciliation with a compact count-only view."""

    action_id: str
    plan_summary: ExecutionEffectPlanSummary
    outcomes: tuple[EffectExecutionOutcome, ...]
    missing_node_ids: tuple[str, ...]
    missing_required_node_ids: tuple[str, ...]
    unexpected_node_ids: tuple[str, ...]
    invalid_outcome_node_ids: tuple[str, ...]
    policy_invalid_outcome_node_ids: tuple[str, ...]
    cardinality_mismatch_node_ids: tuple[str, ...]
    failed_outcome_node_ids: tuple[str, ...]
    unplanned_failures: tuple[UnplannedEffectFailure, ...]
    audited_occurrence_node_ids: tuple[str, ...]

    @property
    def complete(self) -> bool:
        """Return whether every node has one policy-compatible outcome."""

        return not (
            self.missing_node_ids
            or self.unexpected_node_ids
            or self.invalid_outcome_node_ids
            or self.failed_outcome_node_ids
            or self.unplanned_failures
        )

    @property
    def summary(self) -> ExecutionEffectResultSummary:
        """Return count-only results without duplicating detailed identifiers."""

        status_counts = Counter(outcome.status for outcome in self.outcomes)
        return ExecutionEffectResultSummary(
            action_id=self.action_id,
            planned_count=self.plan_summary.node_count,
            estimated_occurrences=self.plan_summary.estimated_occurrences,
            realized_count=status_counts[EffectOutcomeStatus.REALIZED],
            realized_occurrence_count=sum(
                outcome.canonical_occurrence_count or 0
                for outcome in self.outcomes
                if outcome.status == EffectOutcomeStatus.REALIZED
            ),
            linked_count=status_counts[EffectOutcomeStatus.LINKED],
            suppressed_count=status_counts[EffectOutcomeStatus.SUPPRESSED],
            failed_count=status_counts[EffectOutcomeStatus.FAILED],
            missing_count=len(self.missing_node_ids),
            unexpected_count=len(self.unexpected_node_ids),
            unplanned_failure_count=len(self.unplanned_failures),
            invalid_count=len(self.invalid_outcome_node_ids),
            complete=self.complete,
        )

    def require_complete(self) -> None:
        """Fail generation when reconciliation leaves any silent or invalid gap."""

        if self.complete:
            return
        details = []
        if self.missing_node_ids:
            details.append("missing=" + _compact_ids(self.missing_node_ids))
        if self.unexpected_node_ids:
            details.append("unexpected=" + _compact_ids(self.unexpected_node_ids))
        if self.invalid_outcome_node_ids:
            details.append("invalid=" + _compact_ids(self.invalid_outcome_node_ids))
        if self.failed_outcome_node_ids:
            failed_outcomes = {
                outcome.node_id: outcome
                for outcome in self.outcomes
                if outcome.status == EffectOutcomeStatus.FAILED
            }
            details.append(
                "failed="
                + _compact_failed_outcomes(
                    tuple(failed_outcomes[node_id] for node_id in self.failed_outcome_node_ids)
                )
            )
        if self.unplanned_failures:
            details.append("unplanned=" + _compact_unplanned_failures(self.unplanned_failures))
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE,
            "; ".join(details),
        )


@dataclass(frozen=True, slots=True)
class ExecutionEffectAuditSnapshot:
    """Fixed-cardinality aggregate audit for process-effect execution."""

    plan_count: int
    no_effect_plan_count: int
    planned_node_count: int
    required_node_count: int
    optional_node_count: int
    externally_owned_node_count: int
    planned_effect_occurrence_count: int
    owned_effect_plan_count: int
    owned_effect_expected_occurrence_count: int
    owned_effect_published_occurrence_count: int
    realized_node_count: int
    realized_effect_occurrence_count: int
    linked_node_count: int
    suppressed_node_count: int
    failed_node_count: int
    missing_node_count: int
    missing_required_node_count: int
    unexpected_node_count: int
    unplanned_failure_count: int
    invalid_outcome_node_count: int
    policy_invalid_outcome_count: int
    cardinality_mismatch_count: int
    duplicate_outcome_count: int
    incomplete_reconciliation_count: int
    reconciled_effect_occurrence_count: int
    published_effect_occurrence_count: int
    exempt_effect_occurrence_count: int
    unprovenanced_effect_occurrence_count: int
    effect_publication_mismatch_count: int
    reconciliation_digest: str
    effect_occurrence_digest: str

    @property
    def complete(self) -> bool:
        """Return whether every recorded plan has zero reconciliation defects."""

        return not any(
            (
                self.failed_node_count,
                self.missing_node_count,
                self.missing_required_node_count,
                self.unexpected_node_count,
                self.unplanned_failure_count,
                self.invalid_outcome_node_count,
                self.policy_invalid_outcome_count,
                self.cardinality_mismatch_count,
                self.duplicate_outcome_count,
                self.incomplete_reconciliation_count,
                self.exempt_effect_occurrence_count,
                self.unprovenanced_effect_occurrence_count,
                self.effect_publication_mismatch_count,
            )
        )

    def as_dict(self) -> dict[str, int | str | bool]:
        """Return a compact manifest- and probe-friendly mapping."""

        return {
            "complete": self.complete,
            "plan_count": self.plan_count,
            "no_effect_plan_count": self.no_effect_plan_count,
            "planned_node_count": self.planned_node_count,
            "required_node_count": self.required_node_count,
            "optional_node_count": self.optional_node_count,
            "externally_owned_node_count": self.externally_owned_node_count,
            "planned_effect_occurrence_count": self.planned_effect_occurrence_count,
            "owned_effect_plan_count": self.owned_effect_plan_count,
            "owned_effect_expected_occurrence_count": self.owned_effect_expected_occurrence_count,
            "owned_effect_published_occurrence_count": (
                self.owned_effect_published_occurrence_count
            ),
            "realized_node_count": self.realized_node_count,
            "realized_effect_occurrence_count": self.realized_effect_occurrence_count,
            "linked_node_count": self.linked_node_count,
            "suppressed_node_count": self.suppressed_node_count,
            "failed_node_count": self.failed_node_count,
            "missing_node_count": self.missing_node_count,
            "missing_required_node_count": self.missing_required_node_count,
            "unexpected_node_count": self.unexpected_node_count,
            "unplanned_failure_count": self.unplanned_failure_count,
            "invalid_outcome_node_count": self.invalid_outcome_node_count,
            "policy_invalid_outcome_count": self.policy_invalid_outcome_count,
            "cardinality_mismatch_count": self.cardinality_mismatch_count,
            "duplicate_outcome_count": self.duplicate_outcome_count,
            "incomplete_reconciliation_count": self.incomplete_reconciliation_count,
            "reconciled_effect_occurrence_count": self.reconciled_effect_occurrence_count,
            "published_effect_occurrence_count": self.published_effect_occurrence_count,
            "exempt_effect_occurrence_count": self.exempt_effect_occurrence_count,
            "unprovenanced_effect_occurrence_count": self.unprovenanced_effect_occurrence_count,
            "effect_publication_mismatch_count": self.effect_publication_mismatch_count,
            "reconciliation_digest": self.reconciliation_digest,
            "effect_occurrence_digest": self.effect_occurrence_digest,
        }

    def require_complete(self) -> None:
        """Fail finalization before manifests can publish incomplete effect truth."""

        if self.complete:
            return
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE,
            "execution-effect audit contains missing, duplicate, failed, or invalid outcomes",
        )


@dataclass(frozen=True, slots=True)
class ExecutionEffectAuditCohortEntry:
    """One immutable plan and its exact independently recomputed reconciliation."""

    plan: ExecutionEffectPlan
    reconciliation: ExecutionEffectReconciliation

    def __post_init__(self) -> None:
        if type(self.plan) is not ExecutionEffectPlan:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit cohort entries require an ExecutionEffectPlan",
            )
        if type(self.reconciliation) is not ExecutionEffectReconciliation:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit cohort entries require a reconciliation",
            )
        expected = self.plan.reconcile(
            self.reconciliation.outcomes,
            unplanned_failures=self.reconciliation.unplanned_failures,
        )
        if expected != self.reconciliation:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit reconciliation does not match its immutable plan",
            )


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class ExecutionEffectAuditBindingToken:
    """Opaque keyed binding for one active prepared audit cohort."""

    _owner_id: str
    _preparation_id: str
    _cohort_digest: str
    _identity_digest: str
    _delta_digest: str
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class ExecutionEffectAuditCommitReceipt:
    """Opaque keyed proof that one prepared audit cohort committed exactly once."""

    _owner_id: str
    _preparation_id: str
    _cohort_digest: str
    _identity_digest: str
    _delta_digest: str
    _receipt_id: str
    _preparation_object_id: int
    _integrity: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ExecutionEffectAuditPreparationCensus:
    """Constant-time transient census for prepared audit-cohort capabilities."""

    prepared: int
    claimed: int
    capacity: int

    @property
    def active(self) -> int:
        """Return every currently retained transient preparation."""

        return self.prepared + self.claimed


@dataclass(frozen=True, slots=True)
class _ExecutionEffectAuditDelta:
    """Fixed-size precomputed mutation applied atomically to one audit counter."""

    counts: tuple[tuple[str, int], ...]
    digest_count: int
    digest_xor: int
    digest_sum: int
    realized_occurrence_count: int
    realized_occurrence_xor: int
    realized_occurrence_sum: int
    published_occurrence_count: int
    published_occurrence_xor: int
    published_occurrence_sum: int


@dataclass(frozen=True, slots=True)
class _ExecutionEffectAuditCohortBinding:
    """Semantic order and exact nested objects retained by one active capability."""

    root_action_id: str
    entries: tuple[ExecutionEffectAuditCohortEntry, ...]
    owned_plans: tuple[OwnedEffectOccurrencePlan, ...]
    published_provenances: tuple[EffectOccurrenceProvenance, ...]
    cohort_digest: str
    identity_digest: str


class PreparedExecutionEffectAuditCommit:
    """Exact one-shot capability for a validated action-cohort audit delta."""

    __slots__ = (
        "_cancelled",
        "_binding",
        "_committed",
        "_counter",
        "_delta",
        "_receipt",
        "_token",
    )

    def __init__(
        self,
        *,
        counter: ExecutionEffectAuditCounter,
        binding: _ExecutionEffectAuditCohortBinding,
        delta: _ExecutionEffectAuditDelta,
        token: ExecutionEffectAuditBindingToken,
    ) -> None:
        self._counter = counter
        self._binding = binding
        self._delta = delta
        self._token = token
        self._committed = False
        self._cancelled = False
        self._receipt: ExecutionEffectAuditCommitReceipt | None = None

    @property
    def binding_token(self) -> ExecutionEffectAuditBindingToken:
        """Return the exact opaque token bound into an outer action cohort."""

        return self._token

    @property
    def committed(self) -> bool:
        """Return whether this exact capability completed its one permitted commit."""

        return self._committed

    @property
    def receipt(self) -> ExecutionEffectAuditCommitReceipt | None:
        """Return the sole authenticated receipt after a successful commit."""

        return self._receipt

    def commit_no_fail(self) -> ExecutionEffectAuditCommitReceipt:
        """Atomically apply the already validated fixed-size delta exactly once."""

        return self._counter._commit_prepared_action_cohort(self)


@dataclass(slots=True)
class _ExecutionEffectAuditPreparationRecord:
    """Exact active-object reservation for one audit preparation."""

    preparation: PreparedExecutionEffectAuditCommit
    binding: _ExecutionEffectAuditCohortBinding
    token: ExecutionEffectAuditBindingToken
    receipt: ExecutionEffectAuditCommitReceipt
    state: str = "prepared"
    claiming_thread: int | None = None


def _execution_effect_audit_cohort_digest(
    *,
    root_action_id: str,
    entries: tuple[ExecutionEffectAuditCohortEntry, ...],
    owned_plans: tuple[OwnedEffectOccurrencePlan, ...],
    published_provenances: tuple[EffectOccurrenceProvenance, ...],
) -> str:
    """Bind validated cohort values and their caller-supplied semantic order."""

    payload = {
        "version": 1,
        "root_action_id": root_action_id,
        "entries": [
            {
                "anchor": {
                    "family": entry.plan.anchor.family,
                    "stable_id": entry.plan.anchor.stable_id,
                    "source": entry.plan.anchor.source,
                },
                "nodes": [
                    {
                        "node_id": node.node_id,
                        "intent_kind": node.intent.kind.value,
                        "intent_semantic_key": node.intent.semantic_key,
                        "occurrence_cardinality": node.intent.occurrence_cardinality,
                        "role": node.role.value,
                        "requirement": node.requirement.value,
                        "actor_kind": node.actor.kind.value,
                        "actor_node_id": node.actor.node_id,
                        "depends_on": node.depends_on,
                        "instance_key": node.instance_key,
                    }
                    for node in entry.plan.nodes
                ],
                "reconciliation": {
                    "digest": _execution_effect_reconciliation_digest(entry.reconciliation),
                    "outcomes": [
                        {
                            "node_id": outcome.node_id,
                            "status": outcome.status.value,
                            "child_action_id": outcome.child_action_id,
                            "completed_at": (
                                outcome.completed_at.isoformat()
                                if outcome.completed_at is not None
                                else None
                            ),
                            "reason": outcome.reason,
                            "canonical_occurrence_count": (outcome.canonical_occurrence_count),
                        }
                        for outcome in entry.reconciliation.outcomes
                    ],
                },
            }
            for entry in entries
        ],
        "owned_plans": [
            {
                "owner": plan.owner.value,
                "kind": plan.kind.value,
                "root_action_id": plan.root_action_id,
                "instance_key": plan.instance_key,
                "occurrence_count": plan.occurrence_count,
                "plan_action_id": plan.plan_action_id,
                "node_id": plan.node_id,
            }
            for plan in owned_plans
        ],
        "published_provenances": [
            {
                "kind": provenance.kind.value,
                "disposition": provenance.disposition.value,
                "root_action_id": provenance.root_action_id,
                "plan_action_id": provenance.plan_action_id,
                "node_id": provenance.node_id,
                "occurrence_ordinal": provenance.occurrence_ordinal,
                "owner": provenance.owner.value if provenance.owner is not None else None,
                "exemption_reason": provenance.exemption_reason,
            }
            for provenance in published_provenances
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _execution_effect_audit_delta_digest(
    delta: _ExecutionEffectAuditDelta,
    *,
    cohort_digest: str,
) -> str:
    """Hash one fixed-size counter delta without retaining detailed graphs."""

    payload = {
        "version": 1,
        "cohort_digest": cohort_digest,
        "counts": delta.counts,
        "digest_count": delta.digest_count,
        "digest_xor": f"{delta.digest_xor:064x}",
        "digest_sum": f"{delta.digest_sum:064x}",
        "realized_occurrence_count": delta.realized_occurrence_count,
        "realized_occurrence_xor": f"{delta.realized_occurrence_xor:064x}",
        "realized_occurrence_sum": f"{delta.realized_occurrence_sum:064x}",
        "published_occurrence_count": delta.published_occurrence_count,
        "published_occurrence_xor": f"{delta.published_occurrence_xor:064x}",
        "published_occurrence_sum": f"{delta.published_occurrence_sum:064x}",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _execution_effect_audit_identity_digest(
    *,
    entries: tuple[ExecutionEffectAuditCohortEntry, ...],
    owned_plans: tuple[OwnedEffectOccurrencePlan, ...],
    published_provenances: tuple[EffectOccurrenceProvenance, ...],
) -> str:
    """Bind exact nested capability objects and their caller-supplied order."""

    payload = {
        "version": 1,
        "entries": [
            {
                "entry": id(entry),
                "plan": id(entry.plan),
                "anchor": id(entry.plan.anchor),
                "nodes": [
                    {
                        "node": id(node),
                        "intent": id(node.intent),
                        "actor": id(node.actor),
                    }
                    for node in entry.plan.nodes
                ],
                "reconciliation": id(entry.reconciliation),
                "outcomes": [id(outcome) for outcome in entry.reconciliation.outcomes],
                "unplanned_failures": [
                    id(failure) for failure in entry.reconciliation.unplanned_failures
                ],
            }
            for entry in entries
        ],
        "owned_plans": [id(plan) for plan in owned_plans],
        "published_provenances": [id(provenance) for provenance in published_provenances],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _same_exact_objects(actual: tuple[object, ...], expected: object) -> bool:
    """Compare ordered nested capabilities by identity without invoking equality."""

    return bool(
        type(expected) is tuple
        and len(actual) == len(expected)
        and all(left is right for left, right in zip(actual, expected, strict=True))
    )


def _execution_effect_intent_has_safe_shape(intent: object) -> bool:
    """Validate every intent primitive before authenticators derive semantic keys."""

    intent_type = type(intent)
    if intent_type is ChildProcessEffectIntent:
        strings = (intent.image, intent.command_line)
        cardinality = intent.occurrence_cardinality
        typed_fields = True
    elif intent_type is FileEffectIntent:
        strings = (intent.path,)
        cardinality = intent.occurrence_cardinality
        typed_fields = type(intent.action) is FileEffectAction
    elif intent_type is RegistryEffectIntent:
        strings = (intent.key,)
        cardinality = intent.occurrence_cardinality
        typed_fields = (
            type(intent.action) is RegistryEffectAction and type(intent.value_name) is str
        )
    elif intent_type is NetworkEffectIntent:
        strings = (intent.destination, intent.protocol)
        cardinality = intent.occurrence_cardinality
        typed_fields = bool(
            type(intent.destination_port) is int
            and 1 <= intent.destination_port <= 65_535
            and type(intent.service) is str
        )
    elif intent_type is TransferEffectIntent:
        strings = (
            intent.protocol,
            intent.source_path,
            intent.destination,
            intent.destination_path,
        )
        cardinality = intent.occurrence_cardinality
        typed_fields = True
    elif intent_type is ScannerEffectIntent:
        strings = (intent.tool, intent.target)
        cardinality = intent.probe_count
        typed_fields = True
    elif intent_type is ScheduledTaskEffectIntent:
        strings = (intent.task_name,)
        cardinality = intent.occurrence_cardinality
        typed_fields = type(intent.action) is ScheduledTaskEffectAction
    elif intent_type is ServiceEffectIntent:
        strings = (intent.service_name,)
        cardinality = intent.occurrence_cardinality
        typed_fields = type(intent.action) is ServiceEffectAction and type(intent.image) is str
    elif intent_type is SessionEffectIntent:
        strings = (intent.session_kind, intent.principal)
        cardinality = intent.occurrence_cardinality
        typed_fields = type(intent.action) is SessionEffectAction
    elif intent_type is WindowsAuditEffectIntent:
        strings = (intent.semantic_target,)
        cardinality = intent.occurrence_cardinality
        typed_fields = type(intent.audit_kind) is WindowsAuditEffectKind
    else:
        return False
    return bool(
        typed_fields
        and all(type(value) is str and bool(value.strip()) for value in strings)
        and type(cardinality) is int
        and cardinality > 0
    )


class ExecutionEffectAuditCounter:
    """Accumulate bounded count-only execution-effect audit data.

    The counter deliberately retains no action IDs, nodes, outcomes, timestamps,
    or duration-wide graph. Its memory use is constant for the generation run.
    """

    __slots__ = (
        "_action_cohort_capability_locators",
        "_action_cohort_owner_id",
        "_action_cohort_preparation_capacity",
        "_action_cohort_prepared_count",
        "_action_cohort_preparation_locators",
        "_action_cohort_preparations",
        "_action_cohort_secret",
        "_action_cohort_claimed_count",
        "_counts",
        "_digest_count",
        "_digest_sum",
        "_digest_xor",
        "_realized_occurrence_count",
        "_realized_occurrence_sum",
        "_realized_occurrence_xor",
        "_published_occurrence_count",
        "_published_occurrence_sum",
        "_published_occurrence_xor",
        "_lock",
    )

    _KEYS = (
        "plan_count",
        "no_effect_plan_count",
        "planned_node_count",
        "required_node_count",
        "optional_node_count",
        "externally_owned_node_count",
        "planned_effect_occurrence_count",
        "owned_effect_plan_count",
        "owned_effect_expected_occurrence_count",
        "owned_effect_published_occurrence_count",
        "realized_node_count",
        "realized_effect_occurrence_count",
        "linked_node_count",
        "suppressed_node_count",
        "failed_node_count",
        "missing_node_count",
        "missing_required_node_count",
        "unexpected_node_count",
        "unplanned_failure_count",
        "invalid_outcome_node_count",
        "policy_invalid_outcome_count",
        "cardinality_mismatch_count",
        "duplicate_outcome_count",
        "incomplete_reconciliation_count",
        "reconciled_effect_occurrence_count",
        "published_effect_occurrence_count",
        "exempt_effect_occurrence_count",
        "unprovenanced_effect_occurrence_count",
        "effect_publication_mismatch_count",
    )

    def __init__(
        self,
        *,
        action_cohort_preparation_capacity: int = (
            DEFAULT_EXECUTION_EFFECT_AUDIT_PREPARATION_CAPACITY
        ),
    ) -> None:
        if (
            type(action_cohort_preparation_capacity) is not int
            or action_cohort_preparation_capacity <= 0
        ):
            raise ValueError("action_cohort_preparation_capacity must be a positive integer")
        self._action_cohort_owner_id = secrets.token_hex(16)
        self._action_cohort_secret = secrets.token_bytes(32)
        self._action_cohort_preparation_capacity = action_cohort_preparation_capacity
        self._action_cohort_preparations: dict[
            str,
            _ExecutionEffectAuditPreparationRecord,
        ] = {}
        self._action_cohort_preparation_locators: dict[int, str] = {}
        self._action_cohort_capability_locators: dict[int, str] = {}
        self._action_cohort_prepared_count = 0
        self._action_cohort_claimed_count = 0
        self._counts: Counter[str] = Counter()
        self._digest_count = 0
        self._digest_xor = 0
        self._digest_sum = 0
        self._realized_occurrence_count = 0
        self._realized_occurrence_xor = 0
        self._realized_occurrence_sum = 0
        self._published_occurrence_count = 0
        self._published_occurrence_xor = 0
        self._published_occurrence_sum = 0
        self._lock = Lock()

    def prepare_action_cohort(
        self,
        root_action_id: str,
        entries: tuple[ExecutionEffectAuditCohortEntry, ...],
        *,
        owned_plans: tuple[OwnedEffectOccurrencePlan, ...] = (),
        published_provenances: tuple[EffectOccurrenceProvenance, ...] = (),
    ) -> PreparedExecutionEffectAuditCommit:
        """Validate and stage one complete cohort without mutating canonical totals.

        A cohort may contain reconciled execution plans, bounded family-owned
        roots, or both.  At least one plan, owned root, or publication proof is
        required.  A zero-node execution plan remains a valid audited member.
        """

        expected_provenances, cohort_digest = self._validate_action_cohort_inputs(
            root_action_id=root_action_id,
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        )
        if Counter(expected_provenances) != Counter(published_provenances):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "published effect provenance does not exactly match the cohort plan",
            )

        # Deliberately derive against an isolated counter.  The main counter is
        # not touched until the exact claimed capability reaches commit_no_fail.
        scratch = ExecutionEffectAuditCounter()
        for entry in entries:
            scratch.record(entry.reconciliation)
        for plan in owned_plans:
            scratch.record_owned_effect_plan(plan)
        for provenance in published_provenances:
            scratch.record_published_effect_occurrence(
                provenance,
                effect_kind=provenance.kind,
            )
        scratch.snapshot().require_complete()
        delta = _ExecutionEffectAuditDelta(
            counts=tuple((key, scratch._counts[key]) for key in self._KEYS),
            digest_count=scratch._digest_count,
            digest_xor=scratch._digest_xor,
            digest_sum=scratch._digest_sum,
            realized_occurrence_count=scratch._realized_occurrence_count,
            realized_occurrence_xor=scratch._realized_occurrence_xor,
            realized_occurrence_sum=scratch._realized_occurrence_sum,
            published_occurrence_count=scratch._published_occurrence_count,
            published_occurrence_xor=scratch._published_occurrence_xor,
            published_occurrence_sum=scratch._published_occurrence_sum,
        )
        delta_digest = _execution_effect_audit_delta_digest(
            delta,
            cohort_digest=cohort_digest,
        )
        identity_digest = _execution_effect_audit_identity_digest(
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        )
        binding = _ExecutionEffectAuditCohortBinding(
            root_action_id=root_action_id,
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
            cohort_digest=cohort_digest,
            identity_digest=identity_digest,
        )

        with self._lock:
            active_preparations = (
                self._action_cohort_prepared_count + self._action_cohort_claimed_count
            )
            if active_preparations >= self._action_cohort_preparation_capacity:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "Execution-effect audit preparation capacity "
                    f"({self._action_cohort_preparation_capacity}) is exhausted. "
                    "Commit or cancel an active cohort before retrying.",
                )
            preparation_id = secrets.token_hex(16)
            while preparation_id in self._action_cohort_preparations:
                preparation_id = secrets.token_hex(16)
            token = ExecutionEffectAuditBindingToken(
                _owner_id=self._action_cohort_owner_id,
                _preparation_id=preparation_id,
                _cohort_digest=cohort_digest,
                _identity_digest=identity_digest,
                _delta_digest=delta_digest,
                _integrity=self._action_cohort_token_integrity(
                    preparation_id=preparation_id,
                    cohort_digest=cohort_digest,
                    identity_digest=identity_digest,
                    delta_digest=delta_digest,
                ),
            )
            preparation = PreparedExecutionEffectAuditCommit(
                counter=self,
                binding=binding,
                delta=delta,
                token=token,
            )
            receipt_id = secrets.token_hex(16)
            receipt = ExecutionEffectAuditCommitReceipt(
                _owner_id=self._action_cohort_owner_id,
                _preparation_id=preparation_id,
                _cohort_digest=cohort_digest,
                _identity_digest=identity_digest,
                _delta_digest=delta_digest,
                _receipt_id=receipt_id,
                _preparation_object_id=id(preparation),
                _integrity=self._action_cohort_receipt_integrity(
                    preparation_id=preparation_id,
                    cohort_digest=cohort_digest,
                    identity_digest=identity_digest,
                    delta_digest=delta_digest,
                    receipt_id=receipt_id,
                    preparation_object_id=id(preparation),
                ),
            )
            self._action_cohort_preparations[preparation_id] = (
                _ExecutionEffectAuditPreparationRecord(
                    preparation=preparation,
                    binding=binding,
                    token=token,
                    receipt=receipt,
                )
            )
            self._action_cohort_preparation_locators[id(preparation)] = preparation_id
            self._action_cohort_capability_locators[id(token)] = preparation_id
            self._action_cohort_prepared_count += 1
        return preparation

    def cancel_action_cohort(self, preparation: object) -> None:
        """Discard one exact unclaimed preparation with zero canonical mutation."""

        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            if record is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation is foreign, copied, or stale",
                )
            if record.state != "prepared":
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "claimed execution-effect audit preparation cannot cancel directly",
                )
            if not self._action_cohort_record_authenticates_total_locked(record):
                self._release_action_cohort_record_locked(record)
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation integrity check failed",
                )
            self._release_action_cohort_record_locked(record)

    @contextmanager
    def claimed_action_cohort(
        self,
        preparation: object,
    ) -> Iterator[PreparedExecutionEffectAuditCommit]:
        """Short-claim one exact preparation without retaining the counter lock."""

        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            if record is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation is foreign, copied, or stale",
                )
            if record.state != "prepared":
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation is already claimed",
                )
            if not self._action_cohort_record_authenticates_total_locked(record):
                self._release_action_cohort_record_locked(record)
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation integrity check failed",
                )
            record.state = "claimed"
            record.claiming_thread = get_ident()
            self._action_cohort_prepared_count -= 1
            self._action_cohort_claimed_count += 1
            claimed = record.preparation
        try:
            yield claimed
        except BaseException:
            with self._lock:
                active = self._active_action_cohort_record_locked(claimed)
                if active is record:
                    self._release_action_cohort_record_locked(active)
            raise
        else:
            with self._lock:
                active = self._active_action_cohort_record_locked(claimed)
                uncommitted = active is record
                if uncommitted:
                    self._release_action_cohort_record_locked(active)
            if uncommitted or not claimed.committed:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "claimed execution-effect audit preparation exited without commit_no_fail",
                )

    def authenticates_action_cohort_preparation(
        self,
        preparation: object,
        *,
        root_action_id: object | None = None,
        entries: object | None = None,
        owned_plans: object | None = None,
        published_provenances: object | None = None,
    ) -> bool:
        """Totally authenticate an active preparation and optional exact bindings."""

        if type(preparation) is not PreparedExecutionEffectAuditCommit:
            return False
        if root_action_id is not None and type(root_action_id) is not str:
            return False
        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            if record is None or not self._action_cohort_record_authenticates_total_locked(record):
                return False
            binding = record.binding
            if root_action_id is not None and root_action_id != binding.root_action_id:
                return False
            if entries is not None and not _same_exact_objects(binding.entries, entries):
                return False
            if owned_plans is not None and not _same_exact_objects(
                binding.owned_plans,
                owned_plans,
            ):
                return False
            return not (
                published_provenances is not None
                and not _same_exact_objects(
                    binding.published_provenances,
                    published_provenances,
                )
            )

    def authenticates_action_cohort_binding_token(self, token: object) -> bool:
        """Totally authenticate one exact active binding-token object."""

        if type(token) is not ExecutionEffectAuditBindingToken:
            return False
        with self._lock:
            preparation_id = self._action_cohort_capability_locators.get(id(token))
            record = (
                self._action_cohort_preparations.get(preparation_id)
                if preparation_id is not None
                else None
            )
            return bool(
                type(record) is _ExecutionEffectAuditPreparationRecord
                and record.token is token
                and self._action_cohort_record_authenticates_total_locked(record)
            )

    def authenticates_action_cohort_receipt(
        self,
        receipt: object,
        *,
        preparation: object,
        root_action_id: object | None = None,
        entries: object | None = None,
        owned_plans: object | None = None,
        published_provenances: object | None = None,
    ) -> bool:
        """Totally authenticate the exact receipt of one exact committed capability."""

        if type(preparation) is not PreparedExecutionEffectAuditCommit:
            return False
        if type(receipt) is not ExecutionEffectAuditCommitReceipt:
            return False
        if root_action_id is not None and type(root_action_id) is not str:
            return False
        try:
            if (
                preparation._counter is not self
                or type(preparation._committed) is not bool
                or not preparation._committed
                or type(preparation._cancelled) is not bool
                or preparation._cancelled
                or preparation._receipt is not receipt
                or not self._action_cohort_receipt_shape_is_valid(receipt)
                or type(preparation._binding) is not _ExecutionEffectAuditCohortBinding
                or not self._action_cohort_binding_is_valid(preparation._binding)
                or receipt._preparation_object_id != id(preparation)
                or preparation._binding.cohort_digest != receipt._cohort_digest
                or preparation._binding.identity_digest != receipt._identity_digest
                or not self._action_cohort_delta_is_valid(
                    preparation._delta,
                    cohort_digest=preparation._binding.cohort_digest,
                    expected_digest=receipt._delta_digest,
                )
            ):
                return False
            binding = preparation._binding
        except (AttributeError, KeyError, OverflowError, TypeError, UnicodeError, ValueError):
            return False
        if root_action_id is not None and root_action_id != binding.root_action_id:
            return False
        if entries is not None and not _same_exact_objects(binding.entries, entries):
            return False
        if owned_plans is not None and not _same_exact_objects(binding.owned_plans, owned_plans):
            return False
        return not (
            published_provenances is not None
            and not _same_exact_objects(
                binding.published_provenances,
                published_provenances,
            )
        )

    def action_cohort_preparation_census(self) -> ExecutionEffectAuditPreparationCensus:
        """Return constant-time active prepared and claimed capability counts."""

        with self._lock:
            return ExecutionEffectAuditPreparationCensus(
                prepared=self._action_cohort_prepared_count,
                claimed=self._action_cohort_claimed_count,
                capacity=self._action_cohort_preparation_capacity,
            )

    @staticmethod
    def _invalid_action_cohort(message: str) -> ExecutionEffectPlanError:
        return ExecutionEffectPlanError(ExecutionEffectPlanErrorCode.INVALID_PLAN, message)

    def _validate_action_cohort_inputs(
        self,
        *,
        root_action_id: object,
        entries: object,
        owned_plans: object,
        published_provenances: object,
    ) -> tuple[tuple[EffectOccurrenceProvenance, ...], str]:
        if type(root_action_id) is not str or not root_action_id.strip():
            raise self._invalid_action_cohort("audit cohorts require a non-empty root_action_id")
        if type(entries) is not tuple:
            raise self._invalid_action_cohort("audit cohort entries must be an immutable tuple")
        if type(owned_plans) is not tuple:
            raise self._invalid_action_cohort("owned effect plans must be an immutable tuple")
        if type(published_provenances) is not tuple:
            raise self._invalid_action_cohort("published provenances must be an immutable tuple")
        if not entries and not owned_plans and not published_provenances:
            raise self._invalid_action_cohort("an execution-effect audit cohort cannot be empty")

        expected_provenances: list[EffectOccurrenceProvenance] = []
        entry_action_ids: set[str] = set()
        for entry in entries:
            if type(entry) is not ExecutionEffectAuditCohortEntry:
                raise self._invalid_action_cohort(
                    "audit cohort entries require exact typed plan/reconciliation bindings"
                )
            try:
                self._validate_action_cohort_entry(entry)
            except ExecutionEffectPlanError:
                raise
            except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as error:
                raise self._invalid_action_cohort("audit cohort entry is malformed") from error
            entry.reconciliation.require_complete()
            if entry.plan.action_id in entry_action_ids:
                raise self._invalid_action_cohort(
                    "audit cohort entries cannot repeat a plan action identity"
                )
            entry_action_ids.add(entry.plan.action_id)
            nodes_by_id = {node.node_id: node for node in entry.plan.nodes}
            outcomes_by_id = {outcome.node_id: outcome for outcome in entry.reconciliation.outcomes}
            for node_id in entry.reconciliation.audited_occurrence_node_ids:
                node = nodes_by_id[node_id]
                outcome = outcomes_by_id[node_id]
                if outcome.status != EffectOutcomeStatus.REALIZED:
                    continue
                if outcome.canonical_occurrence_count != node.intent.occurrence_cardinality:
                    raise self._invalid_action_cohort(
                        "realized file/registry outcomes require exact occurrence cardinality"
                    )
                kind = (
                    EffectOccurrenceKind.FILE
                    if type(node.intent) is FileEffectIntent
                    else EffectOccurrenceKind.REGISTRY
                )
                expected_provenances.extend(
                    EffectOccurrenceProvenance.planned(
                        kind=kind,
                        root_action_id=root_action_id,
                        plan_action_id=entry.plan.action_id,
                        node_id=node.node_id,
                        occurrence_ordinal=ordinal,
                    )
                    for ordinal in range(node.intent.occurrence_cardinality)
                )

        owned_action_ids: set[str] = set()
        for plan in owned_plans:
            if type(plan) is not OwnedEffectOccurrencePlan:
                raise self._invalid_action_cohort(
                    "owned effect roots require exact OwnedEffectOccurrencePlan values"
                )
            try:
                self._validate_owned_effect_plan(plan)
            except ExecutionEffectPlanError:
                raise
            except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as error:
                raise self._invalid_action_cohort("owned effect root is malformed") from error
            if plan.root_action_id != root_action_id:
                raise self._invalid_action_cohort(
                    "owned effect root does not belong to the cohort root action"
                )
            if plan.plan_action_id in owned_action_ids:
                raise self._invalid_action_cohort(
                    "owned effect roots cannot repeat a plan action identity"
                )
            owned_action_ids.add(plan.plan_action_id)
            expected_provenances.extend(
                plan.provenance(ordinal) for ordinal in range(plan.occurrence_count)
            )

        if len(expected_provenances) != len(set(expected_provenances)):
            raise self._invalid_action_cohort(
                "cohort plans derive duplicate effect occurrence provenance"
            )
        seen_provenances: set[EffectOccurrenceProvenance] = set()
        for provenance in published_provenances:
            if type(provenance) is not EffectOccurrenceProvenance:
                raise self._invalid_action_cohort(
                    "published effects require exact EffectOccurrenceProvenance values"
                )
            try:
                self._validate_effect_occurrence_provenance(provenance)
            except ExecutionEffectPlanError:
                raise
            except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as error:
                raise self._invalid_action_cohort(
                    "published effect provenance is malformed"
                ) from error
            if provenance.disposition == EffectOccurrenceDisposition.EXEMPT:
                raise self._invalid_action_cohort(
                    "audit cohorts cannot publish exempt effect occurrences"
                )
            if provenance.root_action_id != root_action_id:
                raise self._invalid_action_cohort(
                    "published effect provenance does not belong to the cohort root action"
                )
            if provenance in seen_provenances:
                raise self._invalid_action_cohort(
                    "audit cohorts cannot publish duplicate effect provenance"
                )
            seen_provenances.add(provenance)

        cohort_digest = _execution_effect_audit_cohort_digest(
            root_action_id=root_action_id,
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        )
        return tuple(expected_provenances), cohort_digest

    def _validate_action_cohort_entry(self, entry: ExecutionEffectAuditCohortEntry) -> None:
        plan = entry.plan
        reconciliation = entry.reconciliation
        if (
            type(plan) is not ExecutionEffectPlan
            or type(plan.anchor) is not ActionAnchor
            or type(plan.anchor.family) is not str
            or not plan.anchor.family
            or type(plan.anchor.stable_id) is not str
            or not plan.anchor.stable_id
            or type(plan.anchor.source) is not str
            or type(plan.nodes) is not tuple
            or any(type(node) is not ExecutionEffectNode for node in plan.nodes)
            or any(not _execution_effect_intent_has_safe_shape(node.intent) for node in plan.nodes)
            or any(type(node.actor) is not EffectActorRef for node in plan.nodes)
            or any(type(node.node_id) is not str for node in plan.nodes)
            or any(type(node.role) is not OccurrenceRole for node in plan.nodes)
            or any(type(node.requirement) is not EffectRequirement for node in plan.nodes)
            or any(type(node.actor.kind) is not EffectActorKind for node in plan.nodes)
            or any(type(node.actor.node_id) is not str for node in plan.nodes)
            or any(type(node.depends_on) is not tuple for node in plan.nodes)
            or any(
                any(type(dependency) is not str for dependency in node.depends_on)
                for node in plan.nodes
            )
            or any(type(node.instance_key) is not str for node in plan.nodes)
            or type(plan._ordered_ids) is not tuple
            or any(type(node_id) is not str for node_id in plan._ordered_ids)
            or type(reconciliation) is not ExecutionEffectReconciliation
            or type(reconciliation.action_id) is not str
            or type(reconciliation.plan_summary) is not ExecutionEffectPlanSummary
            or type(reconciliation.plan_summary.action_id) is not str
            or any(
                type(value) is not int or isinstance(value, bool)
                for value in (
                    reconciliation.plan_summary.node_count,
                    reconciliation.plan_summary.required_count,
                    reconciliation.plan_summary.optional_count,
                    reconciliation.plan_summary.externally_owned_count,
                    reconciliation.plan_summary.estimated_occurrences,
                )
            )
            or type(reconciliation.outcomes) is not tuple
            or any(
                type(outcome) is not EffectExecutionOutcome for outcome in reconciliation.outcomes
            )
            or any(
                type(outcome.node_id) is not str
                or type(outcome.status) is not EffectOutcomeStatus
                or type(outcome.child_action_id) is not str
                or (outcome.completed_at is not None and type(outcome.completed_at) is not datetime)
                or type(outcome.reason) is not str
                or (
                    outcome.canonical_occurrence_count is not None
                    and (
                        type(outcome.canonical_occurrence_count) is not int
                        or isinstance(outcome.canonical_occurrence_count, bool)
                    )
                )
                for outcome in reconciliation.outcomes
            )
            or type(reconciliation.unplanned_failures) is not tuple
            or any(
                type(failure) is not UnplannedEffectFailure
                for failure in reconciliation.unplanned_failures
            )
            or any(
                type(failure.effect_kind) is not EffectKind
                or type(failure.canonical_occurrence_count) is not int
                or isinstance(failure.canonical_occurrence_count, bool)
                or type(failure.reason) is not str
                for failure in reconciliation.unplanned_failures
            )
            or any(
                type(value) is not tuple or any(type(item) is not str for item in value)
                for value in (
                    reconciliation.missing_node_ids,
                    reconciliation.missing_required_node_ids,
                    reconciliation.unexpected_node_ids,
                    reconciliation.invalid_outcome_node_ids,
                    reconciliation.policy_invalid_outcome_node_ids,
                    reconciliation.cardinality_mismatch_node_ids,
                    reconciliation.failed_outcome_node_ids,
                    reconciliation.audited_occurrence_node_ids,
                )
            )
        ):
            raise self._invalid_action_cohort("audit cohort entry is malformed")
        try:
            validated_plan = ExecutionEffectPlan(plan.anchor, plan.nodes)
            expected = validated_plan.reconcile(
                reconciliation.outcomes,
                unplanned_failures=reconciliation.unplanned_failures,
            )
        except (ExecutionEffectPlanError, AttributeError, TypeError, ValueError) as error:
            raise self._invalid_action_cohort("audit cohort entry is malformed") from error
        if validated_plan != plan or expected != reconciliation:
            raise self._invalid_action_cohort(
                "audit cohort reconciliation does not exactly match its immutable plan"
            )

    def _validate_owned_effect_plan(self, plan: OwnedEffectOccurrencePlan) -> None:
        if (
            type(plan.owner) is not EffectOccurrenceOwner
            or type(plan.kind) is not EffectOccurrenceKind
            or type(plan.root_action_id) is not str
            or type(plan.instance_key) is not str
            or type(plan.occurrence_count) is not int
            or isinstance(plan.occurrence_count, bool)
            or type(plan.plan_action_id) is not str
            or type(plan.node_id) is not str
        ):
            raise self._invalid_action_cohort("owned effect root is malformed")
        try:
            expected = OwnedEffectOccurrencePlan(
                owner=plan.owner,
                kind=plan.kind,
                root_action_id=plan.root_action_id,
                instance_key=plan.instance_key,
                occurrence_count=plan.occurrence_count,
                plan_action_id=plan.plan_action_id,
                node_id=plan.node_id,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise self._invalid_action_cohort("owned effect root is malformed") from error
        if expected != plan:
            raise self._invalid_action_cohort("owned effect root identity is not canonical")

    def _validate_effect_occurrence_provenance(
        self,
        provenance: EffectOccurrenceProvenance,
    ) -> None:
        if (
            type(provenance.kind) is not EffectOccurrenceKind
            or type(provenance.disposition) is not EffectOccurrenceDisposition
            or type(provenance.root_action_id) is not str
            or type(provenance.plan_action_id) is not str
            or type(provenance.node_id) is not str
            or type(provenance.occurrence_ordinal) is not int
            or isinstance(provenance.occurrence_ordinal, bool)
            or (
                provenance.owner is not None and type(provenance.owner) is not EffectOccurrenceOwner
            )
            or type(provenance.exemption_reason) is not str
        ):
            raise self._invalid_action_cohort("published effect provenance is malformed")
        try:
            expected = EffectOccurrenceProvenance(
                kind=provenance.kind,
                disposition=provenance.disposition,
                root_action_id=provenance.root_action_id,
                plan_action_id=provenance.plan_action_id,
                node_id=provenance.node_id,
                occurrence_ordinal=provenance.occurrence_ordinal,
                owner=provenance.owner,
                exemption_reason=provenance.exemption_reason,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise self._invalid_action_cohort("published effect provenance is malformed") from error
        if expected != provenance:
            raise self._invalid_action_cohort(
                "published effect provenance identity is not canonical"
            )

    def _action_cohort_token_integrity(
        self,
        *,
        preparation_id: str,
        cohort_digest: str,
        identity_digest: str,
        delta_digest: str,
    ) -> str:
        payload = (
            "execution-effect-audit-token-v1\0"
            f"{self._action_cohort_owner_id}\0{preparation_id}\0"
            f"{cohort_digest}\0{identity_digest}\0{delta_digest}"
        ).encode("ascii")
        return hmac.new(self._action_cohort_secret, payload, hashlib.sha256).hexdigest()

    def _action_cohort_receipt_integrity(
        self,
        *,
        preparation_id: str,
        cohort_digest: str,
        identity_digest: str,
        delta_digest: str,
        receipt_id: str,
        preparation_object_id: int,
    ) -> str:
        payload = (
            "execution-effect-audit-receipt-v1\0"
            f"{self._action_cohort_owner_id}\0{preparation_id}\0{cohort_digest}\0"
            f"{identity_digest}\0{delta_digest}\0{receipt_id}\0{preparation_object_id}"
        ).encode("ascii")
        return hmac.new(self._action_cohort_secret, payload, hashlib.sha256).hexdigest()

    def _action_cohort_token_shape_is_valid(self, token: object) -> bool:
        if type(token) is not ExecutionEffectAuditBindingToken:
            return False
        values = (
            token._owner_id,
            token._preparation_id,
            token._cohort_digest,
            token._identity_digest,
            token._delta_digest,
            token._integrity,
        )
        if any(type(value) is not str or not value for value in values):
            return False
        if token._owner_id != self._action_cohort_owner_id:
            return False
        expected = self._action_cohort_token_integrity(
            preparation_id=token._preparation_id,
            cohort_digest=token._cohort_digest,
            identity_digest=token._identity_digest,
            delta_digest=token._delta_digest,
        )
        return hmac.compare_digest(token._integrity, expected)

    def _action_cohort_receipt_shape_is_valid(self, receipt: object) -> bool:
        if type(receipt) is not ExecutionEffectAuditCommitReceipt:
            return False
        values = (
            receipt._owner_id,
            receipt._preparation_id,
            receipt._cohort_digest,
            receipt._identity_digest,
            receipt._delta_digest,
            receipt._receipt_id,
            receipt._integrity,
        )
        if (
            any(type(value) is not str or not value for value in values)
            or type(receipt._preparation_object_id) is not int
            or receipt._owner_id != self._action_cohort_owner_id
        ):
            return False
        expected = self._action_cohort_receipt_integrity(
            preparation_id=receipt._preparation_id,
            cohort_digest=receipt._cohort_digest,
            identity_digest=receipt._identity_digest,
            delta_digest=receipt._delta_digest,
            receipt_id=receipt._receipt_id,
            preparation_object_id=receipt._preparation_object_id,
        )
        return hmac.compare_digest(receipt._integrity, expected)

    def _action_cohort_binding_is_valid(
        self,
        binding: object,
    ) -> bool:
        if (
            type(binding) is not _ExecutionEffectAuditCohortBinding
            or type(binding.cohort_digest) is not str
            or type(binding.identity_digest) is not str
        ):
            return False
        try:
            expected, cohort_digest = self._validate_action_cohort_inputs(
                root_action_id=binding.root_action_id,
                entries=binding.entries,
                owned_plans=binding.owned_plans,
                published_provenances=binding.published_provenances,
            )
        except (ExecutionEffectPlanError, AttributeError, TypeError, ValueError):
            return False
        if Counter(expected) != Counter(binding.published_provenances):
            return False
        identity_digest = _execution_effect_audit_identity_digest(
            entries=binding.entries,
            owned_plans=binding.owned_plans,
            published_provenances=binding.published_provenances,
        )
        return bool(
            hmac.compare_digest(binding.cohort_digest, cohort_digest)
            and hmac.compare_digest(binding.identity_digest, identity_digest)
        )

    def _action_cohort_delta_is_valid(
        self,
        delta: object,
        *,
        cohort_digest: str,
        expected_digest: str,
    ) -> bool:
        if (
            type(delta) is not _ExecutionEffectAuditDelta
            or type(delta.counts) is not tuple
            or len(delta.counts) != len(self._KEYS)
        ):
            return False
        for index, pair in enumerate(delta.counts):
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or type(pair[0]) is not str
                or pair[0] != self._KEYS[index]
                or type(pair[1]) is not int
                or isinstance(pair[1], bool)
                or pair[1] < 0
            ):
                return False
        scalar_values = (
            delta.digest_count,
            delta.digest_xor,
            delta.digest_sum,
            delta.realized_occurrence_count,
            delta.realized_occurrence_xor,
            delta.realized_occurrence_sum,
            delta.published_occurrence_count,
            delta.published_occurrence_xor,
            delta.published_occurrence_sum,
        )
        if any(
            type(value) is not int or isinstance(value, bool) or value < 0
            for value in scalar_values
        ):
            return False
        if any(
            value >= 1 << 256
            for value in (
                delta.digest_xor,
                delta.digest_sum,
                delta.realized_occurrence_xor,
                delta.realized_occurrence_sum,
                delta.published_occurrence_xor,
                delta.published_occurrence_sum,
            )
        ):
            return False
        if type(cohort_digest) is not str or type(expected_digest) is not str:
            return False
        actual_digest = _execution_effect_audit_delta_digest(
            delta,
            cohort_digest=cohort_digest,
        )
        return hmac.compare_digest(actual_digest, expected_digest)

    def _active_action_cohort_record_locked(
        self,
        preparation: object,
    ) -> _ExecutionEffectAuditPreparationRecord | None:
        if type(preparation) is not PreparedExecutionEffectAuditCommit:
            return None
        preparation_id = self._action_cohort_preparation_locators.get(id(preparation))
        if preparation_id is None:
            return None
        record = self._action_cohort_preparations.get(preparation_id)
        if (
            type(record) is not _ExecutionEffectAuditPreparationRecord
            or record.preparation is not preparation
        ):
            return None
        return record

    def _action_cohort_record_authenticates_locked(
        self,
        record: _ExecutionEffectAuditPreparationRecord,
    ) -> bool:
        if type(record) is not _ExecutionEffectAuditPreparationRecord:
            return False
        preparation = record.preparation
        token = record.token
        return bool(
            type(preparation) is PreparedExecutionEffectAuditCommit
            and preparation._counter is self
            and preparation._binding is record.binding
            and preparation._token is token
            and type(preparation._committed) is bool
            and not preparation._committed
            and type(preparation._cancelled) is bool
            and not preparation._cancelled
            and preparation._receipt is None
            and type(record.state) is str
            and record.state in {"prepared", "claimed"}
            and (
                record.claiming_thread is None
                if record.state == "prepared"
                else type(record.claiming_thread) is int
            )
            and self._action_cohort_token_shape_is_valid(token)
            and self._action_cohort_binding_is_valid(record.binding)
            and token._cohort_digest == record.binding.cohort_digest
            and token._identity_digest == record.binding.identity_digest
            and self._action_cohort_delta_is_valid(
                preparation._delta,
                cohort_digest=record.binding.cohort_digest,
                expected_digest=token._delta_digest,
            )
            and self._action_cohort_receipt_shape_is_valid(record.receipt)
            and record.receipt._preparation_id == token._preparation_id
            and record.receipt._cohort_digest == token._cohort_digest
            and record.receipt._identity_digest == token._identity_digest
            and record.receipt._delta_digest == token._delta_digest
            and record.receipt._preparation_object_id == id(preparation)
        )

    def _action_cohort_record_authenticates_total_locked(
        self,
        record: _ExecutionEffectAuditPreparationRecord,
    ) -> bool:
        """Return false for every malformed active record without leaking exceptions."""

        try:
            return self._action_cohort_record_authenticates_locked(record)
        except (AttributeError, KeyError, OverflowError, TypeError, UnicodeError, ValueError):
            return False

    def _release_action_cohort_record_locked(
        self,
        record: _ExecutionEffectAuditPreparationRecord,
    ) -> None:
        preparation_id = self._action_cohort_preparation_locators.pop(
            id(record.preparation),
            "",
        )
        if self._action_cohort_preparations.get(preparation_id) is record:
            del self._action_cohort_preparations[preparation_id]
        self._action_cohort_capability_locators.pop(id(record.token), None)
        if record.state == "prepared":
            self._action_cohort_prepared_count -= 1
        elif record.state == "claimed":
            self._action_cohort_claimed_count -= 1
        record.preparation._cancelled = True
        record.claiming_thread = None
        record.state = "cancelled"

    def _commit_prepared_action_cohort(
        self,
        preparation: object,
    ) -> ExecutionEffectAuditCommitReceipt:
        """Apply one already validated claimed delta under one atomic lock update."""

        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            if record is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation is foreign, copied, or stale",
                )
            if (
                record.state != "claimed"
                or record.claiming_thread != get_ident()
                or not self._action_cohort_record_authenticates_total_locked(record)
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation is not authentically claimed",
                )
            delta = record.preparation._delta
            receipt = record.receipt

            # Derive the entire fixed-cardinality replacement before changing
            # any canonical field.  A failure here leaves the main counter
            # byte-for-byte untouched and the claim context cleans the ticket.
            updated_counts = self._counts.copy()
            for key, value in delta.counts:
                updated_counts[key] += value
            digest_count = self._digest_count + delta.digest_count
            digest_xor = self._digest_xor ^ delta.digest_xor
            digest_sum = (self._digest_sum + delta.digest_sum) % (1 << 256)
            realized_occurrence_count = (
                self._realized_occurrence_count + delta.realized_occurrence_count
            )
            realized_occurrence_xor = self._realized_occurrence_xor ^ delta.realized_occurrence_xor
            realized_occurrence_sum = (
                self._realized_occurrence_sum + delta.realized_occurrence_sum
            ) % (1 << 256)
            published_occurrence_count = (
                self._published_occurrence_count + delta.published_occurrence_count
            )
            published_occurrence_xor = (
                self._published_occurrence_xor ^ delta.published_occurrence_xor
            )
            published_occurrence_sum = (
                self._published_occurrence_sum + delta.published_occurrence_sum
            ) % (1 << 256)

            # This is the sole canonical mutation block.  It performs only
            # object assignments under the one counter lock; the receipt stays
            # inaccessible until every aggregate field has been replaced.
            self._counts = updated_counts
            self._digest_count = digest_count
            self._digest_xor = digest_xor
            self._digest_sum = digest_sum
            self._realized_occurrence_count = realized_occurrence_count
            self._realized_occurrence_xor = realized_occurrence_xor
            self._realized_occurrence_sum = realized_occurrence_sum
            self._published_occurrence_count = published_occurrence_count
            self._published_occurrence_xor = published_occurrence_xor
            self._published_occurrence_sum = published_occurrence_sum
            record.preparation._committed = True
            record.preparation._receipt = receipt
            preparation_id = self._action_cohort_preparation_locators.pop(id(record.preparation))
            del self._action_cohort_preparations[preparation_id]
            self._action_cohort_capability_locators.pop(id(record.token), None)
            self._action_cohort_claimed_count -= 1
            record.claiming_thread = None
            record.state = "committed"
            return receipt

    def record(self, reconciliation: ExecutionEffectReconciliation) -> None:
        """Record one reconciliation without retaining its detailed graph."""

        summary = reconciliation.summary
        planned_outcomes = tuple(
            outcome
            for outcome in reconciliation.outcomes
            if outcome.node_id not in reconciliation.unexpected_node_ids
        )
        status_counts = Counter(outcome.status for outcome in planned_outcomes)
        digest_value = int.from_bytes(
            bytes.fromhex(_execution_effect_reconciliation_digest(reconciliation)),
            "big",
        )
        with self._lock:
            self._counts["plan_count"] += 1
            self._counts["no_effect_plan_count"] += int(summary.planned_count == 0)
            self._counts["planned_node_count"] += summary.planned_count
            self._counts["required_node_count"] += reconciliation.plan_summary.required_count
            self._counts["optional_node_count"] += reconciliation.plan_summary.optional_count
            self._counts["externally_owned_node_count"] += (
                reconciliation.plan_summary.externally_owned_count
            )
            self._counts["planned_effect_occurrence_count"] += max(
                0,
                summary.estimated_occurrences - 1,
            )
            self._counts["realized_node_count"] += status_counts[EffectOutcomeStatus.REALIZED]
            self._counts["realized_effect_occurrence_count"] += summary.realized_occurrence_count
            self._counts["linked_node_count"] += status_counts[EffectOutcomeStatus.LINKED]
            self._counts["suppressed_node_count"] += status_counts[EffectOutcomeStatus.SUPPRESSED]
            self._counts["failed_node_count"] += len(reconciliation.failed_outcome_node_ids)
            self._counts["missing_node_count"] += len(reconciliation.missing_node_ids)
            self._counts["missing_required_node_count"] += len(
                reconciliation.missing_required_node_ids
            )
            self._counts["unexpected_node_count"] += len(reconciliation.unexpected_node_ids)
            self._counts["unplanned_failure_count"] += len(reconciliation.unplanned_failures)
            self._counts["invalid_outcome_node_count"] += len(
                reconciliation.invalid_outcome_node_ids
            )
            self._counts["policy_invalid_outcome_count"] += len(
                reconciliation.policy_invalid_outcome_node_ids
            )
            self._counts["cardinality_mismatch_count"] += len(
                reconciliation.cardinality_mismatch_node_ids
            )
            self._counts["incomplete_reconciliation_count"] += int(not summary.complete)
            for outcome in planned_outcomes:
                if (
                    outcome.status != EffectOutcomeStatus.REALIZED
                    or outcome.node_id not in reconciliation.audited_occurrence_node_ids
                ):
                    continue
                for ordinal in range(outcome.canonical_occurrence_count or 0):
                    occurrence_digest = _effect_occurrence_digest_value(
                        reconciliation.action_id,
                        outcome.node_id,
                        ordinal,
                    )
                    self._realized_occurrence_count += 1
                    self._realized_occurrence_xor ^= occurrence_digest
                    self._realized_occurrence_sum = (
                        self._realized_occurrence_sum + occurrence_digest
                    ) % (1 << 256)
            self._digest_count += 1
            self._digest_xor ^= digest_value
            self._digest_sum = (self._digest_sum + digest_value) % (1 << 256)

    def record_rejected_outcomes(self, error: ExecutionEffectPlanError) -> None:
        """Retain a compact rejection count when a caller audits before re-raising."""

        if error.code != ExecutionEffectPlanErrorCode.DUPLICATE_OUTCOME:
            return
        with self._lock:
            self._counts["duplicate_outcome_count"] += 1
            self._counts["incomplete_reconciliation_count"] += 1

    def record_owned_effect_plan(self, plan: OwnedEffectOccurrencePlan) -> None:
        """Register one bounded family-owned root without retaining action history."""

        if not isinstance(plan, OwnedEffectOccurrencePlan):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                f"unsupported owned effect occurrence plan {type(plan).__name__}",
            )
        with self._lock:
            self._counts["owned_effect_plan_count"] += 1
            self._counts["owned_effect_expected_occurrence_count"] += plan.occurrence_count
            for ordinal in range(plan.occurrence_count):
                occurrence_digest = _effect_occurrence_digest_value(
                    plan.plan_action_id,
                    plan.node_id,
                    ordinal,
                )
                self._realized_occurrence_count += 1
                self._realized_occurrence_xor ^= occurrence_digest
                self._realized_occurrence_sum = (
                    self._realized_occurrence_sum + occurrence_digest
                ) % (1 << 256)

    def record_published_effect_occurrence(
        self,
        provenance: EffectOccurrenceProvenance | None,
        *,
        effect_kind: EffectOccurrenceKind,
    ) -> None:
        """Record one independently published file/registry occurrence without history."""

        with self._lock:
            if provenance is None or provenance.kind != effect_kind:
                self._counts["unprovenanced_effect_occurrence_count"] += 1
                return
            if provenance.disposition == EffectOccurrenceDisposition.EXEMPT:
                self._counts["exempt_effect_occurrence_count"] += 1
                return
            if provenance.disposition == EffectOccurrenceDisposition.OWNED_ROOT:
                self._counts["owned_effect_published_occurrence_count"] += 1
            occurrence_digest = _effect_occurrence_digest_value(
                provenance.plan_action_id,
                provenance.node_id,
                provenance.occurrence_ordinal,
            )
            self._counts["published_effect_occurrence_count"] += 1
            self._published_occurrence_count += 1
            self._published_occurrence_xor ^= occurrence_digest
            self._published_occurrence_sum = (
                self._published_occurrence_sum + occurrence_digest
            ) % (1 << 256)

    def snapshot(self) -> ExecutionEffectAuditSnapshot:
        """Return an immutable count-only view of the current audit totals."""

        with self._lock:
            values = {key: self._counts[key] for key in self._KEYS}
            digest_payload = (
                f"execution-effect-audit-v1:{self._digest_count}:"
                f"{self._digest_xor:064x}:{self._digest_sum:064x}"
            )
            reconciliation_digest = hashlib.sha256(digest_payload.encode("ascii")).hexdigest()
            publication_matches = (
                self._published_occurrence_count == self._realized_occurrence_count
                and self._published_occurrence_xor == self._realized_occurrence_xor
                and self._published_occurrence_sum == self._realized_occurrence_sum
            )
            values["effect_publication_mismatch_count"] = int(not publication_matches)
            values["reconciled_effect_occurrence_count"] = self._realized_occurrence_count
            effect_occurrence_payload = (
                f"execution-effect-occurrence-v1:{self._published_occurrence_count}:"
                f"{self._published_occurrence_xor:064x}:"
                f"{self._published_occurrence_sum:064x}"
            )
            effect_occurrence_digest = hashlib.sha256(
                effect_occurrence_payload.encode("ascii")
            ).hexdigest()
        return ExecutionEffectAuditSnapshot(
            **values,
            reconciliation_digest=reconciliation_digest,
            effect_occurrence_digest=effect_occurrence_digest,
        )


def _execution_effect_reconciliation_digest(
    reconciliation: ExecutionEffectReconciliation,
) -> str:
    """Hash one reconciliation without retaining its detailed outcome graph."""

    if reconciliation.plan_summary.node_count == 0 and reconciliation.complete:
        # A valid no-effect reconciliation carries no effect identity.  Root
        # action IDs can legitimately vary with renderer-dependent process
        # visibility, so including them would make this effect-only audit
        # digest change when canonical effect truth and every count are equal.
        return hashlib.sha256(b"execution-effect-empty-plan-v1").hexdigest()
    payload = {
        "action_id": reconciliation.action_id,
        "plan": reconciliation.plan_summary.as_dict(),
        "outcomes": [
            {
                "node_id": outcome.node_id,
                "status": outcome.status.value,
                "child_action_id": outcome.child_action_id,
                "canonical_occurrence_count": outcome.canonical_occurrence_count,
            }
            for outcome in reconciliation.outcomes
        ],
        "missing": reconciliation.missing_node_ids,
        "missing_required": reconciliation.missing_required_node_ids,
        "unexpected": reconciliation.unexpected_node_ids,
        "invalid": reconciliation.invalid_outcome_node_ids,
        "policy_invalid": reconciliation.policy_invalid_outcome_node_ids,
        "cardinality_mismatch": reconciliation.cardinality_mismatch_node_ids,
        "failed": reconciliation.failed_outcome_node_ids,
        "unplanned": [
            {
                "effect_kind": failure.effect_kind.value,
                "canonical_occurrence_count": failure.canonical_occurrence_count,
                "reason": failure.reason,
            }
            for failure in reconciliation.unplanned_failures
        ],
        "audited_occurrence_nodes": reconciliation.audited_occurrence_node_ids,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _effect_occurrence_digest_value(plan_action_id: str, node_id: str, ordinal: int) -> int:
    """Return one commutative exact-occurrence digest value for audit parity."""

    payload = f"execution-effect-occurrence-v1:{plan_action_id}:{node_id}:{ordinal}"
    return int.from_bytes(hashlib.sha256(payload.encode("utf-8")).digest(), "big")


def _compact_ids(values: list[str] | tuple[str, ...], *, limit: int = 8) -> str:
    """Bound diagnostic identifier lists so large plans retain compact failures."""

    rendered = list(values[:limit])
    remaining = len(values) - len(rendered)
    suffix = f", ... (+{remaining})" if remaining > 0 else ""
    return ", ".join(rendered) + suffix


def _compact_failed_outcomes(
    outcomes: tuple[EffectExecutionOutcome, ...],
    *,
    limit: int = 4,
) -> str:
    """Render bounded planned-node failure diagnostics with their reasons."""

    rendered = [f"{outcome.node_id} ({outcome.reason})" for outcome in outcomes[:limit]]
    remaining = len(outcomes) - len(rendered)
    suffix = f", ... (+{remaining})" if remaining > 0 else ""
    return ", ".join(rendered) + suffix


def _compact_unplanned_failures(
    failures: tuple[UnplannedEffectFailure, ...],
    *,
    limit: int = 4,
) -> str:
    """Render bounded effect-kind failures that have no planned node identity."""

    rendered = [
        f"{failure.effect_kind.value} count={failure.canonical_occurrence_count} ({failure.reason})"
        for failure in failures[:limit]
    ]
    remaining = len(failures) - len(rendered)
    suffix = f", ... (+{remaining})" if remaining > 0 else ""
    return ", ".join(rendered) + suffix


__all__ = [
    "ChildProcessEffectIntent",
    "CommandEffectIntent",
    "EffectActorKind",
    "EffectActorRef",
    "EffectExecutionOutcome",
    "EffectKind",
    "EffectOutcomeStatus",
    "EffectRequirement",
    "ExecutionEffectAuditCounter",
    "ExecutionEffectAuditSnapshot",
    "ExecutionEffectNode",
    "ExecutionEffectPlan",
    "ExecutionEffectPlanError",
    "ExecutionEffectPlanErrorCode",
    "ExecutionEffectPlanSummary",
    "ExecutionEffectReconciliation",
    "ExecutionEffectResultSummary",
    "FileEffectAction",
    "FileEffectIntent",
    "NetworkEffectIntent",
    "RegistryEffectAction",
    "RegistryEffectIntent",
    "ROOT_PROCESS_ACTOR",
    "ScannerEffectIntent",
    "ScheduledTaskEffectAction",
    "ScheduledTaskEffectIntent",
    "SessionEffectAction",
    "SessionEffectIntent",
    "ServiceEffectAction",
    "ServiceEffectIntent",
    "TransferEffectIntent",
    "UnplannedEffectFailure",
    "WindowsAuditEffectIntent",
    "WindowsAuditEffectKind",
    "stable_effect_node_id",
]
