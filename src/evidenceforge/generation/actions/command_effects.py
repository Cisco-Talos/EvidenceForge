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
from datetime import datetime, timedelta, timezone
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
DEFAULT_EXECUTION_EFFECT_AUDIT_COHORT_MEMBER_CAPACITY = 16_384
DEFAULT_EXECUTION_EFFECT_AUDIT_COHORT_BYTE_CAPACITY = 4 * 1024 * 1024
DEFAULT_EXECUTION_EFFECT_AUDIT_RETAINED_MEMBER_CAPACITY = 262_144
DEFAULT_EXECUTION_EFFECT_AUDIT_RETAINED_BYTE_CAPACITY = 64 * 1024 * 1024


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
    _publication_token: str = field(repr=False)
    _preparation_object_id: int
    _integrity: str = field(repr=False)

    @property
    def publication_token(self) -> str:
        """Return the bounded opaque proof suitable for an outer publication receipt."""

        return self._publication_token


@dataclass(frozen=True, slots=True)
class ExecutionEffectAuditPreparationCensus:
    """Constant-time transient census for prepared audit-cohort capabilities."""

    prepared: int
    claimed: int
    capacity: int
    retained_members: int
    retained_member_capacity: int
    retained_bytes: int
    retained_byte_capacity: int
    cohort_member_capacity: int
    cohort_byte_capacity: int
    prepared_commit_plans: int
    mutation_fences: int

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
class _ExecutionEffectAuditPreparedCommitPlan:
    """Fully derived canonical replacement retained by one exclusive claim."""

    counts: Counter[str]
    digest_count: int
    digest_xor: int
    digest_sum: int
    realized_occurrence_count: int
    realized_occurrence_xor: int
    realized_occurrence_sum: int
    published_occurrence_count: int
    published_occurrence_xor: int
    published_occurrence_sum: int
    receipt: ExecutionEffectAuditCommitReceipt


@dataclass(frozen=True, slots=True)
class _ExecutionEffectAuditCohortBinding:
    """Closed canonical primitives retained by one active capability."""

    root_action_id: str
    canonical_payload: bytes
    entry_identity_digest: str
    owned_plan_identity_digest: str
    provenance_identity_digest: str
    cohort_digest: str
    identity_digest: str
    retained_members: int
    retained_bytes: int


@dataclass(frozen=True, slots=True)
class _ValidatedExecutionEffectAuditCohort:
    """Ephemeral canonical copies used only while preparing one audit delta."""

    root_action_id: str
    entries: tuple[ExecutionEffectAuditCohortEntry, ...]
    owned_plans: tuple[OwnedEffectOccurrencePlan, ...]
    published_provenances: tuple[EffectOccurrenceProvenance, ...]
    canonical_payload: bytes
    entry_identity_digest: str
    owned_plan_identity_digest: str
    provenance_identity_digest: str
    cohort_digest: str
    identity_digest: str
    retained_members: int
    retained_bytes: int


class PreparedExecutionEffectAuditCommit:
    """Exact one-shot capability for a validated action-cohort audit delta."""

    __slots__ = (
        "_cancelled",
        "_binding",
        "_capability_id",
        "_certified_receipt",
        "_claim_plan",
        "_claim_preparation_id",
        "_claim_record",
        "_claim_thread_id",
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
        self._capability_id = id(self)
        self._committed = False
        self._cancelled = False
        self._certified_receipt: ExecutionEffectAuditCommitReceipt | None = None
        self._claim_plan: _ExecutionEffectAuditPreparedCommitPlan | None = None
        self._claim_preparation_id: str | None = None
        self._claim_record: _ExecutionEffectAuditPreparationRecord | None = None
        self._claim_thread_id: int | None = None
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

    @property
    def expected_receipt(self) -> ExecutionEffectAuditCommitReceipt:
        """Return the exact immutable receipt authenticated by the active claim."""

        return self._counter._expected_action_cohort_receipt(self)

    def certify_composite_commit(
        self,
        expected_receipt: ExecutionEffectAuditCommitReceipt,
    ) -> None:
        """Authenticate this exact claim once for a later composite commit tail."""

        if self._certified_receipt is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit preparation is already composite-certified",
            )
        if self.expected_receipt is not expected_receipt:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit composite certification requires its exact "
                "expected receipt object",
            )
        self._certified_receipt = expected_receipt

    def commit_no_fail(self) -> ExecutionEffectAuditCommitReceipt:
        """Atomically apply the already validated fixed-size delta exactly once."""

        if self._capability_id != id(self) or self._cancelled:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit preparation is foreign, copied, or stale",
            )
        if self._committed:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit preparation is stale after commit",
            )
        if self._claim_thread_id != get_ident():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit preparation must commit on its claiming thread",
            )
        plan = self._claim_plan
        record = self._claim_record
        preparation_id = self._claim_preparation_id
        if plan is None or record is None or preparation_id is None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit preparation is not actively claimed",
            )
        if self._certified_receipt is not None and self._certified_receipt is not plan.receipt:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "execution-effect audit composite certification is stale",
            )
        return self._counter._commit_prepared_action_cohort(
            preparation_id=preparation_id,
            record=record,
            plan=plan,
        )


@dataclass(slots=True)
class _ExecutionEffectAuditPreparationRecord:
    """Exact active-object reservation for one audit preparation."""

    preparation: PreparedExecutionEffectAuditCommit
    binding: _ExecutionEffectAuditCohortBinding
    token: ExecutionEffectAuditBindingToken
    receipt: ExecutionEffectAuditCommitReceipt
    retained_members: int
    retained_bytes: int
    state: str = "prepared"
    claiming_thread: int | None = None
    commit_plan: _ExecutionEffectAuditPreparedCommitPlan | None = None


def _closed_datetime_payload(value: datetime | None) -> object:
    """Return a callback-free primitive for an already canonical datetime."""

    if value is None:
        return None
    if type(value) is not datetime or (
        value.tzinfo is not None and type(value.tzinfo) is not timezone
    ):
        raise TypeError("audit datetime was not canonicalized to a fixed-offset value")
    offset = value.utcoffset()
    offset_microseconds = None
    if offset is not None:
        offset_microseconds = (
            offset.days * 86_400 + offset.seconds
        ) * 1_000_000 + offset.microseconds
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        value.fold,
        value.tzinfo is not None,
        offset_microseconds,
    )


def _canonical_execution_effect_intent_payload(intent: CommandEffectIntent) -> dict[str, object]:
    """Return every semantic field of one already reconstructed intent."""

    common: dict[str, object] = {
        "kind": intent.kind.value,
        "semantic_key": intent.semantic_key,
        "occurrence_cardinality": intent.occurrence_cardinality,
    }
    if type(intent) is ChildProcessEffectIntent:
        common.update(image=intent.image, command_line=intent.command_line)
    elif type(intent) is FileEffectIntent:
        common.update(action=intent.action.value, path=intent.path)
    elif type(intent) is RegistryEffectIntent:
        common.update(
            action=intent.action.value,
            key=intent.key,
            value_name=intent.value_name,
        )
    elif type(intent) is NetworkEffectIntent:
        common.update(
            destination=intent.destination,
            destination_port=intent.destination_port,
            protocol=intent.protocol,
            service=intent.service,
        )
    elif type(intent) is TransferEffectIntent:
        common.update(
            protocol=intent.protocol,
            source_path=intent.source_path,
            destination=intent.destination,
            destination_path=intent.destination_path,
        )
    elif type(intent) is ScannerEffectIntent:
        common.update(tool=intent.tool, target=intent.target, probe_count=intent.probe_count)
    elif type(intent) is ScheduledTaskEffectIntent:
        common.update(action=intent.action.value, task_name=intent.task_name)
    elif type(intent) is ServiceEffectIntent:
        common.update(
            action=intent.action.value,
            service_name=intent.service_name,
            image=intent.image,
        )
    elif type(intent) is SessionEffectIntent:
        common.update(
            action=intent.action.value,
            session_kind=intent.session_kind,
            principal=intent.principal,
        )
    elif type(intent) is WindowsAuditEffectIntent:
        common.update(
            audit_kind=intent.audit_kind.value,
            semantic_target=intent.semantic_target,
        )
    else:
        raise TypeError("execution-effect audit intent was not canonically reconstructed")
    return common


def _execution_effect_audit_cohort_payload(
    *,
    root_action_id: str,
    entries: tuple[ExecutionEffectAuditCohortEntry, ...],
    owned_plans: tuple[OwnedEffectOccurrencePlan, ...],
    published_provenances: tuple[EffectOccurrenceProvenance, ...],
) -> bytes:
    """Encode canonical cohort values and caller-supplied semantic order."""

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
                        "intent": _canonical_execution_effect_intent_payload(node.intent),
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
                            "completed_at": _closed_datetime_payload(outcome.completed_at),
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
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


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


def _exact_identity_digest(label: str, identities: tuple[int, ...]) -> str:
    """Hash ordered object identities without invoking caller equality or repr."""

    digest = hashlib.sha256(f"execution-effect-audit-{label}-identity-v2\0".encode("ascii"))
    for identity in identities:
        digest.update(str(identity).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _is_lower_hex(value: object, *, length: int) -> bool:
    """Return whether ``value`` is one exact bounded lowercase hexadecimal string."""

    return bool(
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _execution_effect_entry_identity_digest(entries: object) -> str | None:
    """Return the exact nested identity binding for an entry tuple, or ``None``."""

    if type(entries) is not tuple:
        return None
    identities: list[int] = []
    try:
        for entry in entries:
            if type(entry) is not ExecutionEffectAuditCohortEntry:
                return None
            plan = entry.plan
            reconciliation = entry.reconciliation
            if (
                type(plan) is not ExecutionEffectPlan
                or type(plan.anchor) is not ActionAnchor
                or type(plan.nodes) is not tuple
                or type(plan._ordered_ids) is not tuple
                or type(reconciliation) is not ExecutionEffectReconciliation
                or type(reconciliation.plan_summary) is not ExecutionEffectPlanSummary
                or type(reconciliation.outcomes) is not tuple
                or type(reconciliation.unplanned_failures) is not tuple
            ):
                return None
            identities.extend(
                (
                    id(entry),
                    id(plan),
                    id(plan.anchor),
                    id(plan.nodes),
                    id(plan._ordered_ids),
                    id(reconciliation),
                    id(reconciliation.plan_summary),
                    id(reconciliation.outcomes),
                    id(reconciliation.unplanned_failures),
                )
            )
            for node in plan.nodes:
                if (
                    type(node) is not ExecutionEffectNode
                    or type(node.actor) is not EffectActorRef
                    or type(node.depends_on) is not tuple
                ):
                    return None
                identities.extend(
                    (
                        id(node),
                        id(node.intent),
                        id(node.actor),
                        id(node.depends_on),
                    )
                )
            identities.extend(id(outcome) for outcome in reconciliation.outcomes)
            identities.extend(id(failure) for failure in reconciliation.unplanned_failures)
            for values in (
                reconciliation.missing_node_ids,
                reconciliation.missing_required_node_ids,
                reconciliation.unexpected_node_ids,
                reconciliation.invalid_outcome_node_ids,
                reconciliation.policy_invalid_outcome_node_ids,
                reconciliation.cardinality_mismatch_node_ids,
                reconciliation.failed_outcome_node_ids,
                reconciliation.audited_occurrence_node_ids,
            ):
                if type(values) is not tuple:
                    return None
                identities.append(id(values))
    except (AttributeError, TypeError):
        return None
    return _exact_identity_digest("entry", tuple(identities))


def _flat_exact_identity_digest(
    label: str,
    values: object,
    *,
    expected_type: type[object],
) -> str | None:
    """Return an ordered identity digest for one exact tuple of typed values."""

    if type(values) is not tuple or any(type(value) is not expected_type for value in values):
        return None
    return _exact_identity_digest(label, tuple(id(value) for value in values))


def _combined_execution_effect_identity_digest(
    *,
    root_action_id: str,
    entry_digest: str,
    owned_plan_digest: str,
    provenance_digest: str,
    retained_members: int,
    retained_bytes: int,
) -> str:
    """Bind all three exact nested capability families into one token field."""

    root_action_digest = hashlib.sha256(root_action_id.encode("utf-8")).hexdigest()
    payload = (
        "execution-effect-audit-identity-v2\0"
        f"{root_action_digest}\0{entry_digest}\0{owned_plan_digest}\0"
        f"{provenance_digest}\0{retained_members}\0{retained_bytes}"
    ).encode()
    return hashlib.sha256(payload).hexdigest()


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
        "_action_cohort_byte_capacity",
        "_action_cohort_claimed_preparation_id",
        "_action_cohort_member_capacity",
        "_action_cohort_owner_id",
        "_action_cohort_preparation_capacity",
        "_action_cohort_prepared_count",
        "_action_cohort_prepared_commit_plans",
        "_action_cohort_preparation_locators",
        "_action_cohort_preparations",
        "_action_cohort_retained_byte_capacity",
        "_action_cohort_retained_bytes",
        "_action_cohort_retained_member_capacity",
        "_action_cohort_retained_members",
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
        action_cohort_member_capacity: int = (
            DEFAULT_EXECUTION_EFFECT_AUDIT_COHORT_MEMBER_CAPACITY
        ),
        action_cohort_byte_capacity: int = DEFAULT_EXECUTION_EFFECT_AUDIT_COHORT_BYTE_CAPACITY,
        action_cohort_retained_member_capacity: int = (
            DEFAULT_EXECUTION_EFFECT_AUDIT_RETAINED_MEMBER_CAPACITY
        ),
        action_cohort_retained_byte_capacity: int = (
            DEFAULT_EXECUTION_EFFECT_AUDIT_RETAINED_BYTE_CAPACITY
        ),
    ) -> None:
        capacities = {
            "action_cohort_preparation_capacity": action_cohort_preparation_capacity,
            "action_cohort_member_capacity": action_cohort_member_capacity,
            "action_cohort_byte_capacity": action_cohort_byte_capacity,
            "action_cohort_retained_member_capacity": action_cohort_retained_member_capacity,
            "action_cohort_retained_byte_capacity": action_cohort_retained_byte_capacity,
        }
        invalid_capacity = next(
            (name for name, value in capacities.items() if type(value) is not int or value <= 0),
            None,
        )
        if invalid_capacity is not None:
            raise ValueError(f"{invalid_capacity} must be a positive integer")
        self._action_cohort_owner_id = secrets.token_hex(16)
        self._action_cohort_secret = secrets.token_bytes(32)
        self._action_cohort_preparation_capacity = action_cohort_preparation_capacity
        self._action_cohort_member_capacity = action_cohort_member_capacity
        self._action_cohort_byte_capacity = action_cohort_byte_capacity
        self._action_cohort_retained_member_capacity = action_cohort_retained_member_capacity
        self._action_cohort_retained_byte_capacity = action_cohort_retained_byte_capacity
        self._action_cohort_preparations: dict[
            str,
            _ExecutionEffectAuditPreparationRecord,
        ] = {}
        self._action_cohort_preparation_locators: dict[int, str] = {}
        self._action_cohort_capability_locators: dict[int, str] = {}
        self._action_cohort_prepared_count = 0
        self._action_cohort_claimed_count = 0
        self._action_cohort_prepared_commit_plans = 0
        self._action_cohort_claimed_preparation_id: str | None = None
        self._action_cohort_retained_members = 0
        self._action_cohort_retained_bytes = 0
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

        validated = self._validate_action_cohort_inputs(
            root_action_id=root_action_id,
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        )

        # Deliberately derive against an isolated counter.  The main counter is
        # not touched until the exact claimed capability reaches commit_no_fail.
        scratch = ExecutionEffectAuditCounter()
        for entry in validated.entries:
            scratch.record(entry.reconciliation)
        for plan in validated.owned_plans:
            scratch.record_owned_effect_plan(plan)
        for provenance in validated.published_provenances:
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
            cohort_digest=validated.cohort_digest,
        )
        binding = _ExecutionEffectAuditCohortBinding(
            root_action_id=validated.root_action_id,
            canonical_payload=validated.canonical_payload,
            entry_identity_digest=validated.entry_identity_digest,
            owned_plan_identity_digest=validated.owned_plan_identity_digest,
            provenance_identity_digest=validated.provenance_identity_digest,
            cohort_digest=validated.cohort_digest,
            identity_digest=validated.identity_digest,
            retained_members=validated.retained_members,
            retained_bytes=validated.retained_bytes,
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
            retained_members = self._action_cohort_retained_members + binding.retained_members
            if retained_members > self._action_cohort_retained_member_capacity:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "Execution-effect audit aggregate retained-member capacity "
                    f"({self._action_cohort_retained_member_capacity}) would be exceeded. "
                    "Commit or cancel an active cohort before retrying.",
                )
            retained_bytes = self._action_cohort_retained_bytes + binding.retained_bytes
            if retained_bytes > self._action_cohort_retained_byte_capacity:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "Execution-effect audit aggregate retained-byte capacity "
                    f"({self._action_cohort_retained_byte_capacity}) would be exceeded. "
                    "Commit or cancel an active cohort before retrying.",
                )
            preparation_id = secrets.token_hex(16)
            while preparation_id in self._action_cohort_preparations:
                preparation_id = secrets.token_hex(16)
            token = ExecutionEffectAuditBindingToken(
                _owner_id=self._action_cohort_owner_id,
                _preparation_id=preparation_id,
                _cohort_digest=validated.cohort_digest,
                _identity_digest=validated.identity_digest,
                _delta_digest=delta_digest,
                _integrity=self._action_cohort_token_integrity(
                    preparation_id=preparation_id,
                    cohort_digest=validated.cohort_digest,
                    identity_digest=validated.identity_digest,
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
            publication_token = secrets.token_hex(32)
            receipt = ExecutionEffectAuditCommitReceipt(
                _owner_id=self._action_cohort_owner_id,
                _preparation_id=preparation_id,
                _cohort_digest=validated.cohort_digest,
                _identity_digest=validated.identity_digest,
                _delta_digest=delta_digest,
                _receipt_id=receipt_id,
                _publication_token=publication_token,
                _preparation_object_id=id(preparation),
                _integrity=self._action_cohort_receipt_integrity(
                    preparation_id=preparation_id,
                    cohort_digest=validated.cohort_digest,
                    identity_digest=validated.identity_digest,
                    delta_digest=delta_digest,
                    receipt_id=receipt_id,
                    publication_token=publication_token,
                    preparation_object_id=id(preparation),
                ),
            )
            self._action_cohort_preparations[preparation_id] = (
                _ExecutionEffectAuditPreparationRecord(
                    preparation=preparation,
                    binding=binding,
                    token=token,
                    receipt=receipt,
                    retained_members=binding.retained_members,
                    retained_bytes=binding.retained_bytes,
                )
            )
            self._action_cohort_preparation_locators[id(preparation)] = preparation_id
            self._action_cohort_capability_locators[id(token)] = preparation_id
            self._action_cohort_prepared_count += 1
            self._action_cohort_retained_members = retained_members
            self._action_cohort_retained_bytes = retained_bytes
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
            if self._action_cohort_claimed_preparation_id is not None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "another execution-effect audit preparation is already claimed",
                )
            try:
                commit_plan = self._derive_action_cohort_commit_plan_locked(record)
            except BaseException:
                self._release_action_cohort_record_locked(record)
                raise
            record.state = "claimed"
            record.claiming_thread = get_ident()
            record.commit_plan = commit_plan
            record.preparation._claim_plan = commit_plan
            record.preparation._claim_preparation_id = record.token._preparation_id
            record.preparation._claim_record = record
            record.preparation._claim_thread_id = record.claiming_thread
            self._action_cohort_claimed_preparation_id = record.token._preparation_id
            self._action_cohort_prepared_count -= 1
            self._action_cohort_claimed_count += 1
            self._action_cohort_prepared_commit_plans += 1
            claimed = record.preparation
        try:
            yield claimed
        except BaseException:
            if not claimed.committed:
                with self._lock:
                    active = self._active_action_cohort_record_locked(claimed)
                    if active is record:
                        self._release_action_cohort_record_locked(active)
            raise
        else:
            if not claimed.committed:
                with self._lock:
                    active = self._active_action_cohort_record_locked(claimed)
                    if active is record:
                        self._release_action_cohort_record_locked(active)
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
        entry_identity_digest = (
            _execution_effect_entry_identity_digest(entries) if entries is not None else None
        )
        if entries is not None and entry_identity_digest is None:
            return False
        owned_plan_identity_digest = (
            _flat_exact_identity_digest(
                "owned-plan",
                owned_plans,
                expected_type=OwnedEffectOccurrencePlan,
            )
            if owned_plans is not None
            else None
        )
        if owned_plans is not None and owned_plan_identity_digest is None:
            return False
        provenance_identity_digest = (
            _flat_exact_identity_digest(
                "provenance",
                published_provenances,
                expected_type=EffectOccurrenceProvenance,
            )
            if published_provenances is not None
            else None
        )
        if published_provenances is not None and provenance_identity_digest is None:
            return False
        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            if record is None or not self._action_cohort_record_authenticates_total_locked(record):
                return False
            binding = record.binding
            if root_action_id is not None and root_action_id != binding.root_action_id:
                return False
            if (
                entry_identity_digest is not None
                and entry_identity_digest != binding.entry_identity_digest
            ):
                return False
            if (
                owned_plan_identity_digest is not None
                and owned_plan_identity_digest != binding.owned_plan_identity_digest
            ):
                return False
            return not (
                provenance_identity_digest is not None
                and provenance_identity_digest != binding.provenance_identity_digest
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

    def authenticates_expected_action_cohort_receipt(
        self,
        receipt: object,
        *,
        preparation: object,
        root_action_id: object | None = None,
        entries: object | None = None,
        owned_plans: object | None = None,
        published_provenances: object | None = None,
    ) -> bool:
        """Totally authenticate the exact receipt exposed by an active claim."""

        if type(receipt) is not ExecutionEffectAuditCommitReceipt:
            return False
        if not self.authenticates_action_cohort_preparation(
            preparation,
            root_action_id=root_action_id,
            entries=entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        ):
            return False
        with self._lock:
            record = self._active_action_cohort_record_locked(preparation)
            return bool(
                record is not None
                and record.state == "claimed"
                and record.claiming_thread == get_ident()
                and record.receipt is receipt
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
        entry_identity_digest = (
            _execution_effect_entry_identity_digest(entries) if entries is not None else None
        )
        if entries is not None and entry_identity_digest is None:
            return False
        owned_plan_identity_digest = (
            _flat_exact_identity_digest(
                "owned-plan",
                owned_plans,
                expected_type=OwnedEffectOccurrencePlan,
            )
            if owned_plans is not None
            else None
        )
        if owned_plans is not None and owned_plan_identity_digest is None:
            return False
        provenance_identity_digest = (
            _flat_exact_identity_digest(
                "provenance",
                published_provenances,
                expected_type=EffectOccurrenceProvenance,
            )
            if published_provenances is not None
            else None
        )
        if published_provenances is not None and provenance_identity_digest is None:
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
                or not self._action_cohort_token_shape_is_valid(preparation._token)
                or receipt._owner_id != preparation._token._owner_id
                or receipt._preparation_id != preparation._token._preparation_id
                or receipt._cohort_digest != preparation._token._cohort_digest
                or receipt._identity_digest != preparation._token._identity_digest
                or receipt._delta_digest != preparation._token._delta_digest
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
        if (
            entry_identity_digest is not None
            and entry_identity_digest != binding.entry_identity_digest
        ):
            return False
        if (
            owned_plan_identity_digest is not None
            and owned_plan_identity_digest != binding.owned_plan_identity_digest
        ):
            return False
        return not (
            provenance_identity_digest is not None
            and provenance_identity_digest != binding.provenance_identity_digest
        )

    def action_cohort_preparation_census(self) -> ExecutionEffectAuditPreparationCensus:
        """Return constant-time active prepared and claimed capability counts."""

        with self._lock:
            return ExecutionEffectAuditPreparationCensus(
                prepared=self._action_cohort_prepared_count,
                claimed=self._action_cohort_claimed_count,
                capacity=self._action_cohort_preparation_capacity,
                retained_members=self._action_cohort_retained_members,
                retained_member_capacity=self._action_cohort_retained_member_capacity,
                retained_bytes=self._action_cohort_retained_bytes,
                retained_byte_capacity=self._action_cohort_retained_byte_capacity,
                cohort_member_capacity=self._action_cohort_member_capacity,
                cohort_byte_capacity=self._action_cohort_byte_capacity,
                prepared_commit_plans=self._action_cohort_prepared_commit_plans,
                mutation_fences=int(self._action_cohort_claimed_preparation_id is not None),
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
    ) -> _ValidatedExecutionEffectAuditCohort:
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

        retained_members = len(owned_plans) + len(published_provenances)
        if retained_members > self._action_cohort_member_capacity:
            raise self._invalid_action_cohort(
                "execution-effect audit cohort member capacity "
                f"({self._action_cohort_member_capacity}) is exceeded"
            )
        for entry in entries:
            if (
                type(entry) is not ExecutionEffectAuditCohortEntry
                or type(entry.plan) is not ExecutionEffectPlan
                or type(entry.plan.nodes) is not tuple
                or type(entry.reconciliation) is not ExecutionEffectReconciliation
                or type(entry.reconciliation.outcomes) is not tuple
                or type(entry.reconciliation.unplanned_failures) is not tuple
            ):
                raise self._invalid_action_cohort(
                    "audit cohort entries require exact typed plan/reconciliation bindings"
                )
            # Each encoded entry accounts for its anchor, plan, summary, and
            # reconciliation; every node accounts for its intent and actor.
            # Variable dependency and text payloads are independently bounded
            # by canonical byte size.
            retained_members += (
                5
                + 3 * len(entry.plan.nodes)
                + len(entry.reconciliation.outcomes)
                + len(entry.reconciliation.unplanned_failures)
            )
            if retained_members > self._action_cohort_member_capacity:
                raise self._invalid_action_cohort(
                    "execution-effect audit cohort member capacity "
                    f"({self._action_cohort_member_capacity}) is exceeded"
                )

        canonical_entries = tuple(
            self._canonicalize_action_cohort_entry(entry) for entry in entries
        )
        canonical_owned_plans = tuple(
            self._canonicalize_owned_effect_plan(plan) for plan in owned_plans
        )
        canonical_provenances = tuple(
            self._canonicalize_effect_occurrence_provenance(provenance)
            for provenance in published_provenances
        )

        expected_specs: dict[
            tuple[str, str],
            tuple[
                EffectOccurrenceDisposition,
                EffectOccurrenceKind,
                EffectOccurrenceOwner | None,
                int,
            ],
        ] = {}
        expected_occurrence_count = 0
        entry_action_ids: set[str] = set()
        for entry in canonical_entries:
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
                key = (entry.plan.action_id, node.node_id)
                if key in expected_specs:
                    raise self._invalid_action_cohort(
                        "cohort plans derive duplicate effect occurrence roots"
                    )
                expected_specs[key] = (
                    EffectOccurrenceDisposition.PLANNED,
                    kind,
                    None,
                    node.intent.occurrence_cardinality,
                )
                expected_occurrence_count += node.intent.occurrence_cardinality

        owned_action_ids: set[str] = set()
        for plan in canonical_owned_plans:
            if plan.root_action_id != root_action_id:
                raise self._invalid_action_cohort(
                    "owned effect root does not belong to the cohort root action"
                )
            if plan.plan_action_id in owned_action_ids:
                raise self._invalid_action_cohort(
                    "owned effect roots cannot repeat a plan action identity"
                )
            owned_action_ids.add(plan.plan_action_id)
            key = (plan.plan_action_id, plan.node_id)
            if key in expected_specs:
                raise self._invalid_action_cohort(
                    "cohort plans derive duplicate effect occurrence roots"
                )
            expected_specs[key] = (
                EffectOccurrenceDisposition.OWNED_ROOT,
                plan.kind,
                plan.owner,
                plan.occurrence_count,
            )
            expected_occurrence_count += plan.occurrence_count

        if expected_occurrence_count > self._action_cohort_member_capacity:
            raise self._invalid_action_cohort(
                "execution-effect audit occurrence expansion exceeds per-cohort member capacity "
                f"({self._action_cohort_member_capacity})"
            )
        if expected_occurrence_count != len(canonical_provenances):
            raise self._invalid_action_cohort(
                "published effect provenance does not exactly match the cohort plan"
            )

        seen_provenances: set[tuple[str, str, int]] = set()
        for provenance in canonical_provenances:
            if provenance.disposition == EffectOccurrenceDisposition.EXEMPT:
                raise self._invalid_action_cohort(
                    "audit cohorts cannot publish exempt effect occurrences"
                )
            if provenance.root_action_id != root_action_id:
                raise self._invalid_action_cohort(
                    "published effect provenance does not belong to the cohort root action"
                )
            occurrence_key = (
                provenance.plan_action_id,
                provenance.node_id,
                provenance.occurrence_ordinal,
            )
            if occurrence_key in seen_provenances:
                raise self._invalid_action_cohort(
                    "audit cohorts cannot publish duplicate effect provenance"
                )
            seen_provenances.add(occurrence_key)
            expected = expected_specs.get((provenance.plan_action_id, provenance.node_id))
            if expected is None:
                raise self._invalid_action_cohort(
                    "published effect provenance does not match a cohort plan root"
                )
            disposition, kind, owner, occurrence_count = expected
            if (
                provenance.disposition is not disposition
                or provenance.kind is not kind
                or provenance.owner is not owner
                or not 0 <= provenance.occurrence_ordinal < occurrence_count
            ):
                raise self._invalid_action_cohort(
                    "published effect provenance kind, owner, or ordinal is not canonical"
                )

        canonical_payload = _execution_effect_audit_cohort_payload(
            root_action_id=root_action_id,
            entries=canonical_entries,
            owned_plans=canonical_owned_plans,
            published_provenances=canonical_provenances,
        )
        retained_bytes = len(canonical_payload)
        if retained_bytes > self._action_cohort_byte_capacity:
            raise self._invalid_action_cohort(
                "execution-effect audit cohort byte capacity "
                f"({self._action_cohort_byte_capacity}) is exceeded"
            )
        entry_identity_digest = _execution_effect_entry_identity_digest(entries)
        owned_plan_identity_digest = _flat_exact_identity_digest(
            "owned-plan",
            owned_plans,
            expected_type=OwnedEffectOccurrencePlan,
        )
        provenance_identity_digest = _flat_exact_identity_digest(
            "provenance",
            published_provenances,
            expected_type=EffectOccurrenceProvenance,
        )
        if (
            entry_identity_digest is None
            or owned_plan_identity_digest is None
            or provenance_identity_digest is None
        ):
            raise self._invalid_action_cohort(
                "audit cohort nested capability identities changed during preparation"
            )
        identity_digest = _combined_execution_effect_identity_digest(
            root_action_id=root_action_id,
            entry_digest=entry_identity_digest,
            owned_plan_digest=owned_plan_identity_digest,
            provenance_digest=provenance_identity_digest,
            retained_members=retained_members,
            retained_bytes=retained_bytes,
        )
        return _ValidatedExecutionEffectAuditCohort(
            root_action_id=root_action_id,
            entries=canonical_entries,
            owned_plans=canonical_owned_plans,
            published_provenances=canonical_provenances,
            canonical_payload=canonical_payload,
            entry_identity_digest=entry_identity_digest,
            owned_plan_identity_digest=owned_plan_identity_digest,
            provenance_identity_digest=provenance_identity_digest,
            cohort_digest=hashlib.sha256(canonical_payload).hexdigest(),
            identity_digest=identity_digest,
            retained_members=retained_members,
            retained_bytes=retained_bytes,
        )

    def _canonicalize_action_cohort_entry(
        self,
        entry: ExecutionEffectAuditCohortEntry,
    ) -> ExecutionEffectAuditCohortEntry:
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
            canonical_anchor = ActionAnchor(
                family=plan.anchor.family,
                stable_id=plan.anchor.stable_id,
                source=plan.anchor.source,
            )
            canonical_nodes = tuple(
                self._canonicalize_execution_effect_node(node) for node in plan.nodes
            )
            canonical_plan = ExecutionEffectPlan(canonical_anchor, canonical_nodes)
            canonical_outcomes = tuple(
                self._canonicalize_execution_effect_outcome(outcome)
                for outcome in reconciliation.outcomes
            )
            canonical_failures = tuple(
                UnplannedEffectFailure(
                    effect_kind=failure.effect_kind,
                    canonical_occurrence_count=failure.canonical_occurrence_count,
                    reason=failure.reason,
                )
                for failure in reconciliation.unplanned_failures
            )
            if any(
                original.effect_kind is not canonical.effect_kind
                or original.canonical_occurrence_count != canonical.canonical_occurrence_count
                or original.reason != canonical.reason
                for original, canonical in zip(
                    reconciliation.unplanned_failures,
                    canonical_failures,
                    strict=True,
                )
            ):
                raise self._invalid_action_cohort("audit cohort unplanned failure is not canonical")
            expected = canonical_plan.reconcile(
                canonical_outcomes,
                unplanned_failures=canonical_failures,
            )
        except (ExecutionEffectPlanError, AttributeError, TypeError, ValueError) as error:
            raise self._invalid_action_cohort("audit cohort entry is malformed") from error
        if plan._ordered_ids != canonical_plan._ordered_ids:
            raise self._invalid_action_cohort(
                "audit cohort plan order does not match its reconstructed graph"
            )
        summary = reconciliation.plan_summary
        expected_summary = expected.plan_summary
        if (
            reconciliation.action_id != expected.action_id
            or summary.action_id != expected_summary.action_id
            or summary.node_count != expected_summary.node_count
            or summary.required_count != expected_summary.required_count
            or summary.optional_count != expected_summary.optional_count
            or summary.externally_owned_count != expected_summary.externally_owned_count
            or summary.estimated_occurrences != expected_summary.estimated_occurrences
            or canonical_outcomes != expected.outcomes
            or canonical_failures != expected.unplanned_failures
            or any(
                actual != canonical
                for actual, canonical in (
                    (reconciliation.missing_node_ids, expected.missing_node_ids),
                    (
                        reconciliation.missing_required_node_ids,
                        expected.missing_required_node_ids,
                    ),
                    (reconciliation.unexpected_node_ids, expected.unexpected_node_ids),
                    (
                        reconciliation.invalid_outcome_node_ids,
                        expected.invalid_outcome_node_ids,
                    ),
                    (
                        reconciliation.policy_invalid_outcome_node_ids,
                        expected.policy_invalid_outcome_node_ids,
                    ),
                    (
                        reconciliation.cardinality_mismatch_node_ids,
                        expected.cardinality_mismatch_node_ids,
                    ),
                    (
                        reconciliation.failed_outcome_node_ids,
                        expected.failed_outcome_node_ids,
                    ),
                    (
                        reconciliation.audited_occurrence_node_ids,
                        expected.audited_occurrence_node_ids,
                    ),
                )
            )
        ):
            raise self._invalid_action_cohort(
                "audit cohort reconciliation does not exactly match its immutable plan"
            )
        return ExecutionEffectAuditCohortEntry(canonical_plan, expected)

    def _canonicalize_execution_effect_node(
        self,
        node: object,
    ) -> ExecutionEffectNode:
        if (
            type(node) is not ExecutionEffectNode
            or type(node.node_id) is not str
            or type(node.role) is not OccurrenceRole
            or type(node.requirement) is not EffectRequirement
            or type(node.actor) is not EffectActorRef
            or type(node.actor.kind) is not EffectActorKind
            or type(node.actor.node_id) is not str
            or type(node.depends_on) is not tuple
            or any(type(dependency) is not str for dependency in node.depends_on)
            or type(node.instance_key) is not str
            or not _execution_effect_intent_has_safe_shape(node.intent)
        ):
            raise self._invalid_action_cohort("audit cohort effect node is malformed")
        canonical_actor = EffectActorRef(node.actor.kind, node.actor.node_id)
        return ExecutionEffectNode(
            node_id=node.node_id,
            intent=self._canonicalize_execution_effect_intent(node.intent),
            role=node.role,
            requirement=node.requirement,
            actor=canonical_actor,
            depends_on=node.depends_on,
            instance_key=node.instance_key,
        )

    def _canonicalize_execution_effect_intent(
        self,
        intent: object,
    ) -> CommandEffectIntent:
        if not _execution_effect_intent_has_safe_shape(intent):
            raise self._invalid_action_cohort("audit cohort effect intent is malformed")
        if type(intent) is ChildProcessEffectIntent:
            return ChildProcessEffectIntent(
                image=intent.image,
                command_line=intent.command_line,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is FileEffectIntent:
            return FileEffectIntent(
                action=intent.action,
                path=intent.path,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is RegistryEffectIntent:
            return RegistryEffectIntent(
                action=intent.action,
                key=intent.key,
                value_name=intent.value_name,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is NetworkEffectIntent:
            return NetworkEffectIntent(
                destination=intent.destination,
                destination_port=intent.destination_port,
                protocol=intent.protocol,
                service=intent.service,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is TransferEffectIntent:
            return TransferEffectIntent(
                protocol=intent.protocol,
                source_path=intent.source_path,
                destination=intent.destination,
                destination_path=intent.destination_path,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is ScannerEffectIntent:
            return ScannerEffectIntent(
                tool=intent.tool,
                target=intent.target,
                probe_count=intent.probe_count,
            )
        if type(intent) is ScheduledTaskEffectIntent:
            return ScheduledTaskEffectIntent(
                action=intent.action,
                task_name=intent.task_name,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is ServiceEffectIntent:
            return ServiceEffectIntent(
                action=intent.action,
                service_name=intent.service_name,
                image=intent.image,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is SessionEffectIntent:
            return SessionEffectIntent(
                action=intent.action,
                session_kind=intent.session_kind,
                principal=intent.principal,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        if type(intent) is WindowsAuditEffectIntent:
            return WindowsAuditEffectIntent(
                audit_kind=intent.audit_kind,
                semantic_target=intent.semantic_target,
                occurrence_cardinality=intent.occurrence_cardinality,
            )
        raise self._invalid_action_cohort("audit cohort effect intent is malformed")

    def _canonicalize_execution_effect_outcome(
        self,
        outcome: object,
    ) -> EffectExecutionOutcome:
        if (
            type(outcome) is not EffectExecutionOutcome
            or type(outcome.node_id) is not str
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
        ):
            raise self._invalid_action_cohort("audit cohort effect outcome is malformed")
        canonical = EffectExecutionOutcome(
            node_id=outcome.node_id,
            status=outcome.status,
            child_action_id=outcome.child_action_id,
            completed_at=self._canonicalize_action_cohort_datetime(outcome.completed_at),
            reason=outcome.reason,
            canonical_occurrence_count=outcome.canonical_occurrence_count,
        )
        if (
            outcome.node_id != canonical.node_id
            or outcome.status is not canonical.status
            or outcome.child_action_id != canonical.child_action_id
            or outcome.reason != canonical.reason
            or outcome.canonical_occurrence_count != canonical.canonical_occurrence_count
        ):
            raise self._invalid_action_cohort("audit cohort effect outcome is not canonical")
        return canonical

    def _canonicalize_action_cohort_datetime(
        self,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None
        if type(value) is not datetime:
            raise self._invalid_action_cohort("audit cohort timestamp is malformed")
        fixed_timezone = None
        if value.tzinfo is not None:
            try:
                offset = value.utcoffset()
            except (AttributeError, OverflowError, TypeError, ValueError) as error:
                raise self._invalid_action_cohort(
                    "audit cohort timestamp offset is malformed"
                ) from error
            if type(offset) is not timedelta:
                raise self._invalid_action_cohort(
                    "audit cohort aware timestamp requires an exact concrete UTC offset"
                )
            safe_offset = timedelta(
                days=offset.days,
                seconds=offset.seconds,
                microseconds=offset.microseconds,
            )
            try:
                fixed_timezone = timezone(safe_offset)
            except ValueError as error:
                raise self._invalid_action_cohort(
                    "audit cohort timestamp offset lies outside datetime bounds"
                ) from error
        return datetime(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=fixed_timezone,
            fold=value.fold,
        )

    def _canonicalize_owned_effect_plan(
        self,
        plan: object,
    ) -> OwnedEffectOccurrencePlan:
        if (
            type(plan) is not OwnedEffectOccurrencePlan
            or type(plan.owner) is not EffectOccurrenceOwner
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
            canonical = OwnedEffectOccurrencePlan(
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
        if canonical.plan_action_id != plan.plan_action_id or canonical.node_id != plan.node_id:
            raise self._invalid_action_cohort("owned effect root identity is not canonical")
        return canonical

    def _canonicalize_effect_occurrence_provenance(
        self,
        provenance: object,
    ) -> EffectOccurrenceProvenance:
        if (
            type(provenance) is not EffectOccurrenceProvenance
            or type(provenance.kind) is not EffectOccurrenceKind
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
            canonical = EffectOccurrenceProvenance(
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
        return canonical

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
        publication_token: str,
        preparation_object_id: int,
    ) -> str:
        payload = (
            "execution-effect-audit-receipt-v2\0"
            f"{self._action_cohort_owner_id}\0{preparation_id}\0{cohort_digest}\0"
            f"{identity_digest}\0{delta_digest}\0{receipt_id}\0{publication_token}\0"
            f"{preparation_object_id}"
        ).encode("ascii")
        return hmac.new(self._action_cohort_secret, payload, hashlib.sha256).hexdigest()

    def _action_cohort_token_shape_is_valid(self, token: object) -> bool:
        if type(token) is not ExecutionEffectAuditBindingToken:
            return False
        if not (
            _is_lower_hex(token._owner_id, length=32)
            and _is_lower_hex(token._preparation_id, length=32)
            and _is_lower_hex(token._cohort_digest, length=64)
            and _is_lower_hex(token._identity_digest, length=64)
            and _is_lower_hex(token._delta_digest, length=64)
            and _is_lower_hex(token._integrity, length=64)
        ):
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
        if (
            not _is_lower_hex(receipt._owner_id, length=32)
            or not _is_lower_hex(receipt._preparation_id, length=32)
            or not _is_lower_hex(receipt._cohort_digest, length=64)
            or not _is_lower_hex(receipt._identity_digest, length=64)
            or not _is_lower_hex(receipt._delta_digest, length=64)
            or not _is_lower_hex(receipt._receipt_id, length=32)
            or not _is_lower_hex(receipt._publication_token, length=64)
            or not _is_lower_hex(receipt._integrity, length=64)
            or type(receipt._preparation_object_id) is not int
            or receipt._preparation_object_id <= 0
            or receipt._owner_id != self._action_cohort_owner_id
        ):
            return False
        expected = self._action_cohort_receipt_integrity(
            preparation_id=receipt._preparation_id,
            cohort_digest=receipt._cohort_digest,
            identity_digest=receipt._identity_digest,
            delta_digest=receipt._delta_digest,
            receipt_id=receipt._receipt_id,
            publication_token=receipt._publication_token,
            preparation_object_id=receipt._preparation_object_id,
        )
        return hmac.compare_digest(receipt._integrity, expected)

    def _action_cohort_binding_is_valid(
        self,
        binding: object,
    ) -> bool:
        if (
            type(binding) is not _ExecutionEffectAuditCohortBinding
            or type(binding.root_action_id) is not str
            or not binding.root_action_id
            or type(binding.canonical_payload) is not bytes
            or not binding.canonical_payload
            or not _is_lower_hex(binding.entry_identity_digest, length=64)
            or not _is_lower_hex(binding.owned_plan_identity_digest, length=64)
            or not _is_lower_hex(binding.provenance_identity_digest, length=64)
            or not _is_lower_hex(binding.cohort_digest, length=64)
            or not _is_lower_hex(binding.identity_digest, length=64)
            or type(binding.retained_members) is not int
            or type(binding.retained_bytes) is not int
            or len(binding.root_action_id) > binding.retained_bytes
            or not 0 < binding.retained_members <= self._action_cohort_member_capacity
            or binding.retained_bytes != len(binding.canonical_payload)
            or not 0 < binding.retained_bytes <= self._action_cohort_byte_capacity
        ):
            return False
        cohort_digest = hashlib.sha256(binding.canonical_payload).hexdigest()
        identity_digest = _combined_execution_effect_identity_digest(
            root_action_id=binding.root_action_id,
            entry_digest=binding.entry_identity_digest,
            owned_plan_digest=binding.owned_plan_identity_digest,
            provenance_digest=binding.provenance_identity_digest,
            retained_members=binding.retained_members,
            retained_bytes=binding.retained_bytes,
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
        if not (
            _is_lower_hex(cohort_digest, length=64) and _is_lower_hex(expected_digest, length=64)
        ):
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

    def _derive_action_cohort_commit_plan_locked(
        self,
        record: _ExecutionEffectAuditPreparationRecord,
    ) -> _ExecutionEffectAuditPreparedCommitPlan:
        """Derive every fallible replacement before exposing a claimed capability."""

        delta = record.preparation._delta
        updated_counts = self._counts.copy()
        for key, value in delta.counts:
            updated_counts[key] += value
        return _ExecutionEffectAuditPreparedCommitPlan(
            counts=updated_counts,
            digest_count=self._digest_count + delta.digest_count,
            digest_xor=self._digest_xor ^ delta.digest_xor,
            digest_sum=(self._digest_sum + delta.digest_sum) % (1 << 256),
            realized_occurrence_count=(
                self._realized_occurrence_count + delta.realized_occurrence_count
            ),
            realized_occurrence_xor=(self._realized_occurrence_xor ^ delta.realized_occurrence_xor),
            realized_occurrence_sum=(self._realized_occurrence_sum + delta.realized_occurrence_sum)
            % (1 << 256),
            published_occurrence_count=(
                self._published_occurrence_count + delta.published_occurrence_count
            ),
            published_occurrence_xor=(
                self._published_occurrence_xor ^ delta.published_occurrence_xor
            ),
            published_occurrence_sum=(
                self._published_occurrence_sum + delta.published_occurrence_sum
            )
            % (1 << 256),
            receipt=record.receipt,
        )

    def _action_cohort_commit_plan_is_valid_locked(
        self,
        record: _ExecutionEffectAuditPreparationRecord,
    ) -> bool:
        """Authenticate one precomputed replacement during the final precommit sweep."""

        plan = record.commit_plan
        if (
            type(plan) is not _ExecutionEffectAuditPreparedCommitPlan
            or type(plan.counts) is not Counter
            or plan.receipt is not record.receipt
        ):
            return False
        try:
            expected = self._derive_action_cohort_commit_plan_locked(record)
        except (AttributeError, KeyError, OverflowError, TypeError, UnicodeError, ValueError):
            return False
        return bool(
            plan.counts == expected.counts
            and plan.digest_count == expected.digest_count
            and plan.digest_xor == expected.digest_xor
            and plan.digest_sum == expected.digest_sum
            and plan.realized_occurrence_count == expected.realized_occurrence_count
            and plan.realized_occurrence_xor == expected.realized_occurrence_xor
            and plan.realized_occurrence_sum == expected.realized_occurrence_sum
            and plan.published_occurrence_count == expected.published_occurrence_count
            and plan.published_occurrence_xor == expected.published_occurrence_xor
            and plan.published_occurrence_sum == expected.published_occurrence_sum
        )

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
            and preparation._capability_id == id(preparation)
            and preparation._binding is record.binding
            and preparation._token is token
            and type(preparation._committed) is bool
            and not preparation._committed
            and type(preparation._cancelled) is bool
            and not preparation._cancelled
            and preparation._receipt is None
            and self._action_cohort_binding_is_valid(record.binding)
            and type(record.retained_members) is int
            and not isinstance(record.retained_members, bool)
            and record.retained_members == record.binding.retained_members
            and type(record.retained_bytes) is int
            and not isinstance(record.retained_bytes, bool)
            and record.retained_bytes == record.binding.retained_bytes
            and type(record.state) is str
            and record.state in {"prepared", "claimed"}
            and (
                (
                    record.claiming_thread is None
                    and record.commit_plan is None
                    and preparation._claim_plan is None
                    and preparation._claim_preparation_id is None
                    and preparation._claim_record is None
                    and preparation._claim_thread_id is None
                    and preparation._certified_receipt is None
                    and self._action_cohort_claimed_preparation_id != record.token._preparation_id
                )
                if record.state == "prepared"
                else (
                    type(record.claiming_thread) is int
                    and preparation._claim_plan is record.commit_plan
                    and preparation._claim_preparation_id == record.token._preparation_id
                    and preparation._claim_record is record
                    and preparation._claim_thread_id == record.claiming_thread
                    and (
                        preparation._certified_receipt is None
                        or preparation._certified_receipt is record.receipt
                    )
                    and self._action_cohort_claimed_preparation_id == record.token._preparation_id
                    and self._action_cohort_commit_plan_is_valid_locked(record)
                )
            )
            and self._action_cohort_token_shape_is_valid(token)
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
            self._action_cohort_prepared_commit_plans -= 1
            if self._action_cohort_claimed_preparation_id == record.token._preparation_id:
                self._action_cohort_claimed_preparation_id = None
        self._action_cohort_retained_members -= record.retained_members
        self._action_cohort_retained_bytes -= record.retained_bytes
        record.preparation._cancelled = True
        record.preparation._certified_receipt = None
        record.preparation._claim_plan = None
        record.preparation._claim_preparation_id = None
        record.preparation._claim_record = None
        record.preparation._claim_thread_id = None
        record.claiming_thread = None
        record.commit_plan = None
        record.state = "cancelled"

    def _reject_action_cohort_mutation_fence_locked(self) -> None:
        """Reject direct mutation while one exclusive replacement is claimed."""

        if self._action_cohort_claimed_preparation_id is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "a claimed execution-effect audit preparation temporarily fences mutation",
            )

    def _expected_action_cohort_receipt(
        self,
        preparation: object,
    ) -> ExecutionEffectAuditCommitReceipt:
        """Return one claim-owned receipt without allocating or authenticating after commit."""

        with self._lock:
            if type(preparation) is not PreparedExecutionEffectAuditCommit:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit expected receipt requires its exact preparation",
                )
            if preparation._counter is not self:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation belongs to another counter",
                )
            if preparation._committed:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation has no active expected receipt",
                )
            record = self._active_action_cohort_record_locked(preparation)
            if (
                record is None
                or record.state != "claimed"
                or record.claiming_thread != get_ident()
                or not self._action_cohort_record_authenticates_total_locked(record)
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "execution-effect audit preparation has no active expected receipt",
                )
            return record.receipt

    def _commit_prepared_action_cohort(
        self,
        *,
        preparation_id: str,
        record: _ExecutionEffectAuditPreparationRecord,
        plan: _ExecutionEffectAuditPreparedCommitPlan,
    ) -> ExecutionEffectAuditCommitReceipt:
        """Apply only the trusted swaps retained by one claim-certified plan."""

        with self._lock:
            # All values and the exact receipt were derived and authenticated
            # before the capability was yielded. This tail performs only
            # trusted reference/integer swaps and bounded locator cleanup.
            object.__setattr__(self, "_counts", plan.counts)
            object.__setattr__(self, "_digest_count", plan.digest_count)
            object.__setattr__(self, "_digest_xor", plan.digest_xor)
            object.__setattr__(self, "_digest_sum", plan.digest_sum)
            object.__setattr__(
                self,
                "_realized_occurrence_count",
                plan.realized_occurrence_count,
            )
            object.__setattr__(self, "_realized_occurrence_xor", plan.realized_occurrence_xor)
            object.__setattr__(self, "_realized_occurrence_sum", plan.realized_occurrence_sum)
            object.__setattr__(
                self,
                "_published_occurrence_count",
                plan.published_occurrence_count,
            )
            object.__setattr__(self, "_published_occurrence_xor", plan.published_occurrence_xor)
            object.__setattr__(self, "_published_occurrence_sum", plan.published_occurrence_sum)
            object.__setattr__(record.preparation, "_receipt", plan.receipt)
            object.__setattr__(record.preparation, "_committed", True)
            self._action_cohort_preparation_locators.pop(id(record.preparation), None)
            self._action_cohort_preparations.pop(preparation_id, None)
            self._action_cohort_capability_locators.pop(id(record.token), None)
            object.__setattr__(
                self,
                "_action_cohort_claimed_count",
                self._action_cohort_claimed_count - 1,
            )
            object.__setattr__(
                self,
                "_action_cohort_prepared_commit_plans",
                self._action_cohort_prepared_commit_plans - 1,
            )
            object.__setattr__(self, "_action_cohort_claimed_preparation_id", None)
            object.__setattr__(
                self,
                "_action_cohort_retained_members",
                self._action_cohort_retained_members - record.retained_members,
            )
            object.__setattr__(
                self,
                "_action_cohort_retained_bytes",
                self._action_cohort_retained_bytes - record.retained_bytes,
            )
            record.claiming_thread = None
            record.state = "committed"
            return plan.receipt

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
            self._reject_action_cohort_mutation_fence_locked()
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
            self._reject_action_cohort_mutation_fence_locked()
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
            self._reject_action_cohort_mutation_fence_locked()
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
            self._reject_action_cohort_mutation_fence_locked()
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
