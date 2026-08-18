# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical lifecycle authority and isolated StateManager compatibility checks.

Production dispatch publishes and validates lifecycle authority before legacy state teardown.
Direct fixtures may explicitly retain the old diagnostic-only ordering. The adapter never exposes
mutable registry state to renderers.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import PurePath
from threading import Lock
from typing import Literal, TypedDict

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contracts import EventKind
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleMembership,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.state import RunningProcess
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc

_PROCESS_START_TYPES = frozenset({EventKind.PROCESS_CREATE, EventKind.SYSTEM_PROCESS_CREATE})
_PROCESS_CLOSE_TYPES = frozenset({EventKind.PROCESS_TERMINATE})
_SESSION_START_TYPES = frozenset({EventKind.LOGON, EventKind.MACHINE_LOGON, EventKind.SSH_SESSION})
_SESSION_CLOSE_TYPES = frozenset({EventKind.LOGOFF})
_BUILTIN_LOGON_IDS = frozenset({"", "0x3e4", "0x3e5", "0x3e6", "0x3e7"})
_MAX_ANCESTOR_DEPTH = 64

LifecycleShadowPhase = Literal["prepare", "commit"]
LifecycleShadowViolationCode = Literal[
    "process_registration_failed",
    "process_start_parity_failed",
    "process_close_authority_failed",
    "process_close_parity_failed",
    "session_registration_failed",
    "session_start_parity_failed",
    "session_close_authority_failed",
    "session_close_parity_failed",
    "unclassified_shadow_failure",
]


class LifecycleShadowViolationError(StateError):
    """Typed, finite-cardinality shadow failure safe to record and continue."""

    def __init__(
        self,
        code: LifecycleShadowViolationCode,
        phase: LifecycleShadowPhase,
        detail: str,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.phase = phase


class LifecycleShadowViolationSummary(TypedDict):
    """Bounded aggregate suitable for manifests and ground-truth diagnostics."""

    total: int
    by_code: dict[str, int]
    by_event: dict[str, dict[str, int]]


class LifecycleShadow:
    """Publish canonical process/session lifecycle truth around legacy state."""

    def __init__(self, state_manager: StateManager, registry: LifecycleRegistry) -> None:
        """Bind one engine-owned lifecycle registry to its legacy state authority."""

        self._state_manager = state_manager
        self._registry = registry
        self._violation_counts: Counter[str] = Counter()
        self._violations_by_event: Counter[tuple[str, str]] = Counter()
        self._diagnostic_lock = Lock()

    @property
    def registry(self) -> LifecycleRegistry:
        """Return the engine-owned registry for diagnostics and watermark management."""

        return self._registry

    @property
    def state_manager(self) -> StateManager:
        """Return the exact State owner projected by this adapter."""

        return self._state_manager

    @property
    def violation_summary(self) -> LifecycleShadowViolationSummary:
        """Return a deterministic bounded summary without retaining entity details."""

        with self._diagnostic_lock:
            by_event: dict[str, dict[str, int]] = {}
            for (event_type, code), count in sorted(self._violations_by_event.items()):
                by_event.setdefault(event_type, {})[code] = count
            return {
                "total": sum(self._violation_counts.values()),
                "by_code": dict(sorted(self._violation_counts.items())),
                "by_event": by_event,
            }

    def record_violation(
        self,
        event: CanonicalOccurrence,
        phase: LifecycleShadowPhase,
        error: StateError,
    ) -> None:
        """Record one typed shadow failure without retaining its unbounded detail."""

        if isinstance(error, LifecycleShadowViolationError) and error.phase == phase:
            code = error.code
        else:
            code = "unclassified_shadow_failure"
        event_type = (
            event.event_type.value
            if isinstance(event.event_type, EventKind)
            else str(event.event_type)
        )
        with self._diagnostic_lock:
            self._violation_counts[code] += 1
            self._violations_by_event[(event_type, code)] += 1

    def ensure_session(self, identity: SessionIdentity) -> SessionLifecycleIdentity:
        """Publish one legacy session identity through the strict registry boundary."""

        return self._ensure_session(identity)

    def ensure_process(
        self,
        identity: ProcessIdentity,
        *,
        session: SessionIdentity | None = None,
    ) -> ProcessLifecycleIdentity:
        """Publish one legacy process and its exact ancestry through the registry."""

        return self._ensure_process(identity, session=session)

    @staticmethod
    def project_session_start(identity: SessionIdentity) -> SessionLifecycleIdentity:
        """Project an allocation-free session plan into registry identity truth."""

        return SessionLifecycleIdentity(
            hostname=identity.hostname,
            object_id=identity.object_id,
            logon_id=identity.logon_id,
            principal=identity.principal,
            session_kind=identity.session_kind,
            started_at=identity.started_at,
            session_id=identity.session_id,
            logon_guid=identity.logon_guid,
        )

    def project_process_start(
        self,
        identity: ProcessIdentity,
        *,
        integrity_level: str,
        session: SessionIdentity | None,
        token_session_id: int | None,
        session_logon_type: int | None,
        parent_object_id: str,
    ) -> tuple[ProcessLifecycleIdentity, ProcessTokenIdentity, LifecycleMembership]:
        """Project immutable planned fields without consulting materialized process state."""

        token = ProcessTokenIdentity(
            principal=identity.principal,
            logon_id=identity.logon_id,
            session_id=session.session_id if session is not None else token_session_id,
            logon_type=session_logon_type,
            integrity_level=integrity_level,
        )
        if session is not None:
            membership = LifecycleMembership(
                owner_kind="session",
                owner_object_id=session.object_id,
                session_object_id=session.object_id,
            )
        else:
            owner_kind = "boot" if token.logon_id in _BUILTIN_LOGON_IDS else "detached"
            membership = LifecycleMembership(
                owner_kind=owner_kind,
                owner_object_id=stable_uuid(
                    "lifecycle-shadow-owner",
                    owner_kind,
                    identity.hostname,
                    token.principal,
                    token.logon_id,
                ),
            )
        candidate = ProcessLifecycleIdentity(
            hostname=identity.hostname,
            object_id=identity.object_id,
            pid=identity.pid,
            started_at=identity.started_at,
            image=identity.image,
            parent_object_id=parent_object_id,
            role=self._process_role(identity.image),
        )
        return candidate, token, membership

    def prepare(self, event: CanonicalOccurrence) -> None:
        """Register exact start identities and validate closure prerequisites."""

        plan = event.identity_plan
        if plan is None:
            return

        session = plan.session
        if isinstance(session, SessionIdentity) and event.event_type in (
            _SESSION_START_TYPES | _SESSION_CLOSE_TYPES | _PROCESS_START_TYPES
        ):
            try:
                self._ensure_session(session)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_registration_failed",
                    "prepare",
                    str(exc),
                ) from exc

        process = plan.subject
        if isinstance(process, ProcessIdentity) and event.event_type in (
            _PROCESS_START_TYPES | _PROCESS_CLOSE_TYPES
        ):
            try:
                self._ensure_process(
                    process,
                    session=session,
                    require_exact_parent=event.event_type in _PROCESS_START_TYPES,
                )
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_registration_failed",
                    "prepare",
                    str(exc),
                ) from exc

    def commit(self, event: CanonicalOccurrence) -> None:
        """Retain diagnostic-only post-apply behavior for explicit fixture mode."""

        plan = event.identity_plan
        if plan is None:
            return

        session = plan.session
        process = plan.subject
        if event.event_type in _PROCESS_START_TYPES and isinstance(process, ProcessIdentity):
            try:
                self._assert_process_start_parity(process)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_start_parity_failed",
                    "commit",
                    str(exc),
                ) from exc
        elif event.event_type in _PROCESS_CLOSE_TYPES and isinstance(process, ProcessIdentity):
            try:
                self._close_process(process, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_close_authority_failed",
                    "commit",
                    str(exc),
                ) from exc
            try:
                self._assert_process_close_parity(process, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_close_parity_failed",
                    "commit",
                    str(exc),
                ) from exc

        if event.event_type in _SESSION_START_TYPES and isinstance(session, SessionIdentity):
            try:
                self._assert_session_start_parity(session)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_start_parity_failed",
                    "commit",
                    str(exc),
                ) from exc
        elif event.event_type in _SESSION_CLOSE_TYPES and isinstance(session, SessionIdentity):
            try:
                self._close_session(session, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_close_authority_failed",
                    "commit",
                    str(exc),
                ) from exc
            try:
                self._assert_session_close_parity(session, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_close_parity_failed",
                    "commit",
                    str(exc),
                ) from exc

    def enforce_pre_apply(self, event: CanonicalOccurrence) -> None:
        """Validate legacy parity and commit lifecycle authority before state teardown.

        ``prepare`` must run first. All facts used here are already frozen on the
        occurrence, registry, or pre-transition ``StateManager`` view. A failure
        therefore cannot follow legacy state mutation.
        """

        plan = event.identity_plan
        if plan is None:
            return

        session = plan.session
        process = plan.subject
        if event.event_type in _PROCESS_START_TYPES and isinstance(process, ProcessIdentity):
            try:
                self._assert_process_start_parity(process)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_start_parity_failed",
                    "prepare",
                    str(exc),
                ) from exc
        elif event.event_type in _PROCESS_CLOSE_TYPES and isinstance(process, ProcessIdentity):
            try:
                self._validate_process_close_pre_apply(process, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_close_parity_failed",
                    "prepare",
                    str(exc),
                ) from exc
            try:
                self._close_process(process, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "process_close_authority_failed",
                    "prepare",
                    str(exc),
                ) from exc

        if event.event_type in _SESSION_START_TYPES and isinstance(session, SessionIdentity):
            try:
                self._assert_session_start_parity(session)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_start_parity_failed",
                    "prepare",
                    str(exc),
                ) from exc
        elif event.event_type in _SESSION_CLOSE_TYPES and isinstance(session, SessionIdentity):
            try:
                self._validate_session_close_pre_apply(session, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_close_parity_failed",
                    "prepare",
                    str(exc),
                ) from exc
            try:
                self._close_session(session, event)
            except StateError as exc:
                raise LifecycleShadowViolationError(
                    "session_close_authority_failed",
                    "prepare",
                    str(exc),
                ) from exc

    def observe_post_apply(self, event: CanonicalOccurrence) -> None:
        """Record impossible post-apply divergence without invalidating authority.

        Production has already checked the exact pre-transition state and
        committed registry authority. ``StateManager.apply`` is a deterministic,
        lock-owned teardown. This check is therefore diagnostic defense-in-depth,
        not a second rejection boundary.
        """

        plan = event.identity_plan
        if plan is None:
            return
        session = plan.session
        process = plan.subject
        checks: list[tuple[LifecycleShadowViolationCode, Callable[[], None]]] = []
        if event.event_type in _PROCESS_CLOSE_TYPES and isinstance(process, ProcessIdentity):
            checks.append(
                (
                    "process_close_parity_failed",
                    lambda: self._assert_process_close_parity(process, event),
                )
            )
        if event.event_type in _SESSION_CLOSE_TYPES and isinstance(session, SessionIdentity):
            checks.append(
                (
                    "session_close_parity_failed",
                    lambda: self._assert_session_close_parity(session, event),
                )
            )
        for code, check in checks:
            try:
                check()
            except StateError as exc:
                self.record_violation(
                    event,
                    "commit",
                    LifecycleShadowViolationError(code, "commit", str(exc)),
                )

    def _ensure_session(self, identity: SessionIdentity) -> SessionLifecycleIdentity:
        candidate = SessionLifecycleIdentity(
            hostname=identity.hostname,
            object_id=identity.object_id,
            logon_id=identity.logon_id,
            principal=identity.principal,
            session_kind=identity.session_kind,
            started_at=identity.started_at,
            session_id=identity.session_id,
            logon_guid=identity.logon_guid,
        )
        existing = self._registry.get_session(identity.object_id)
        if existing is not None:
            if existing.identity != candidate:
                raise StateError(
                    "Lifecycle shadow session identity changed after publication: "
                    f"{identity.object_id}; identity={existing.identity!r} "
                    f"candidate_identity={candidate!r}"
                )
            return existing.identity

        action_id = stable_uuid("lifecycle-shadow-start-action", "session", identity.object_id)
        self._registry.register_session(
            candidate,
            action_id=action_id,
            transition_id=stable_uuid(
                "lifecycle-shadow-start-transition",
                "session",
                identity.object_id,
            ),
        )
        return candidate

    def _ensure_process(
        self,
        identity: ProcessIdentity,
        *,
        session: SessionIdentity | None,
        ancestors: frozenset[str] = frozenset(),
        require_exact_parent: bool = False,
    ) -> ProcessLifecycleIdentity:
        existing = self._registry.get_process(identity.object_id)
        if existing is not None:
            candidate, token, membership = self._project_process(
                identity,
                session=session,
                parent_object_id=existing.identity.parent_object_id,
            )
            if existing.membership.owner_kind != "session":
                # A privileged responder may be published before authentication
                # and later receive a compatibility LogonID for legacy lookup.
                # That mutable attachment cannot rewrite its canonical boot,
                # service, transport, or detached lifecycle ownership.
                membership = existing.membership
                token = ProcessTokenIdentity(
                    principal=token.principal,
                    logon_id=token.logon_id,
                    session_id=existing.token.session_id,
                    logon_type=existing.token.logon_type,
                    integrity_level=token.integrity_level,
                )
            if not token.integrity_level or token.session_id is None or token.logon_type is None:
                # Recently ended compatibility state may retain the durable
                # ProcessIdentity without optional token enrichment.  Preserve
                # the already-published immutable fields; never reinterpret a
                # missing value as an identity mutation.
                token = ProcessTokenIdentity(
                    principal=token.principal,
                    logon_id=token.logon_id,
                    session_id=(
                        token.session_id
                        if token.session_id is not None
                        else existing.token.session_id
                    ),
                    logon_type=(
                        token.logon_type
                        if token.logon_type is not None
                        else existing.token.logon_type
                    ),
                    integrity_level=token.integrity_level or existing.token.integrity_level,
                )
            if (
                existing.identity != candidate
                or existing.token != token
                or existing.membership != membership
            ):
                raise StateError(
                    "Lifecycle shadow process identity changed after publication: "
                    f"{identity.object_id}; "
                    f"identity={existing.identity!r} candidate_identity={candidate!r}; "
                    f"token={existing.token!r} candidate_token={token!r}; "
                    f"membership={existing.membership!r} "
                    f"candidate_membership={membership!r}"
                )
            return existing.identity

        if identity.object_id in ancestors or len(ancestors) >= _MAX_ANCESTOR_DEPTH:
            raise StateError(
                f"Lifecycle shadow process ancestor cycle/depth exceeded at {identity.object_id}"
            )
        next_ancestors = ancestors | {identity.object_id}

        parent_object_id = ""
        if identity.parent_pid not in {0, 4}:
            parent = self._state_manager.get_process_identity(
                identity.hostname, identity.parent_pid
            )
            if parent is not None and self._state_manager.is_process_active_at(
                identity.hostname,
                identity.parent_pid,
                identity.started_at,
            ):
                parent_session = self._session_for_process(parent)
                self._ensure_process(
                    parent,
                    session=parent_session,
                    ancestors=next_ancestors,
                    require_exact_parent=require_exact_parent,
                )
                parent_object_id = parent.object_id
            elif require_exact_parent:
                raise StateError(
                    "Lifecycle process start has no exact active parent at its start: "
                    f"{identity.object_id} parent PID {identity.parent_pid}"
                )

        effective_session = self._validated_session_for_process(identity, session)
        if effective_session is not None:
            self._ensure_session(effective_session)
        candidate, token, membership = self._project_process(
            identity,
            session=effective_session,
            parent_object_id=parent_object_id,
        )
        action_id = stable_uuid("lifecycle-shadow-start-action", "process", identity.object_id)
        self._registry.register_process(
            candidate,
            token=token,
            membership=membership,
            action_id=action_id,
            transition_id=stable_uuid(
                "lifecycle-shadow-start-transition",
                "process",
                identity.object_id,
            ),
        )
        return candidate

    def _project_process(
        self,
        identity: ProcessIdentity,
        *,
        session: SessionIdentity | None,
        parent_object_id: str,
    ) -> tuple[ProcessLifecycleIdentity, ProcessTokenIdentity, LifecycleMembership]:
        running = self._state_manager.get_process(identity.hostname, identity.pid)
        token = self._process_token(identity, running)
        membership_session = session
        if membership_session is not None and (
            membership_session.hostname != identity.hostname
            or membership_session.logon_id != identity.logon_id
        ):
            membership_session = self._session_for_process(identity)

        if membership_session is not None:
            membership = LifecycleMembership(
                owner_kind="session",
                owner_object_id=membership_session.object_id,
                session_object_id=membership_session.object_id,
            )
        else:
            owner_kind = "boot" if token.logon_id in _BUILTIN_LOGON_IDS else "detached"
            membership = LifecycleMembership(
                owner_kind=owner_kind,
                owner_object_id=stable_uuid(
                    "lifecycle-shadow-owner",
                    owner_kind,
                    identity.hostname,
                    token.principal,
                    token.logon_id,
                ),
            )

        return (
            ProcessLifecycleIdentity(
                hostname=identity.hostname,
                object_id=identity.object_id,
                pid=identity.pid,
                started_at=identity.started_at,
                image=identity.image,
                parent_object_id=parent_object_id,
                role=self._process_role(identity.image),
            ),
            token,
            membership,
        )

    def _process_token(
        self,
        identity: ProcessIdentity,
        running: RunningProcess | None,
    ) -> ProcessTokenIdentity:
        if running is not None and running.ecar_object_id != identity.object_id:
            # PID reuse must not leak the current process token into a retained
            # canonical identity for an older process instance.
            running = None
        principal = running.username if running is not None else identity.principal
        logon_id = (
            running.token_logon_id or running.logon_id if running is not None else identity.logon_id
        )
        session_identity = self._state_manager.get_session_identity(logon_id) if logon_id else None
        return ProcessTokenIdentity(
            principal=principal,
            logon_id=logon_id,
            session_id=(
                running.auth_session_id
                if running is not None and running.auth_session_id is not None
                else session_identity.session_id
                if session_identity is not None
                else None
            ),
            logon_type=(
                running.auth_logon_type
                if running is not None and running.auth_logon_type is not None
                else self._state_manager.get_session_logon_type(logon_id)
                if logon_id
                else None
            ),
            integrity_level=running.integrity_level if running is not None else "",
        )

    def _session_for_process(self, identity: ProcessIdentity) -> SessionIdentity | None:
        if not identity.logon_id:
            return None
        session = self._state_manager.get_session_identity(identity.logon_id)
        if session is None or session.hostname != identity.hostname:
            return None
        if ensure_utc(session.started_at) > ensure_utc(identity.started_at):
            # Pre-authentication transport/service workers (for example the
            # privileged sshd child) can later carry a legacy membership LogonID
            # while retaining their boot/service lifecycle ownership.  A session
            # that did not exist when the process started cannot be its immutable
            # lifecycle membership.
            return None
        active_at_start = self._state_manager.get_session_at(
            identity.logon_id,
            identity.started_at,
        )
        if active_at_start is None:
            raise StateError(
                "Lifecycle process starts outside its referenced session interval: "
                f"{identity.object_id} in {session.object_id}"
            )
        return session

    def _validated_session_for_process(
        self,
        identity: ProcessIdentity,
        session: SessionIdentity | None,
    ) -> SessionIdentity | None:
        """Resolve exact membership and reject an inactive referenced interval."""

        if (
            session is None
            or session.hostname != identity.hostname
            or session.logon_id != identity.logon_id
        ):
            return self._session_for_process(identity)
        if ensure_utc(session.started_at) > ensure_utc(identity.started_at):
            return None
        if self._state_manager.get_session_at(identity.logon_id, identity.started_at) is None:
            raise StateError(
                "Lifecycle process starts outside its referenced session interval: "
                f"{identity.object_id} in {session.object_id}"
            )
        return session

    @staticmethod
    def _process_role(image: str) -> str:
        executable = PurePath(image.replace("\\", "/")).name.casefold()
        if executable == "userinit.exe":
            # userinit creates Explorer and exits after shell handoff; Explorer's
            # durable lifecycle is session-owned rather than child-contained.
            return "bootstrap_handoff"
        if executable in {"bash", "sh", "zsh"}:
            return "shell"
        if executable in {"nmap", "nmap.exe"}:
            return "scanner"
        return "application"

    def _close_process(
        self,
        identity: ProcessIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        snapshot = self._registry.get_process(identity.object_id)
        if snapshot is None:
            raise StateError(f"Lifecycle shadow lost process {identity.object_id} before close")
        close_at = ensure_utc(event.timestamp)
        if snapshot.closed_at is not None:
            if snapshot.closed_at != close_at:
                raise StateError(
                    f"Lifecycle shadow process {identity.object_id} closed at conflicting times"
                )
            return
        action_id = stable_uuid("lifecycle-shadow-close-action", "process", identity.object_id)
        barrier = LifecycleCloseBarrier(
            barrier_id=stable_uuid("lifecycle-shadow-close-barrier", "process", identity.object_id),
            subject=snapshot.identity.ref,
            requested_at=close_at,
            authority="generated",
            action_id=action_id,
        )
        ticket = self._registry.request_close(
            barrier,
            ticket_id=stable_uuid(
                "lifecycle-shadow-close-ticket",
                "process",
                identity.object_id,
            ),
        )
        if ticket.effective_at != close_at:
            raise StateError(
                f"Lifecycle shadow process {identity.object_id} close was extended unexpectedly"
            )
        self._registry.close(ticket.ticket_id)

    def _close_session(
        self,
        identity: SessionIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        snapshot = self._registry.get_session(identity.object_id)
        if snapshot is None:
            raise StateError(f"Lifecycle shadow lost session {identity.object_id} before close")
        close_at = ensure_utc(event.timestamp)
        if snapshot.closed_at is not None:
            if snapshot.closed_at != close_at:
                raise StateError(
                    f"Lifecycle shadow session {identity.object_id} closed at conflicting times"
                )
            return
        action_id = stable_uuid("lifecycle-shadow-close-action", "session", identity.object_id)
        barrier = LifecycleCloseBarrier(
            barrier_id=stable_uuid("lifecycle-shadow-close-barrier", "session", identity.object_id),
            subject=snapshot.identity.ref,
            requested_at=close_at,
            authority="generated",
            action_id=action_id,
        )
        ticket = self._registry.request_close(
            barrier,
            ticket_id=stable_uuid(
                "lifecycle-shadow-close-ticket",
                "session",
                identity.object_id,
            ),
        )
        if ticket.effective_at != close_at:
            raise StateError(
                f"Lifecycle shadow session {identity.object_id} close was extended unexpectedly"
            )
        self._registry.close(ticket.ticket_id)

    def _assert_process_start_parity(self, identity: ProcessIdentity) -> None:
        running = self._state_manager.get_process(identity.hostname, identity.pid)
        if running is None or running.ecar_object_id != identity.object_id:
            raise StateError(
                f"Lifecycle shadow process start disagrees with StateManager: {identity.object_id}"
            )
        resolved = self._registry.process_for_pid_at(
            identity.hostname,
            identity.pid,
            identity.started_at,
        )
        if resolved is None or resolved.identity.object_id != identity.object_id:
            raise StateError(
                f"Lifecycle shadow process start cannot resolve exact PID: {identity.object_id}"
            )

    def _validate_process_close_pre_apply(
        self,
        identity: ProcessIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        """Validate one exact live legacy process before authoritative close."""

        running = self._state_manager.get_process(identity.hostname, identity.pid)
        close_at = ensure_utc(event.timestamp)
        if (
            running is None
            or running.ecar_object_id != identity.object_id
            or ensure_utc(running.start_time) > close_at
        ):
            raise StateError(
                "Lifecycle process close has no exact live StateManager identity: "
                f"{identity.object_id}"
            )

    def _validate_session_close_pre_apply(
        self,
        identity: SessionIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        """Validate one exact active legacy session before authoritative close."""

        active = self._state_manager.get_session(identity.logon_id)
        close_at = ensure_utc(event.timestamp)
        if (
            active is None
            or active.ecar_object_id != identity.object_id
            or active.system != identity.hostname
            or ensure_utc(active.start_time) > close_at
        ):
            raise StateError(
                "Lifecycle session close has no exact active StateManager identity: "
                f"{identity.object_id}"
            )
        end_plan = active.end_plan
        if (
            end_plan is not None
            and end_plan.is_hard_deadline
            and close_at > ensure_utc(end_plan.canonical_end)
        ):
            raise StateError(
                "Lifecycle session close exceeds its hard deadline: "
                f"{identity.object_id} at {close_at.isoformat()} > "
                f"{ensure_utc(end_plan.canonical_end).isoformat()}"
            )

    def _assert_process_close_parity(
        self,
        identity: ProcessIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        close_at = ensure_utc(event.timestamp)
        snapshot = self._registry.get_process(identity.object_id)
        if (
            self._state_manager.get_process(identity.hostname, identity.pid) is not None
            or self._state_manager.is_process_active_at(identity.hostname, identity.pid, close_at)
            or snapshot is None
            or snapshot.closed_at != close_at
        ):
            raise StateError(
                f"Lifecycle shadow process close disagrees with StateManager: {identity.object_id}"
            )

    def _assert_session_start_parity(self, identity: SessionIdentity) -> None:
        current = self._state_manager.get_session_identity(identity.logon_id)
        resolved = self._registry.session_for_logon_at(
            identity.hostname,
            identity.logon_id,
            identity.started_at,
        )
        if (
            current is None
            or current.object_id != identity.object_id
            or resolved is None
            or resolved.identity.object_id != identity.object_id
        ):
            raise StateError(
                "Lifecycle shadow session start disagrees with StateManager: "
                f"object={identity.object_id}, logon={identity.logon_id}, "
                f"started={identity.started_at.isoformat()}, "
                f"state_object={current.object_id if current is not None else '<missing>'}, "
                "registry_object="
                f"{resolved.identity.object_id if resolved is not None else '<missing>'}"
            )

    def _assert_session_close_parity(
        self,
        identity: SessionIdentity,
        event: CanonicalOccurrence,
    ) -> None:
        close_at = ensure_utc(event.timestamp)
        snapshot = self._registry.get_session(identity.object_id)
        if (
            self._state_manager.get_session(identity.logon_id) is not None
            or self._state_manager.get_session_at(identity.logon_id, close_at) is not None
            or snapshot is None
            or snapshot.closed_at != close_at
        ):
            raise StateError(
                f"Lifecycle shadow session close disagrees with StateManager: {identity.object_id}"
            )
