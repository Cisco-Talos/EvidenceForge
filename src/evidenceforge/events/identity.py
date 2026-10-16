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

"""Immutable canonical identity plans for evidence-producing occurrences."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

type PosixIdentifier = Annotated[int, Field(strict=True, ge=0, lt=2**32)]

type EntityIdentityKind = Literal[
    "authentication_attempt",
    "authentication_occurrence",
    "file",
    "module",
    "network_flow",
    "registry",
    "service",
]


@dataclass(frozen=True, slots=True)
class EntityIdentity:
    """Immutable identity for a non-process canonical evidence object."""

    object_id: str
    kind: EntityIdentityKind
    hostname: str = ""
    semantic_key: str = ""

    def __post_init__(self) -> None:
        """Reject identity-free entities at the canonical boundary."""

        if not self.object_id:
            raise ValueError("Entity identity requires a non-empty object_id")


@dataclass(frozen=True, slots=True)
class ThreadIdentity:
    """Immutable identity of one explicitly modeled host-native thread."""

    hostname: str
    process_object_id: str
    pid: int
    tid: int
    object_id: str
    started_at: datetime
    kind: str = "worker"

    def __post_init__(self) -> None:
        """Reject incomplete or invalid canonical thread identities."""

        if not self.hostname or not self.process_object_id or not self.object_id:
            raise ValueError("Thread identity requires host, process object, and thread object")
        if self.pid < 0 or self.tid < 0:
            raise ValueError("Thread PID and TID must be non-negative host-local identifiers")

    @property
    def canonical_key(self) -> tuple[str, str, int]:
        """Return the collision-safe durable thread key."""

        return (self.hostname, self.process_object_id, self.tid)


@dataclass(frozen=True, slots=True)
class PosixProcessCredentials:
    """Explicit credential snapshot, independent of login principal and process PID.

    Audit origin may be unknown; absence must not become root or an unset native
    sentinel. Saved IDs and supplementary groups are outside this bounded model.
    """

    real_uid: PosixIdentifier
    effective_uid: PosixIdentifier
    real_gid: PosixIdentifier
    effective_gid: PosixIdentifier
    audit_uid: PosixIdentifier | None = None
    audit_session_id: PosixIdentifier | None = None

    def __post_init__(self) -> None:
        """Reject coerced, negative or out-of-range POSIX identifiers."""

        for value in (self.real_uid, self.effective_uid, self.real_gid, self.effective_gid):
            if type(value) is not int or not 0 <= value < 2**32:
                raise ValueError("POSIX credentials require unsigned 32-bit integer IDs")
        for value in (self.audit_uid, self.audit_session_id):
            if value is not None and (type(value) is not int or not 0 <= value < 2**32):
                raise ValueError("Audit origin requires unsigned 32-bit integer IDs or absence")

    @property
    def origin(self) -> tuple[int, int, int | None, int | None]:
        """Return real and audit identities that an image replacement must retain."""

        return (self.real_uid, self.real_gid, self.audit_uid, self.audit_session_id)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Immutable identity of one host- and process-start-scoped process object."""

    hostname: str
    object_id: str
    pid: int
    parent_pid: int
    image: str
    command_line: str
    principal: str
    logon_id: str
    started_at: datetime
    lifecycle_group_id: str
    parent_lifecycle_group_id: str = ""
    primary_thread: ThreadIdentity | None = None
    execution_ordinal: int = 0
    executed_at: datetime | None = None
    lifetime_image: str = ""
    credentials: PosixProcessCredentials | None = None

    @property
    def initial_image(self) -> str:
        """Return the immutable image that established lifetime ownership."""

        return self.lifetime_image or self.image

    @property
    def execution_id(self) -> str:
        """Identify an image execution without changing its owning process lifetime."""

        return f"{self.object_id}:exec:{self.execution_ordinal}"

    @property
    def execution_started_at(self) -> datetime:
        """Return the start of this image epoch, including the initial execution."""

        return self.executed_at if self.executed_at is not None else self.started_at

    def __post_init__(self) -> None:
        """Reject incomplete process object identity."""

        if not self.hostname or not self.object_id or not self.lifecycle_group_id:
            raise ValueError("Process identity requires host, object, and lifecycle group")
        if self.pid < 0 or self.parent_pid < 0:
            raise ValueError("Process PIDs must be non-negative host-local identifiers")
        if self.credentials is not None and type(self.credentials) is not PosixProcessCredentials:
            raise ValueError("Process credentials require an exact immutable POSIX snapshot")
        if type(self.execution_ordinal) is not int or self.execution_ordinal < 0:
            raise ValueError("Process execution ordinal must be a non-negative integer")
        if self.execution_ordinal == 0 and (
            self.executed_at is not None
            or (self.lifetime_image and self.lifetime_image != self.image)
        ):
            raise ValueError("Initial process execution must retain its lifetime start and image")
        if self.execution_ordinal > 0 and (
            self.executed_at is None
            or self.executed_at <= self.started_at
            or not self.lifetime_image
        ):
            raise ValueError("Replacement process execution must follow the lifetime start")
        if self.primary_thread is not None:
            if self.primary_thread.hostname != self.hostname:
                raise ValueError("Primary thread host must match its owning process")
            if self.primary_thread.process_object_id != self.object_id:
                raise ValueError("Primary thread must reference its owning process object")
            if self.primary_thread.pid != self.pid:
                raise ValueError("Primary thread PID must match its owning process")


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    """Immutable identity of one durable authentication/session object."""

    hostname: str
    object_id: str
    logon_id: str
    session_id: int
    principal: str
    session_kind: str
    started_at: datetime
    lifecycle_group_id: str
    logon_guid: str = ""
    parent_lifecycle_group_id: str = ""

    def __post_init__(self) -> None:
        """Reject incomplete session identity."""

        if not self.hostname or not self.object_id or not self.lifecycle_group_id:
            raise ValueError("Session identity requires host, object, and lifecycle group")
        if not self.logon_id:
            raise ValueError("Session identity requires a canonical LogonID")
        if self.session_id < 0:
            raise ValueError("Session ID must be a non-negative host-local identifier")


type IdentityObject = ProcessIdentity | ThreadIdentity | SessionIdentity | EntityIdentity


@dataclass(frozen=True, slots=True)
class EventIdentityPlan:
    """Frozen subject/actor/target roles for one canonical event.

    ``subject`` is the object whose lifecycle or state the event describes,
    ``actor`` is the identity that performed the action, and ``target`` is the
    identity acted upon. A role is absent when that identity was not explicitly
    modeled; planners and emitters must not synthesize it.
    """

    subject: IdentityObject | None = None
    actor: IdentityObject | None = None
    target: IdentityObject | None = None
    session: SessionIdentity | None = None

    @property
    def object_id(self) -> str:
        """Return the canonical object identifier for the subject role."""

        return self.subject.object_id if self.subject is not None else ""

    @property
    def actor_id(self) -> str:
        """Return the canonical object identifier for the actor role."""

        return self.actor.object_id if self.actor is not None else ""

    @property
    def canonical_tid(self) -> int:
        """Return a TID only when the subject itself is an explicitly modeled thread."""

        if isinstance(self.subject, ThreadIdentity):
            return self.subject.tid
        if isinstance(self.subject, ProcessIdentity) and self.subject.primary_thread is not None:
            return self.subject.primary_thread.tid
        return -1
