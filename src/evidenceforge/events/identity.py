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
from typing import TypeAlias


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

    def __post_init__(self) -> None:
        """Reject incomplete process object identity."""

        if not self.hostname or not self.object_id or not self.lifecycle_group_id:
            raise ValueError("Process identity requires host, object, and lifecycle group")
        if self.pid < 0 or self.parent_pid < 0:
            raise ValueError("Process PIDs must be non-negative host-local identifiers")
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
    parent_lifecycle_group_id: str = ""

    def __post_init__(self) -> None:
        """Reject incomplete session identity."""

        if not self.hostname or not self.object_id or not self.lifecycle_group_id:
            raise ValueError("Session identity requires host, object, and lifecycle group")
        if not self.logon_id:
            raise ValueError("Session identity requires a canonical LogonID")
        if self.session_id < 0:
            raise ValueError("Session ID must be a non-negative host-local identifier")


IdentityObject: TypeAlias = ProcessIdentity | ThreadIdentity | SessionIdentity


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
        """Return the compatibility object identifier for the subject role."""

        return self.subject.object_id if self.subject is not None else ""

    @property
    def actor_id(self) -> str:
        """Return the compatibility actor identifier for the actor role."""

        return self.actor.object_id if self.actor is not None else ""

    @property
    def canonical_tid(self) -> int:
        """Return a TID only when the subject itself is an explicitly modeled thread."""

        if isinstance(self.subject, ThreadIdentity):
            return self.subject.tid
        if isinstance(self.subject, ProcessIdentity) and self.subject.primary_thread is not None:
            return self.subject.primary_thread.tid
        return -1
