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

import shlex
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from evidenceforge.events.job_control import PosixGroupIdentity
from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.macos_execution_directory import (
    MacosExecutionDirectory,
    validate_macos_execution_directory,
)
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.events.parentage import ProcessParentage, validate_process_parentage
from evidenceforge.events.process_executable import (
    ProcessExecutableVersion,
)
from evidenceforge.events.responsibility import (
    ProcessResponsibility,
    validate_process_responsibility,
)

type PosixIdentifier = Annotated[int, Field(strict=True, ge=0, lt=2**32)]
type PosixProcessArguments = Annotated[
    tuple[Annotated[str, Field(strict=True)], ...],
    Field(strict=True, min_length=1, max_length=256),
]

type PosixProcessEnvironment = Annotated[
    tuple[Annotated[str, Field(strict=True)], ...],
    Field(strict=True, max_length=256),
]

type EntityIdentityKind = Literal[
    "process_attempt",
    "kernel_writer",
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
class MacosAuditSession:
    """Explicit authenticated audit origin, independent of desktop/session IDs.

    Kernel-assigned IDs occupy a separate namespace above native process IDs.
    This snapshot does not assert native audit-trail collection or logout timing.
    """

    audit_uid: PosixIdentifier
    audit_session_id: PosixIdentifier
    created_at: datetime

    def __post_init__(self) -> None:
        """Reject unknown account sentinels and non-kernel-assigned session IDs."""
        if type(self.audit_uid) is not int or not 0 <= self.audit_uid < 2**32 - 1:
            raise ValueError("Authenticated audit origin requires a known unsigned account ID")
        if (
            type(self.audit_session_id) is not int
            or not 100_000 <= self.audit_session_id < 2**32 - 1
        ):
            raise ValueError("macOS audit session requires a kernel-assigned session ID")
        if type(self.created_at) is not datetime or self.created_at.utcoffset() is None:
            raise ValueError("Audit session creation requires an aware timestamp")


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

    @property
    def has_no_authenticated_audit_origin(self) -> bool:
        """Distinguish legacy unknown or explicit XNU default from an authenticated origin."""
        return (self.audit_uid, self.audit_session_id) in {(None, None), (2**32 - 1, 0)}

    @property
    def is_unattributed_root(self) -> bool:
        """Return whether this is root with legacy unknown or modeled default audit origin."""
        return (self.real_uid, self.effective_uid, self.real_gid, self.effective_gid) == (
            0,
            0,
            0,
            0,
        ) and self.has_no_authenticated_audit_origin


@dataclass(frozen=True, slots=True)
class MacosProcessAuditBinding:
    """One authenticated audit-origin adoption without changing task or POSIX IDs."""

    origin: MacosAuditSession
    before: PosixProcessCredentials
    after: PosixProcessCredentials
    bound_at: datetime

    def __post_init__(self) -> None:
        """Require a privileged receiver and preserve its non-audit credentials."""
        if (
            type(self.origin) is not MacosAuditSession
            or type(self.before) is not PosixProcessCredentials
            or type(self.after) is not PosixProcessCredentials
        ):
            raise ValueError("Process audit binding requires exact immutable identity facts")
        if type(self.bound_at) is not datetime or self.bound_at.utcoffset() is None:
            raise ValueError("Process audit binding requires an aware timestamp")
        if self.bound_at < self.origin.created_at:
            raise ValueError("Process audit binding precedes authentication")
        if self.before.real_uid != 0 or self.before.effective_uid != 0:
            raise ValueError("SSH audit-origin adoption requires a privileged receiver")
        if self.before.audit_uid not in (None, 2**32 - 1):
            raise ValueError("SSH audit-origin adoption cannot replace an authenticated origin")
        if (
            (
                self.after.real_uid,
                self.after.effective_uid,
                self.after.real_gid,
                self.after.effective_gid,
            )
            != (
                self.before.real_uid,
                self.before.effective_uid,
                self.before.real_gid,
                self.before.effective_gid,
            )
            or self.after.audit_uid != self.origin.audit_uid
            or self.after.audit_session_id != self.origin.audit_session_id
        ):
            raise ValueError(
                "Process audit binding must preserve POSIX IDs and use its exact origin"
            )


@dataclass(frozen=True, slots=True)
class MacosProcessPrivilegeDrop:
    """One permanent authenticated SSH child credential transition, without exec."""

    origin: MacosAuditSession
    before: PosixProcessCredentials
    after: PosixProcessCredentials
    before_principal: str
    after_principal: str
    before_integrity: str
    after_integrity: str
    dropped_at: datetime

    def __post_init__(self) -> None:
        """Preserve audit origin while permanently adopting the authenticated user."""
        if (
            type(self.origin) is not MacosAuditSession
            or type(self.before) is not PosixProcessCredentials
            or type(self.after) is not PosixProcessCredentials
        ):
            raise ValueError("SSH privilege drop requires exact immutable credential facts")
        if type(self.dropped_at) is not datetime or self.dropped_at.utcoffset() is None:
            raise ValueError("SSH privilege drop requires an aware timestamp")
        if self.dropped_at < self.origin.created_at:
            raise ValueError("SSH privilege drop precedes authentication")
        if any(
            type(value) is not str or not value
            for value in (
                self.before_principal,
                self.after_principal,
                self.before_integrity,
                self.after_integrity,
            )
        ):
            raise ValueError("SSH privilege drop requires explicit principals and integrity")
        if self.before.real_uid != 0 or self.before.effective_uid != 0:
            raise ValueError("SSH privilege drop requires a privileged child")
        if (
            self.after.real_uid == 0
            or self.after.real_uid != self.after.effective_uid
            or self.after.real_uid != self.origin.audit_uid
            or self.after.real_gid != self.after.effective_gid
            or (self.before.audit_uid, self.before.audit_session_id)
            != (self.origin.audit_uid, self.origin.audit_session_id)
            or (self.after.audit_uid, self.after.audit_session_id)
            != (self.origin.audit_uid, self.origin.audit_session_id)
        ):
            raise ValueError("SSH privilege drop must adopt the user and preserve audit origin")


@dataclass(frozen=True, slots=True)
class MacosProcessServiceDrop:
    """One pre-authentication service-child drop, independent of a login origin."""

    parent_object_id: str
    parent_execution_id: str
    execution_ordinal: int
    before: PosixProcessCredentials
    after: PosixProcessCredentials
    before_principal: str
    after_principal: str
    before_integrity: str
    after_integrity: str
    dropped_at: datetime

    def __post_init__(self) -> None:
        """Require a permanent root-to-service transition with no authenticated audit origin."""
        if (
            type(self.before) is not PosixProcessCredentials
            or type(self.after) is not PosixProcessCredentials
        ):
            raise ValueError("Service privilege drop requires exact credential facts")
        if type(self.execution_ordinal) is not int or self.execution_ordinal < 0:
            raise ValueError("Service privilege drop requires its exact execution ordinal")
        if type(self.dropped_at) is not datetime or self.dropped_at.utcoffset() is None:
            raise ValueError("Service privilege drop requires an aware timestamp")
        if any(
            type(value) is not str or not value
            for value in (
                self.parent_object_id,
                self.parent_execution_id,
                self.before_principal,
                self.after_principal,
                self.before_integrity,
                self.after_integrity,
            )
        ):
            raise ValueError(
                "Service privilege drop requires parent, principal and integrity identities"
            )
        if (
            self.before.real_uid != 0
            or self.before.effective_uid != 0
            or self.after.real_uid == 0
            or self.after.real_uid != self.after.effective_uid
            or self.after.real_gid != self.after.effective_gid
            or not self.before.has_no_authenticated_audit_origin
            or (self.before.audit_uid, self.before.audit_session_id)
            != (self.after.audit_uid, self.after.audit_session_id)
        ):
            raise ValueError(
                "Service privilege drop must adopt a nonroot service without authenticated origin"
            )


def validate_process_arguments(
    arguments: tuple[str, ...] | None, *, command_line: str | None = None
) -> None:
    """Validate a bounded explicit argv; never parse a display command line."""
    if arguments is None:
        return
    if (
        type(arguments) is not tuple
        or not 1 <= len(arguments) <= 256
        or any(type(value) is not str or "\x00" in value for value in arguments)
        or not arguments[0]
        or sum(len(value.encode("utf-8")) + 1 for value in arguments) > 65536
    ):
        raise ValueError("Explicit process argv requires 1–256 NUL-free strings within 64 KiB")
    if command_line is not None and (
        type(command_line) is not str or command_line != shlex.join(arguments)
    ):
        raise ValueError("Explicit POSIX argv requires its canonical shell-quoted display line")


def validate_process_environment(environment: object) -> None:
    """Validate an explicitly supplied ordered envp vector, without expanding values.

    None is unknown; an empty tuple is a known empty environment. Preserve raw
    entries and duplicate names: conversion to a mapping would lose source facts.
    The entry/byte bounds are internal admission budgets, not kernel limits.
    """
    if environment is None:
        return
    if (
        type(environment) is not tuple
        or len(environment) > 256
        or any(type(value) is not str or "\0" in value for value in environment)
        or sum(len(value.encode("utf-8")) + 1 for value in environment) > 65536
    ):
        raise ValueError(
            "Explicit process environment requires up to 256 NUL-free strings within 64 KiB"
        )


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
    audit_pid_version: PosixIdentifier | None = None
    arguments: PosixProcessArguments | None = None
    job_control: PosixGroupIdentity | None = None
    environment: PosixProcessEnvironment | None = None
    parentage: ProcessParentage | None = None
    responsibility: ProcessResponsibility | None = None
    image_security: MacosImageSecurity | None = None
    execution_directory: MacosExecutionDirectory | None = None
    executable_version: ProcessExecutableVersion | None = None
    exec_image: MacosExecImage | None = None
    exec_script: MacosExecScript | None = None

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

        validate_process_responsibility(
            self.responsibility,
            hostname=self.hostname,
            object_id=self.object_id,
            started_at=self.started_at,
        )
        validate_process_arguments(self.arguments, command_line=self.command_line)
        validate_process_environment(self.environment)
        if self.executable_version is not None:
            if type(self.executable_version) is not ProcessExecutableVersion:
                raise ValueError("Process executable version requires its exact immutable type")
            self.executable_version.__post_init__()
        validate_macos_execution_directory(
            self.execution_directory, hostname=self.hostname, observed_at=self.execution_started_at
        )
        if self.exec_script is not None:
            if type(self.exec_script) is not MacosExecScript:
                raise ValueError("Process script requires exact immutable facts")
            self.exec_script.__post_init__()
            if (
                self.exec_script.hostname is not None
                and self.exec_script.hostname.casefold() != self.hostname.casefold()
            ):
                raise ValueError("Process script belongs to another host")
        if (
            self.exec_script is not None
            and self.exec_script.content_id is not None
            and self.executable_version is not None
        ):
            if (
                self.exec_script.content_id == self.executable_version.content_id
                or self.exec_script.artifact_version_id
                == self.executable_version.artifact_version_id
            ):
                raise ValueError(
                    "Execution script and loaded interpreter require distinct file identities"
                )
        if self.exec_image is not None:
            if type(self.exec_image) is not MacosExecImage:
                raise ValueError("Process execution image requires its exact type")
            self.exec_image.__post_init__()
        if self.image_security is not None:
            if type(self.image_security) is not MacosImageSecurity:
                raise ValueError("Process image security requires its exact immutable type")
            self.image_security.__post_init__()
        validate_process_parentage(
            self.parentage,
            hostname=self.hostname,
            object_id=self.object_id,
            parent_pid=self.parent_pid,
            started_at=self.started_at,
        )
        if self.job_control is not None and (
            type(self.job_control) is not PosixGroupIdentity
            or self.job_control.session.hostname != self.hostname
        ):
            raise ValueError("Process job control requires its exact host-scoped group")

        if not self.hostname or not self.object_id or not self.lifecycle_group_id:
            raise ValueError("Process identity requires host, object, and lifecycle group")
        if self.pid < 0 or self.parent_pid < 0:
            raise ValueError("Process PIDs must be non-negative host-local identifiers")
        if self.audit_pid_version is not None and (
            type(self.audit_pid_version) is not int or not 0 < self.audit_pid_version < 2**32
        ):
            raise ValueError("Audit PID version requires a positive unsigned 32-bit integer")
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
