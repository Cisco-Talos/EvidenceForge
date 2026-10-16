# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-independent process image replacement observation contracts."""

from dataclasses import replace
from datetime import datetime
from typing import Protocol

from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity


class _ProcessTransitionOccurrence(Protocol):
    timestamp: datetime
    event_type: str
    identity_plan: EventIdentityPlan | None
    src_host: object | None
    process: object | None
    lifecycle: object | None


def _validate_transition_time(event: _ProcessTransitionOccurrence) -> None:
    if type(event.timestamp) is not datetime or event.timestamp.utcoffset() is None:
        raise ValueError("Process transition requires an aware canonical timestamp")


def process_exec_identities(
    event: _ProcessTransitionOccurrence,
) -> tuple[ProcessIdentity, ProcessIdentity]:
    """Validate and return the pre-exec actor and post-exec subject snapshots.

    This structural check does not authorize mutation. The dispatcher must bind both
    snapshots to the exact authenticated State cohort before publication.
    """
    _validate_transition_time(event)
    plan = event.identity_plan
    if (
        type(plan) is not EventIdentityPlan
        or type(plan.actor) is not ProcessIdentity
        or type(plan.subject) is not ProcessIdentity
        or plan.target is not None
    ):
        raise ValueError("Process exec requires exact before/after process identity roles")
    before, after = plan.actor, plan.subject
    if (
        after.execution_ordinal != before.execution_ordinal + 1
        or after.execution_started_at != event.timestamp
        or after.execution_started_at <= before.execution_started_at
        or after.initial_image != before.initial_image
        or replace(
            after,
            image=before.image,
            command_line=before.command_line,
            execution_ordinal=before.execution_ordinal,
            executed_at=before.executed_at,
            lifetime_image=before.lifetime_image,
            credentials=before.credentials,
            audit_pid_version=before.audit_pid_version,
            primary_thread=before.primary_thread,
        )
        != before
    ):
        raise ValueError("Process exec must advance one execution within the same lifetime")
    if (before.credentials is None) != (after.credentials is None) or (
        before.credentials is not None
        and after.credentials is not None
        and before.credentials.origin != after.credentials.origin
    ):
        raise ValueError("Process exec must preserve known real and audit credentials")
    _validate_process_context(event, after, platforms={"linux", "macos"})
    return before, after


def _validate_process_context(
    event: _ProcessTransitionOccurrence, after: ProcessIdentity, *, platforms: set[str]
) -> None:
    plan = event.identity_plan
    host, process, lifecycle = event.src_host, event.process, event.lifecycle
    if (
        getattr(host, "hostname", None) != after.hostname
        or getattr(host, "os_category", None) not in platforms
        or not after.image.startswith("/")
        or "\0" in after.image
        or not after.command_line
        or "\0" in after.command_line
    ):
        raise ValueError("Process transition requires its exact POSIX host and executable")
    expected = {
        "pid": after.pid,
        "parent_pid": after.parent_pid,
        "image": after.image,
        "command_line": after.command_line,
        "username": after.principal,
        "logon_id": after.logon_id,
        "start_time": after.started_at,
    }
    if any(getattr(process, name, None) != value for name, value in expected.items()):
        raise ValueError("Process transition context disagrees with its resulting identity")
    if (
        getattr(lifecycle, "group_id", None) != after.lifecycle_group_id
        or getattr(lifecycle, "canonical_start", None) != after.started_at
        or getattr(lifecycle, "phase", None) != "dependent"
        or getattr(lifecycle, "parent_group_id", None) != (after.parent_lifecycle_group_id or None)
    ):
        raise ValueError("Process transition must retain its dependent process lifecycle")
    if plan.session is not None and (
        plan.session.hostname != after.hostname or plan.session.logon_id != after.logon_id
    ):
        raise ValueError("Process transition session disagrees with process ownership")


def process_credential_identities(
    event: _ProcessTransitionOccurrence,
) -> tuple[ProcessIdentity, ProcessIdentity]:
    """Validate one bounded Mac credential transition without implying native ES output.

    Exact authenticated State patches own authorization, session facts and integrity.
    This contract preserves lifetime, execution, threads and native PID version.
    """
    _validate_transition_time(event)
    plan = event.identity_plan
    if (
        type(plan) is not EventIdentityPlan
        or type(plan.actor) is not ProcessIdentity
        or type(plan.subject) is not ProcessIdentity
        or plan.target is not None
    ):
        raise ValueError("Process credentials require exact before/after process identity roles")
    before, after = plan.actor, plan.subject
    if (
        before.credentials is None
        or after.credentials is None
        or replace(after, principal=before.principal, credentials=before.credentials) != before
        or event.timestamp < before.execution_started_at
        or before.credentials == after.credentials
    ):
        raise ValueError("Process credentials must retain their exact process execution")
    old, new = before.credentials, after.credentials
    if event.event_type == "process_audit_bind":
        if (
            before.principal != after.principal
            or old.real_uid != 0
            or old.effective_uid != 0
            or old.audit_uid not in (None, 2**32 - 1)
            or new.audit_uid is None
            or new.audit_uid == 2**32 - 1
            or new.audit_session_id is None
            or not 100_000 <= new.audit_session_id < 2**32 - 1
            or replace(new, audit_uid=old.audit_uid, audit_session_id=old.audit_session_id) != old
        ):
            raise ValueError("Process audit adoption must preserve privileged POSIX credentials")
    elif event.event_type == "process_privilege_drop":
        if (
            old.real_uid != 0
            or old.effective_uid != 0
            or new.real_uid == 0
            or new.real_uid != new.audit_uid
            or new.real_uid != new.effective_uid
            or new.real_gid != new.effective_gid
            or old.audit_uid != new.audit_uid
            or old.audit_session_id != new.audit_session_id
            or new.audit_uid is None
            or new.audit_session_id is None
            or event.timestamp <= before.started_at
        ):
            raise ValueError("Process privilege drop must retain its authenticated audit origin")
    else:
        raise ValueError("Unsupported process credential transition")
    _validate_process_context(event, after, platforms={"macos"})
    return before, after
