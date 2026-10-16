# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-independent process image replacement observation contracts."""

from dataclasses import replace
from datetime import datetime
from typing import Protocol

from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity


class _ExecutionOccurrence(Protocol):
    timestamp: datetime
    identity_plan: EventIdentityPlan | None
    src_host: object | None
    process: object | None
    lifecycle: object | None


def process_exec_identities(
    event: _ExecutionOccurrence,
) -> tuple[ProcessIdentity, ProcessIdentity]:
    """Validate and return the pre-exec actor and post-exec subject snapshots.

    This structural check does not authorize mutation. The dispatcher must bind both
    snapshots to the exact authenticated State cohort before publication.
    """
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
    host, process, lifecycle = event.src_host, event.process, event.lifecycle
    if (
        getattr(host, "hostname", None) != after.hostname
        or getattr(host, "os_category", None) not in {"linux", "macos"}
        or not after.image.startswith("/")
        or "\0" in after.image
        or not after.command_line
        or "\0" in after.command_line
    ):
        raise ValueError("Process exec requires its exact POSIX host and executable")
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
        raise ValueError("Process exec context disagrees with its post-exec identity")
    if (
        getattr(lifecycle, "group_id", None) != after.lifecycle_group_id
        or getattr(lifecycle, "canonical_start", None) != after.started_at
        or getattr(lifecycle, "phase", None) != "dependent"
        or getattr(lifecycle, "parent_group_id", None) != (after.parent_lifecycle_group_id or None)
    ):
        raise ValueError("Process exec must retain its dependent process lifecycle")
    if plan.session is not None and (
        plan.session.hostname != after.hostname or plan.session.logon_id != after.logon_id
    ):
        raise ValueError("Process exec session disagrees with process ownership")
    return before, after
