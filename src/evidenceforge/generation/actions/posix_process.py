# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical POSIX image replacement occurrences for State-owned cohorts."""

from datetime import datetime
from typing import Literal

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.process import (
    process_credential_identities,
    process_exec_identities,
    process_exit_identity,
    process_fork_identities,
    process_job_control_identities,
)
from evidenceforge.events.process_outcome import PosixProcessExit


def process_exec_occurrence(
    *,
    host: HostContext,
    before: ProcessIdentity,
    after: ProcessIdentity,
    integrity_level: str,
    session: SessionIdentity | None = None,
) -> OccurrenceBuilder:
    """Project exact State exec snapshots without allocating identity or source facts.

    The caller must bind this occurrence to the cohort that owns the snapshots;
    compatibility dispatch cannot publish an exec independently of its mutation.
    """
    event = _process_transition_occurrence(
        host=host,
        before=before,
        after=after,
        integrity_level=integrity_level,
        session=session,
        timestamp=after.execution_started_at,
        kind="process_exec",
    )
    process_exec_identities(event)
    return event


def process_job_control_occurrence(
    *,
    host: HostContext,
    before: ProcessIdentity,
    after: ProcessIdentity,
    timestamp: datetime,
    integrity_level: str,
    session: SessionIdentity | None = None,
    actor: ProcessIdentity | None = None,
) -> OccurrenceBuilder:
    """Project a State-owned membership transition without inventing native ES data."""
    event = _process_transition_occurrence(
        host=host,
        before=before,
        after=after,
        timestamp=timestamp,
        integrity_level=integrity_level,
        session=session,
        kind="process_job_control",
    )
    event.identity_plan = EventIdentityPlan(
        subject=after, actor=before if actor is None else actor, target=before, session=session
    )
    process_job_control_identities(event)
    return event


def process_credential_occurrence(
    *,
    host: HostContext,
    before: ProcessIdentity,
    after: ProcessIdentity,
    timestamp: datetime,
    kind: Literal["process_audit_bind", "process_privilege_drop", "process_service_drop"],
    integrity_level: str,
    session: SessionIdentity | None = None,
) -> OccurrenceBuilder:
    """Project an exact State credential patch without inferring native event families."""
    event = _process_transition_occurrence(
        host=host,
        before=before,
        after=after,
        integrity_level=integrity_level,
        session=session,
        timestamp=timestamp,
        kind=kind,
    )
    process_credential_identities(event)
    return event


def _process_transition_occurrence(
    *,
    host: HostContext,
    before: ProcessIdentity,
    after: ProcessIdentity,
    timestamp: datetime,
    kind: str,
    integrity_level: str,
    session: SessionIdentity | None,
) -> OccurrenceBuilder:
    event = OccurrenceBuilder(
        timestamp=timestamp,
        event_type=kind,
        src_host=host,
        process=ProcessContext(
            pid=after.pid,
            parent_pid=after.parent_pid,
            image=after.image,
            command_line=after.command_line,
            username=after.principal,
            integrity_level=integrity_level,
            logon_id=after.logon_id,
            start_time=after.started_at,
        ),
        identity_plan=EventIdentityPlan(subject=after, actor=before, session=session),
        lifecycle=ActionLifecycleContext(
            group_id=after.lifecycle_group_id,
            canonical_start=after.started_at,
            phase="dependent",
            parent_group_id=after.parent_lifecycle_group_id or None,
        ),
    )
    return event


def process_fork_occurrence(
    *,
    host: HostContext,
    parent: ProcessIdentity,
    child: ProcessIdentity,
    integrity_level: str,
    session: SessionIdentity | None = None,
) -> OccurrenceBuilder:
    """Project a State-planned fork with its immutable parent execution actor."""
    event = OccurrenceBuilder(
        timestamp=child.started_at,
        event_type="process_fork",
        src_host=host,
        process=ProcessContext(
            pid=child.pid,
            parent_pid=parent.pid,
            parent_image=parent.image,
            image=child.image,
            command_line=child.command_line,
            username=child.principal,
            integrity_level=integrity_level,
            logon_id=child.logon_id,
            start_time=child.started_at,
        ),
        identity_plan=EventIdentityPlan(subject=child, actor=parent, session=session),
        lifecycle=ActionLifecycleContext(
            group_id=child.lifecycle_group_id,
            canonical_start=child.started_at,
            phase="start",
            parent_group_id=child.parent_lifecycle_group_id or None,
        ),
    )
    process_fork_identities(event)
    return event


def process_exit_occurrence(
    *,
    host: HostContext,
    process: ProcessIdentity,
    timestamp: datetime,
    integrity_level: str,
    session: SessionIdentity | None = None,
    exit_outcome: PosixProcessExit | None = None,
) -> OccurrenceBuilder:
    """Project a State-owned termination with an optional explicit terminal result."""
    event = OccurrenceBuilder(
        timestamp=timestamp,
        event_type="process_terminate",
        src_host=host,
        process=ProcessContext(
            pid=process.pid,
            parent_pid=process.parent_pid,
            image=process.image,
            command_line=process.command_line,
            username=process.principal,
            integrity_level=integrity_level,
            logon_id=process.logon_id,
            start_time=process.started_at,
            exit_outcome=exit_outcome,
        ),
        identity_plan=EventIdentityPlan(subject=process, session=session),
        lifecycle=ActionLifecycleContext(
            group_id=process.lifecycle_group_id,
            canonical_start=process.started_at,
            phase="closure",
            parent_group_id=process.parent_lifecycle_group_id or None,
        ),
    )
    process_exit_identity(event)
    return event
