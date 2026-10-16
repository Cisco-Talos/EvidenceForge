# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical POSIX image replacement occurrences for State-owned cohorts."""

from datetime import datetime
from typing import Literal

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.process import process_credential_identities, process_exec_identities


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


def process_credential_occurrence(
    *,
    host: HostContext,
    before: ProcessIdentity,
    after: ProcessIdentity,
    timestamp: datetime,
    kind: Literal["process_audit_bind", "process_privilege_drop"],
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
