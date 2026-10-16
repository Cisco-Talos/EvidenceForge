# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical POSIX image replacement occurrences for State-owned cohorts."""

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.process import process_exec_identities


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
    event = OccurrenceBuilder(
        timestamp=after.execution_started_at,
        event_type="process_exec",
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
    process_exec_identities(event)
    return event
