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

"""Canonical identity-role and lifecycle planning before source observation."""

from __future__ import annotations

from dataclasses import replace

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import EdrContext
from evidenceforge.events.identity import (
    EventIdentityPlan,
    ProcessIdentity,
    SessionIdentity,
    ThreadIdentity,
)
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import stable_uuid

_PROCESS_START_TYPES = {"process_create", "system_process_create"}
_PROCESS_CLOSURE_TYPES = {"process_terminate"}
_SESSION_START_TYPES = {"logon", "machine_logon", "ssh_session"}
_SESSION_CLOSURE_TYPES = {"logoff"}


class IdentityLifecyclePlanner:
    """Resolve canonical identity roles and lifecycle groups for one event."""

    def __init__(self, state_manager: StateManager) -> None:
        self._state_manager = state_manager

    def plan(self, event: SecurityEvent) -> None:
        """Attach a frozen identity plan and lifecycle metadata in place.

        Planning runs before ``StateManager.apply`` so termination and logoff
        events can still resolve their live durable identities. Missing process
        or thread state remains missing; this layer never invents attribution.
        """

        session = self._session_identity(event)
        process = self._process_identity(event)
        plan = self._plan_roles(event, process=process, session=session)
        if plan is not None:
            event.identity_plan = plan
            self._project_compatibility(event, plan)
        if event.lifecycle is None:
            event.lifecycle = self._plan_lifecycle(
                event,
                process=process,
                session=session,
            )

    def _plan_roles(
        self,
        event: SecurityEvent,
        *,
        process: ProcessIdentity | None,
        session: SessionIdentity | None,
    ) -> EventIdentityPlan | None:
        if event.event_type in _PROCESS_START_TYPES | _PROCESS_CLOSURE_TYPES:
            if process is None:
                return None
            actor = self._state_manager.get_process_identity(
                process.hostname,
                process.parent_pid,
            )
            return EventIdentityPlan(
                subject=process,
                actor=actor if event.event_type in _PROCESS_START_TYPES else None,
                session=session,
            )

        if event.event_type == "process_access":
            target = self._target_process_identity(event)
            if process is None and target is None:
                return None
            return EventIdentityPlan(
                subject=target,
                actor=process,
                target=target,
                session=session,
            )

        if event.event_type == "create_remote_thread":
            target = self._target_process_identity(event)
            thread = self._remote_thread_identity(event, target)
            if process is None and target is None and thread is None:
                return None
            return EventIdentityPlan(
                subject=thread,
                actor=process,
                target=target,
                session=session,
            )

        if event.event_type in _SESSION_START_TYPES | _SESSION_CLOSURE_TYPES:
            if session is None:
                return None
            if (
                event.event_type == "logon"
                and event.auth is not None
                and event.auth.logon_type == 7
            ):
                child_group_id = stable_uuid(
                    "session-reauth-lifecycle",
                    session.object_id,
                    event.timestamp.isoformat(),
                )
                reauth = replace(
                    session,
                    object_id=stable_uuid(
                        "session-reauth",
                        session.object_id,
                        event.timestamp.isoformat(),
                    ),
                    started_at=event.timestamp,
                    lifecycle_group_id=child_group_id,
                    parent_lifecycle_group_id=session.lifecycle_group_id,
                )
                return EventIdentityPlan(subject=reauth, actor=session, session=session)
            return EventIdentityPlan(subject=session, session=session)

        actor = process or self._network_actor_identity(event)
        target = self._network_target_identity(event)
        if actor is not None or target is not None or session is not None:
            return EventIdentityPlan(actor=actor, target=target, session=session)
        return None

    def _plan_lifecycle(
        self,
        event: SecurityEvent,
        *,
        process: ProcessIdentity | None,
        session: SessionIdentity | None,
    ) -> ActionLifecycleContext | None:
        if event.event_type in _SESSION_START_TYPES and session is not None:
            if (
                event.event_type == "logon"
                and event.auth is not None
                and event.auth.logon_type == 7
            ):
                return ActionLifecycleContext(
                    group_id=stable_uuid(
                        "session-reauth-lifecycle",
                        session.object_id,
                        event.timestamp.isoformat(),
                    ),
                    canonical_start=event.timestamp,
                    phase="start",
                    parent_group_id=session.lifecycle_group_id,
                )
            return ActionLifecycleContext(
                group_id=session.lifecycle_group_id,
                canonical_start=session.started_at,
                phase="start",
                parent_group_id=session.parent_lifecycle_group_id or None,
            )
        if event.event_type == "logoff" and session is not None:
            return ActionLifecycleContext(
                group_id=session.lifecycle_group_id,
                canonical_start=session.started_at,
                phase="closure",
                parent_group_id=session.parent_lifecycle_group_id or None,
            )
        if process is not None:
            phase = "dependent"
            if event.event_type in _PROCESS_START_TYPES:
                phase = "start"
            elif event.event_type in _PROCESS_CLOSURE_TYPES:
                phase = "closure"
            return ActionLifecycleContext(
                group_id=process.lifecycle_group_id,
                canonical_start=process.started_at,
                phase=phase,
                parent_group_id=process.parent_lifecycle_group_id or None,
            )
        if session is not None:
            return ActionLifecycleContext(
                group_id=session.lifecycle_group_id,
                canonical_start=session.started_at,
                phase="dependent",
                parent_group_id=session.parent_lifecycle_group_id or None,
            )
        return None

    def _session_identity(self, event: SecurityEvent) -> SessionIdentity | None:
        if event.auth is None or not event.auth.logon_id:
            return None
        return self._state_manager.get_session_identity(event.auth.logon_id)

    def _process_identity(self, event: SecurityEvent) -> ProcessIdentity | None:
        host = event.src_host or event.dst_host
        if host is None:
            return None
        if event.process is not None and event.process.pid >= 0:
            return self._state_manager.get_process_identity(host.hostname, event.process.pid)
        if event.network is not None and event.network.initiating_pid >= 0 and event.src_host:
            return self._state_manager.get_process_identity(
                event.src_host.hostname,
                event.network.initiating_pid,
            )
        return None

    def _network_actor_identity(self, event: SecurityEvent) -> ProcessIdentity | None:
        if event.network is None or event.src_host is None or event.network.initiating_pid < 0:
            return None
        return self._state_manager.get_process_identity(
            event.src_host.hostname,
            event.network.initiating_pid,
        )

    def _network_target_identity(self, event: SecurityEvent) -> ProcessIdentity | None:
        if event.network is None or event.dst_host is None or event.network.responding_pid < 0:
            return None
        return self._state_manager.get_process_identity(
            event.dst_host.hostname,
            event.network.responding_pid,
        )

    def _target_process_identity(self, event: SecurityEvent) -> ProcessIdentity | None:
        host = event.src_host or event.dst_host
        if host is None:
            return None
        object_id = ""
        target_pid = -1
        if event.process_access is not None:
            object_id = event.process_access.target_process_object_id
            target_pid = event.process_access.target_pid
        elif event.remote_thread is not None:
            object_id = event.remote_thread.target_process_object_id
            target_pid = event.remote_thread.target_pid
        if object_id:
            return self._state_manager.get_process_identity_by_object_id(object_id)
        if target_pid >= 0:
            return self._state_manager.get_process_identity(host.hostname, target_pid)
        return None

    def _remote_thread_identity(
        self,
        event: SecurityEvent,
        target: ProcessIdentity | None,
    ) -> ThreadIdentity | None:
        remote = event.remote_thread
        if remote is None or target is None or remote.new_thread_id < 0:
            return None
        return self._state_manager.get_thread(
            target.hostname,
            target.object_id,
            remote.new_thread_id,
        )

    @staticmethod
    def _project_compatibility(event: SecurityEvent, plan: EventIdentityPlan) -> None:
        """Fill legacy eCAR fields from canonical truth and reject contradictions."""

        if event.edr is None:
            event.edr = EdrContext()
        if plan.object_id:
            event.edr.object_id = plan.object_id
        if plan.actor_id:
            event.edr.actor_id = plan.actor_id
        if plan.canonical_tid >= 0 and (
            event.event_type in _PROCESS_START_TYPES | _PROCESS_CLOSURE_TYPES
            or isinstance(plan.subject, ThreadIdentity)
        ):
            event.edr.tid = plan.canonical_tid
        event.edr.validate_identity_plan(plan)
