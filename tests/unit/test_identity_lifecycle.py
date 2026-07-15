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

"""Tests for upstream identity-role and lifecycle planning."""

from datetime import UTC, datetime, timedelta

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    FileContext,
    HostContext,
    NetworkContext,
    ProcessAccessContext,
    ProcessContext,
    RemoteThreadContext,
)
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.generation.identity_lifecycle import IdentityLifecyclePlanner
from evidenceforge.generation.state_manager import StateManager


def _host() -> HostContext:
    return HostContext(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
    )


def _process_context(pid: int, parent_pid: int, logon_id: str) -> ProcessContext:
    return ProcessContext(
        pid=pid,
        parent_pid=parent_pid,
        image=rf"C:\Windows\System32\process-{pid}.exe",
        command_line=f"process-{pid}.exe",
        username="analyst",
        logon_id=logon_id,
    )


def _identity_state() -> tuple[StateManager, IdentityLifecyclePlanner, str, int, int]:
    start = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    logon_id = state.create_session(
        "analyst",
        "WS-01",
        2,
        "-",
        lifecycle_group_id="session-group",
    )
    parent_pid = state.create_process(
        "WS-01",
        0,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        "analyst",
        "Medium",
        logon_id,
        lifecycle_group_id="parent-process-group",
    )
    state.set_current_time(start + timedelta(seconds=1))
    child_pid = state.create_process(
        "WS-01",
        parent_pid,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        "analyst",
        "Medium",
        logon_id,
        lifecycle_group_id="child-process-group",
    )
    return state, IdentityLifecyclePlanner(state), logon_id, parent_pid, child_pid


def test_process_create_and_terminate_share_identity_and_primary_thread() -> None:
    state, planner, logon_id, parent_pid, child_pid = _identity_state()
    child = state.get_process_identity("WS-01", child_pid)
    assert child is not None
    create = SecurityEvent(
        timestamp=child.started_at,
        event_type="process_create",
        src_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id),
        process=_process_context(child_pid, parent_pid, logon_id),
        edr=EdrContext(),
    )
    planner.plan(create)

    assert create.identity_plan is not None
    assert create.identity_plan.subject == child
    assert isinstance(create.identity_plan.actor, ProcessIdentity)
    assert create.identity_plan.actor.pid == parent_pid
    assert isinstance(create.identity_plan.session, SessionIdentity)
    assert create.lifecycle is not None
    assert create.lifecycle.group_id == "child-process-group"
    assert create.lifecycle.parent_group_id == "session-group"
    assert create.lifecycle.phase == "start"
    assert child.primary_thread is not None
    assert create.edr is not None
    assert create.edr.tid == child.primary_thread.tid

    terminate = SecurityEvent(
        timestamp=child.started_at + timedelta(seconds=10),
        event_type="process_terminate",
        src_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id),
        process=_process_context(child_pid, parent_pid, logon_id),
        edr=EdrContext(),
    )
    planner.plan(terminate)
    assert terminate.identity_plan is not None
    assert terminate.identity_plan.subject == child
    assert terminate.lifecycle is not None
    assert terminate.lifecycle.group_id == create.lifecycle.group_id
    assert terminate.lifecycle.phase == "closure"
    assert terminate.edr is not None
    assert terminate.edr.tid == create.edr.tid


def test_system_process_create_uses_canonical_process_and_primary_thread() -> None:
    state, planner, logon_id, parent_pid, child_pid = _identity_state()
    child = state.get_process_identity("WS-01", child_pid)
    assert child is not None
    assert child.primary_thread is not None
    event = SecurityEvent(
        timestamp=child.started_at,
        event_type="system_process_create",
        src_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id),
        process=_process_context(child_pid, parent_pid, logon_id),
        edr=EdrContext(),
    )

    planner.plan(event)

    assert event.identity_plan is not None
    assert event.identity_plan.subject == child
    assert isinstance(event.identity_plan.actor, ProcessIdentity)
    assert event.identity_plan.actor.pid == parent_pid
    assert event.edr is not None
    assert event.edr.tid == child.primary_thread.tid
    assert event.lifecycle is not None
    assert event.lifecycle.group_id == "child-process-group"
    assert event.lifecycle.phase == "start"


def test_dependent_process_event_keeps_object_semantics_without_synthesized_tid() -> None:
    state, planner, logon_id, parent_pid, child_pid = _identity_state()
    event = SecurityEvent(
        timestamp=state.get_process("WS-01", child_pid).start_time + timedelta(seconds=2),
        event_type="file_create",
        src_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id),
        process=_process_context(child_pid, parent_pid, logon_id),
        file=FileContext(path=r"C:\Temp\out.txt", action="create"),
        edr=EdrContext(object_id="file-object"),
    )
    planner.plan(event)

    assert event.identity_plan is not None
    assert event.identity_plan.subject is None
    assert isinstance(event.identity_plan.actor, ProcessIdentity)
    assert event.identity_plan.actor.pid == child_pid
    assert event.edr is not None
    assert event.edr.object_id == "file-object"
    assert event.edr.actor_id == event.identity_plan.actor.object_id
    assert event.edr.tid == -1
    assert event.lifecycle is not None
    assert event.lifecycle.phase == "dependent"
    assert event.lifecycle.group_id == "child-process-group"


def test_cross_process_roles_and_registered_remote_thread_are_explicit() -> None:
    state, planner, logon_id, parent_pid, child_pid = _identity_state()
    parent = state.get_process_identity("WS-01", parent_pid)
    child = state.get_process_identity("WS-01", child_pid)
    assert parent is not None
    assert child is not None

    access = SecurityEvent(
        timestamp=child.started_at + timedelta(seconds=2),
        event_type="process_access",
        src_host=_host(),
        process=_process_context(child_pid, parent_pid, logon_id),
        process_access=ProcessAccessContext(
            source_pid=child_pid,
            source_image=child.image,
            target_pid=parent_pid,
            target_image=parent.image,
            target_process_object_id=parent.object_id,
            granted_access="0x1010",
        ),
        edr=EdrContext(object_id=parent.object_id, actor_id=child.object_id),
    )
    planner.plan(access)
    assert access.identity_plan is not None
    assert access.identity_plan.subject == parent
    assert access.identity_plan.actor == child
    assert access.identity_plan.target == parent
    assert access.edr is not None
    assert access.edr.tid == -1

    remote_thread = state.create_thread(
        "WS-01",
        parent.object_id,
        tid=7300,
        kind="remote",
        start_time=access.timestamp,
    )
    remote = SecurityEvent(
        timestamp=access.timestamp,
        event_type="create_remote_thread",
        src_host=_host(),
        process=_process_context(child_pid, parent_pid, logon_id),
        remote_thread=RemoteThreadContext(
            target_pid=parent_pid,
            target_image=parent.image,
            new_thread_id=remote_thread.tid,
            start_address=0x7FF600001000,
            target_process_object_id=parent.object_id,
            thread_object_id=remote_thread.object_id,
        ),
        edr=EdrContext(),
    )
    planner.plan(remote)
    assert remote.identity_plan is not None
    assert isinstance(remote.identity_plan.subject, ThreadIdentity)
    assert remote.identity_plan.subject == remote_thread
    assert remote.identity_plan.actor == child
    assert remote.identity_plan.target == parent


def test_session_start_unlock_child_and_logoff_lifecycle() -> None:
    state, planner, logon_id, _parent_pid, _child_pid = _identity_state()
    session = state.get_session_identity(logon_id)
    assert session is not None
    logon = SecurityEvent(
        timestamp=session.started_at,
        event_type="logon",
        dst_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id, logon_type=2),
        edr=EdrContext(),
    )
    planner.plan(logon)
    assert logon.identity_plan is not None
    assert logon.identity_plan.subject == session
    assert logon.lifecycle is not None
    assert logon.lifecycle.group_id == "session-group"
    assert logon.lifecycle.phase == "start"

    unlock = SecurityEvent(
        timestamp=session.started_at + timedelta(hours=1),
        event_type="logon",
        dst_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id, logon_type=7),
        edr=EdrContext(),
    )
    planner.plan(unlock)
    assert unlock.identity_plan is not None
    assert unlock.identity_plan.subject != session
    assert unlock.identity_plan.actor == session
    assert unlock.lifecycle is not None
    assert unlock.lifecycle.group_id != session.lifecycle_group_id
    assert unlock.lifecycle.parent_group_id == session.lifecycle_group_id

    logoff = SecurityEvent(
        timestamp=session.started_at + timedelta(hours=8),
        event_type="logoff",
        dst_host=_host(),
        auth=AuthContext(username="analyst", logon_id=logon_id, logon_type=2),
        edr=EdrContext(),
    )
    planner.plan(logoff)
    assert logoff.lifecycle is not None
    assert logoff.lifecycle.group_id == logon.lifecycle.group_id
    assert logoff.lifecycle.phase == "closure"


def test_ssh_and_machine_logons_start_their_durable_session_lifecycle() -> None:
    state, planner, logon_id, _parent_pid, _child_pid = _identity_state()
    session = state.get_session_identity(logon_id)
    assert session is not None

    for event_type in ("ssh_session", "machine_logon"):
        start = SecurityEvent(
            timestamp=session.started_at,
            event_type=event_type,
            dst_host=_host(),
            auth=AuthContext(username="analyst", logon_id=logon_id, logon_type=10),
            edr=EdrContext(),
        )
        planner.plan(start)

        assert start.identity_plan is not None
        assert start.identity_plan.subject == session
        assert start.edr is not None
        assert start.edr.object_id == session.object_id
        assert start.lifecycle is not None
        assert start.lifecycle.group_id == session.lifecycle_group_id
        assert start.lifecycle.phase == "start"


def test_flow_actor_is_canonical_or_omitted_as_complete_group() -> None:
    state, planner, _logon_id, _parent_pid, child_pid = _identity_state()
    flow = SecurityEvent(
        timestamp=state.get_process("WS-01", child_pid).start_time + timedelta(seconds=1),
        event_type="connection",
        src_host=_host(),
        network=NetworkContext(
            src_ip="10.0.0.10",
            src_port=51000,
            dst_ip="198.51.100.20",
            dst_port=443,
            protocol="tcp",
            initiating_pid=child_pid,
        ),
    )
    planner.plan(flow)
    assert flow.identity_plan is not None
    assert isinstance(flow.identity_plan.actor, ProcessIdentity)
    assert flow.identity_plan.actor.pid == child_pid

    state.end_process("WS-01", child_pid, flow.timestamp + timedelta(seconds=1))
    stale_flow = SecurityEvent(
        timestamp=flow.timestamp + timedelta(seconds=2),
        event_type="connection",
        src_host=_host(),
        network=NetworkContext(
            src_ip="10.0.0.10",
            src_port=51001,
            dst_ip="198.51.100.20",
            dst_port=443,
            protocol="tcp",
            initiating_pid=child_pid,
        ),
    )
    planner.plan(stale_flow)
    assert stale_flow.identity_plan is None
    assert stale_flow.edr is None
