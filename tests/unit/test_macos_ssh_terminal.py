# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact Mac SSH process teardown binds native session/transport roles."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverProcesses,
    MacosSshReceiverStartup,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_macos_audit_sessions import _START
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _request
from tests.unit.test_process_exit_projection import _prepare


def _started(
    tmp_path: Path, collected: bool = True
) -> tuple[StateManager, EventDispatcher, EcarEmitter, HostContext, MacosSshReceiverProcesses]:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    while startup.result is None:
        startup.advance()
    return state, dispatcher, emitter, host, startup.result


def _close(
    state: StateManager,
    host: HostContext,
    identity: ProcessIdentity,
    at: datetime,
    *,
    root: bool = False,
) -> tuple[ActionCohortMaterializationPlan, OccurrenceBuilder, str]:
    session = state.get_session_identity(identity.logon_id)
    builder = state.begin_action_cohort_materialization()
    builder.patch_session_activity(session, at)
    builder.terminate_process(identity, end_time=at)
    event = process_exit_occurrence(
        host=host,
        process=identity,
        timestamp=at,
        integrity_level="System" if identity.principal == "root" else "Medium",
    )
    event.auth = AuthContext(
        username=identity.principal,
        logon_id=identity.logon_id,
        session_id=session.session_id,
        logon_type=10,
    )
    event.identity_plan = EventIdentityPlan(subject=identity, session=session)
    suffix = "receiver-terminate" if root else f"receiver-descendant:{identity.object_id}"
    return builder.seal(), event, f"ssh-close:synthetic:{suffix}"


@pytest.mark.parametrize("collected", [False, True])
def test_mac_terminal_closes_executed_children_then_privileged_receiver(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, host, roles = _started(tmp_path, collected)
    identities = (roles.shell, roles.authenticated_child, roles.privileged_receiver)
    for index, identity in enumerate(identities):
        plan, event, root = _close(
            state,
            host,
            identity,
            _START + timedelta(minutes=6, seconds=index),
            root=index == 2,
        )
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(dispatcher, plan, event, exact=True, root=root)
        )
        assert state.get_process(identity.hostname, identity.pid) is None
    assert state.get_session(roles.shell.logon_id) is not None
    emitter.close()


@pytest.mark.parametrize("damage", ["role", "platform", "sid", "session", "audit", "protocol"])
def test_mac_terminal_rejects_changed_platform_and_receiver_ownership(
    tmp_path: Path, damage: str
) -> None:
    state, dispatcher, emitter, host, roles = _started(tmp_path)
    plan, event, root = _close(state, host, roles.shell, _START + timedelta(minutes=6))
    if damage == "role":
        root = "ssh-close:synthetic:receiver-terminate"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    elif damage == "sid":
        event.auth.user_sid = "S-1-5-21-123"
    elif damage == "session":
        event.auth.logon_id = "foreign"
    elif damage == "audit":
        state.get_session(roles.shell.logon_id).audit_origin = None
    else:
        state.get_session(roles.shell.logon_id).auth_protocol = "local"
    with pytest.raises(EventContractError):
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(dispatcher, plan, event, exact=True, root=root)
        )
    assert state.get_process_identity(roles.shell.hostname, roles.shell.pid) == roles.shell
    emitter.close()


@pytest.mark.parametrize("target", [0, 2])
def test_mac_terminal_recovers_lost_output_after_process_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: int
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, host, roles = _started(tmp_path)
    identities = (roles.shell, roles.authenticated_child, roles.privileged_receiver)
    for index, identity in enumerate(identities[:target]):
        plan, event, root = _close(
            state, host, identity, _START + timedelta(minutes=6, seconds=index)
        )
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(dispatcher, plan, event, exact=True, root=root)
        )
    identity = identities[target]
    plan, event, root = _close(
        state, host, identity, _START + timedelta(minutes=6, seconds=target), root=target == 2
    )
    original = ExternalSortedLineWriter._commit_exact_row
    failed = False

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal failed
        original(writer, *args)
        if not failed:
            failed = True
            raise RuntimeError("injected terminal lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    batch = _prepare(dispatcher, plan, event, exact=True, root=root)
    with pytest.raises(RuntimeError, match="terminal lost return"):
        with dispatcher.claimed_action_cohort(batch) as capability:
            capability.commit_no_fail()
    assert capability.committed
    assert state.get_process(identity.hostname, identity.pid) is None
    version = state.materialization_version
    dispatcher.resume_action_cohort_projection(capability.receipt)
    assert state.materialization_version == version
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert (
        len(
            [
                row
                for row in rows
                if row["action"] == "TERMINATE" and row["objectID"] == identity.object_id
            ]
        )
        == 1
    )
