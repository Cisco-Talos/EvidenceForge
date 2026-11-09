# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac canonical SSH logout has exact State ownership and no invented PAM evidence."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import SyslogContext
from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.actions.ssh_session_events import ssh_logout_occurrence
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_audit_sessions import _START
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _request
from tests.unit.test_process_exit_projection import _prepare


def _ready_logout(tmp_path: Path, collected: bool = True) -> tuple:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    while startup.result is None:
        startup.advance()
    session = state.get_session_identity(receiver.logon_id)
    roles = startup.result
    close = _START + timedelta(minutes=5)
    for index, process in enumerate(
        (roles.shell, roles.authenticated_child, roles.privileged_receiver), 1
    ):
        at = close + timedelta(seconds=index)
        builder = state.begin_action_cohort_materialization()
        builder.terminate_process(process, end_time=at)
        event = process_exit_occurrence(
            host=host,
            process=process,
            timestamp=at,
            integrity_level="System" if process.principal == "root" else "Medium",
        )
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(
                dispatcher,
                builder.seal(),
                event,
                exact=True,
                root=f"process-exit:{process.object_id}",
            )
        )
    event = ssh_logout_occurrence(
        host=host,
        session=session,
        timestamp=close + timedelta(seconds=4),
        source_ip="192.0.2.10",
        source_port=50222,
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminalize_session(session, end_time=event.timestamp)
    return state, dispatcher, emitter, builder.seal(), event


@pytest.mark.parametrize("collected", [False, True])
def test_mac_ssh_logout_closes_exact_session_without_linux_native_context(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, plan, event = _ready_logout(tmp_path, collected)
    identity = event.identity_plan.subject
    assert event.syslog is None
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(dispatcher, plan, event, exact=True, root=f"ssh-close:{identity.object_id}:logout")
    )
    assert state.get_session(identity.logon_id) is None
    assert state.get_session_identity(identity.logon_id) == identity
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_session(identity.logon_id) is None
    assert restored.get_session_identity(identity.logon_id) == identity
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    logout = [row for row in rows if row["action"] == "LOGOUT"]
    assert len(logout) == int(collected)
    if collected:
        assert logout[0]["objectID"] == identity.object_id
        assert logout[0]["object"] == "USER_SESSION"


@pytest.mark.parametrize(
    "damage", ["pam", "namespace", "linux_host", "protocol", "audit", "host", "time", "root"]
)
def test_mac_logout_rejects_foreign_platform_or_session_facts_before_state_close(
    tmp_path: Path, damage: str
) -> None:
    state, dispatcher, emitter, plan, event = _ready_logout(tmp_path, False)
    identity = event.identity_plan.subject
    root = f"ssh-close:{identity.object_id}:logout"
    if damage == "pam":
        event.syslog = SyslogContext(app_name="sshd", pid=11, message="invented PAM close")
    elif damage == "linux_host":
        event.dst_host.os_category = "linux"
        event.syslog = SyslogContext(app_name="sshd", pid=11, message="invented PAM close")
    elif damage == "namespace":
        state._pid_os[identity.hostname] = "linux"
    elif damage == "protocol":
        state.get_session(identity.logon_id).auth_protocol = "kerberos"
    elif damage == "audit":
        state.get_session(identity.logon_id).audit_origin = None
    elif damage == "host":
        event.dst_host.hostname = "other-mac"
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    else:
        root = "unowned:logout"
    with pytest.raises((EventContractError, StateError)):
        _prepare(dispatcher, plan, event, exact=True, root=root)
    assert state.get_session(identity.logon_id) is not None
    emitter.close()


def test_mac_logout_recovers_lost_output_after_session_state_has_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, plan, event = _ready_logout(tmp_path)
    identity = event.identity_plan.subject
    original = ExternalSortedLineWriter._commit_exact_row
    failed = False

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal failed
        original(writer, *args)
        if not failed:
            failed = True
            raise RuntimeError("injected logout lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    batch = _prepare(
        dispatcher, plan, event, exact=True, root=f"ssh-close:{identity.object_id}:logout"
    )
    with pytest.raises(RuntimeError, match="logout lost return"):
        with dispatcher.claimed_action_cohort(batch) as capability:
            capability.commit_no_fail()
    assert capability.committed
    assert state.get_session(identity.logon_id) is None
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
    assert len([row for row in rows if row["action"] == "LOGOUT"]) == 1


@pytest.mark.parametrize("damage", ["pam_pid", "platform", "session_kind", "naive_time"])
def test_mac_logout_constructor_rejects_native_or_identity_substitution(
    tmp_path: Path, damage: str
) -> None:
    from dataclasses import replace

    state, _, emitter, _, event = _ready_logout(tmp_path, False)
    identity = event.identity_plan.subject
    host = event.dst_host
    timestamp = event.timestamp
    receiver_pid = None
    if damage == "pam_pid":
        receiver_pid = 200
    elif damage == "platform":
        host = replace(host, os_category="windows")
    elif damage == "session_kind":
        identity = replace(identity, session_kind="interactive")
    else:
        timestamp = timestamp.replace(tzinfo=None)
    with pytest.raises(EventContractError):
        ssh_logout_occurrence(
            host=host,
            session=identity,
            timestamp=timestamp,
            source_ip="192.0.2.10",
            source_port=50222,
            linux_receiver_pid=receiver_pid,
        )
    assert state.get_session(identity.logon_id) is not None
    emitter.close()
