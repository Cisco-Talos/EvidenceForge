# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Mac receiver roles compose before native/transport admission is enabled."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_exec_occurrence,
    process_exit_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from tests.unit.test_macos_audit_sessions import _START, _commit
from tests.unit.test_macos_service_drop import _account
from tests.unit.test_process_exit_projection import _prepare


def _catalog_image(application: str) -> tuple[str, str]:
    platform = application_descriptor(application)["platforms"]["macos"]
    return platform["image_path"], platform["command_templates"][0]


def _bootstrap(
    tmp_path: Path, collected: bool = True
) -> tuple[StateManager, EventDispatcher, EcarEmitter, HostContext, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    launchd = state.plan_process_materialization(
        system="MAC-A",
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START - timedelta(minutes=1),
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    state.materialize_process(launchd)
    bootstrap = state.begin_materialization_batch()
    session = bootstrap.plan_session(
        username="casey",
        system="MAC-A",
        logon_type=10,
        source_ip="192.0.2.10",
        session_kind="ssh",
        auth_protocol="ssh",
        start_time=_START,
        source_ready_time=_START + timedelta(seconds=12),
        network_close_time=_START + timedelta(minutes=5),
        effective_uid=501,
        effective_gid=20,
    )
    session = bootstrap.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=_START + timedelta(seconds=7)
    )
    image, command = _catalog_image("macos-sshd-keygen-wrapper")
    receiver = bootstrap.plan_process(
        system="MAC-A",
        parent_pid=launchd.identity.pid,
        image=image,
        command_line=command,
        username="root",
        integrity_level="System",
        os_category="macos",
        logon_id=session.identity.logon_id,
        session_plan=session,
        require_session=True,
        start_time=_START,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    bootstrap.bind_session_processes(
        session, transport_plan=receiver, process_tree_root_plan=receiver
    )
    _commit(state, bootstrap)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=True)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    host = HostContext(
        hostname="MAC-A",
        ip="192.0.2.20",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    return state, dispatcher, emitter, host, receiver.identity


@pytest.mark.parametrize("collected", [False, True])
def test_successful_receiver_process_graph_preserves_distinct_privilege_and_execution_owners(
    tmp_path: Path, collected: bool
) -> None:
    from evidenceforge.evaluation.parsers.ecar import EcarParser

    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    observations: list[OccurrenceBuilder] = []

    def publish(plan: ActionCohortMaterializationPlan, event: OccurrenceBuilder) -> None:
        subject = event.identity_plan.subject
        if event.event_type == "process_fork":
            root = f"process-fork:{subject.object_id}"
        elif event.event_type == "process_exec":
            root = f"process-exec:{subject.execution_id}"
        elif event.event_type == "process_terminate":
            root = f"process-exit:{subject.object_id}"
        else:
            root = f"{event.event_type}:{subject.execution_id}"
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(dispatcher, plan, event, exact=True, root=root)
        )
        observations.append(event)

    def execute(before: ProcessIdentity, application: str, second: int) -> ProcessIdentity:
        image, command = _catalog_image(application)
        builder = state.begin_action_cohort_materialization()
        after = builder.execute_process(
            before,
            image=image,
            command_line=command,
            executed_at=_START + timedelta(seconds=second),
        )
        publish(
            builder.seal(),
            process_exec_occurrence(
                host=host,
                before=before,
                after=after,
                integrity_level="System" if after.principal == "root" else "Medium",
            ),
        )
        return after

    def fork(parent: ProcessIdentity, second: int) -> ProcessIdentity:
        builder = state.begin_action_cohort_materialization()
        child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=second))
        publish(
            builder.seal(),
            process_fork_occurrence(
                host=host,
                parent=parent,
                child=child.identity,
                integrity_level="System" if parent.principal == "root" else "Medium",
            ),
        )
        return child.identity

    privileged = execute(receiver, "macos-sshd", 1)
    privileged = execute(privileged, "macos-sshd-session", 2)
    preauth = fork(privileged, 3)
    preauth = execute(preauth, "macos-sshd-auth", 4)
    builder = state.begin_action_cohort_materialization()
    dropped = builder.drop_macos_service_child_privileges(
        preauth, service_account=_account(), dropped_at=_START + timedelta(seconds=5)
    )
    publish(
        builder.seal(),
        process_credential_occurrence(
            host=host,
            before=preauth,
            after=dropped,
            timestamp=_START + timedelta(seconds=5),
            kind="process_service_drop",
            integrity_level="Medium",
        ),
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(dropped, end_time=_START + timedelta(seconds=6))
    publish(
        builder.seal(),
        process_exit_occurrence(
            host=host,
            process=dropped,
            timestamp=_START + timedelta(seconds=6),
            integrity_level="Medium",
        ),
    )
    assert state.get_process("MAC-A", dropped.pid) is None
    builder = state.begin_action_cohort_materialization()
    adopted = builder.bind_macos_process_audit_origin(
        privileged, bound_at=_START + timedelta(seconds=7)
    )
    publish(
        builder.seal(),
        process_credential_occurrence(
            host=host,
            before=privileged,
            after=adopted,
            timestamp=_START + timedelta(seconds=7),
            kind="process_audit_bind",
            integrity_level="System",
        ),
    )
    postauth = fork(adopted, 8)
    builder = state.begin_action_cohort_materialization()
    user_child = builder.drop_macos_ssh_child_privileges(
        postauth, dropped_at=_START + timedelta(seconds=9)
    )
    publish(
        builder.seal(),
        process_credential_occurrence(
            host=host,
            before=postauth,
            after=user_child,
            timestamp=_START + timedelta(seconds=9),
            kind="process_privilege_drop",
            integrity_level="Medium",
        ),
    )
    shell_child = fork(user_child, 10)
    builder = state.begin_action_cohort_materialization()
    shell = builder.execute_process(
        shell_child,
        image="/bin/zsh",
        command_line="-zsh",
        executed_at=_START + timedelta(seconds=11),
    )
    publish(
        builder.seal(),
        process_exec_occurrence(
            host=host,
            before=shell_child,
            after=shell,
            integrity_level="Medium",
        ),
    )
    emitter.close()
    assert receiver.object_id == adopted.object_id
    assert adopted.execution_ordinal == 2
    assert adopted.credentials == PosixProcessCredentials(0, 0, 0, 0, 501, 100_000)
    assert (
        user_child.credentials
        == shell.credentials
        == PosixProcessCredentials(501, 501, 20, 20, 501, 100_000)
    )
    assert dropped.credentials == PosixProcessCredentials(75, 75, 75, 75)
    assert len({identity.object_id for identity in (adopted, dropped, user_child, shell)}) == 4
    assert shell.parent_pid == user_child.pid and user_child.parent_pid == adopted.pid
    assert all(row.src_host.os_category == "macos" and row.syslog is None for row in observations)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for manager in (state, restored):
        for live in (adopted, user_child, shell):
            assert manager.get_process_identity("MAC-A", live.pid) == live
        assert (
            manager.get_process_identity_by_object_id(
                dropped.object_id, event_time=_START + timedelta(seconds=5)
            )
            == dropped
        )
        assert (
            manager.get_process_identity_by_object_id(
                dropped.object_id, event_time=_START + timedelta(seconds=6)
            )
            is None
        )
    rows = [row for path in tmp_path.rglob("ecar.json") for row in EcarParser().parse_file(path)]
    assert len(rows) == (11 if collected else 0)
    assert all(not row.parse_errors for row in rows)
