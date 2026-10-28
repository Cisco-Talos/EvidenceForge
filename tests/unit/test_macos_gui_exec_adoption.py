# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented GUI launch transitions preserve exact audit, group and exec ownership."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity, SessionIdentity
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.events.process import process_exec_identities
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.generation.actions.posix_process import process_exec_occurrence
from evidenceforge.generation.checkpoints.state_manager_head import (
    StateManagerParticipant,
    _capture_head,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _commit
from tests.unit.test_process_execution_state import _START

_APP = "/Applications/Invented.app/Contents/MacOS/Invented"
_HOST = HostContext(
    hostname="MAC-GUI",
    ip="192.0.2.41",
    os="macOS 27",
    os_category="macos",
    system_type="workstation",
)


def _setup(
    *,
    image: str = "/usr/libexec/xpcproxy",
    credentials: PosixProcessCredentials | None = None,
    executable_version: ProcessExecutableVersion | None = None,
    image_security: MacosImageSecurity | None = None,
) -> tuple[StateManager, ProcessIdentity, SessionIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    boot = state.plan_process_materialization(
        system=_HOST.hostname,
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START,
        new_posix_session=True,
        macos_terminal="absent",
        responsibility=ProcessResponsibility(None),
        credentials=PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0),
    )
    state.materialize_process(boot)
    batch = state.begin_materialization_batch()
    session = batch.plan_session(
        system=_HOST.hostname,
        username="alex",
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        auth_protocol="local",
        effective_uid=501,
        effective_gid=20,
        session_id=0,
        start_time=_START + timedelta(seconds=1),
    )
    session = batch.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=session.identity.started_at
    )
    _commit(state, batch)
    launch = state.plan_process_materialization(
        system=_HOST.hostname,
        parent_pid=1,
        image=image,
        command_line=image,
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=2),
        logon_id=session.identity.logon_id,
        credentials=credentials or PosixProcessCredentials(501, 501, 20, 20, 2**32 - 1, 0),
        responsibility=ProcessResponsibility(None),
        executable_version=executable_version,
        image_security=image_security,
    )
    state.materialize_process(launch)
    return state, launch.identity, session.identity


def _plan(state: StateManager, before: ProcessIdentity, owner: SessionIdentity) -> tuple:
    batch = state.begin_action_cohort_materialization()
    after = batch.execute_process(
        before,
        image=_APP,
        command_line=_APP,
        arguments=(_APP,),
        executed_at=_START + timedelta(seconds=3),
        macos_gui_session=owner,
    )
    return batch.seal(), after


def test_gui_adoption_is_atomic_preserves_posix_credentials_and_has_no_fork() -> None:
    state, before, owner = _setup()
    digest = state.materialization_digest()
    plan, after = _plan(state, before, owner)
    assert state.materialization_digest() == digest
    assert plan.processes == ()
    assert plan.process_executions[0].gui_session == owner
    origin = state.get_session(owner.logon_id).audit_origin
    assert after.credentials == PosixProcessCredentials(
        501, 501, 20, 20, origin.audit_uid, origin.audit_session_id
    )
    assert after.credentials.origin != before.credentials.origin
    assert before.job_control.pgid == before.job_control.session.sid == 1
    assert after.job_control.session == before.job_control.session
    assert after.job_control.pgid == after.pid
    assert after.parentage == before.parentage
    assert after.responsibility == ProcessResponsibility(None)
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(_HOST.hostname, before.pid) == after
        assert state.get_posix_group_members(after.job_control) == (after,)
        assert all(p.pid != before.pid for p in state.get_posix_group_members(before.job_control))
    assert state.materialization_digest() == digest
    assert before in state.get_posix_group_members(before.job_control)
    assert state.get_posix_group_members(after.job_control) == ()
    result = state.materialize_action_cohort(plan)
    assert result.executed_processes == (after,)
    assert result.started_processes == ()
    assert state.get_posix_group_members(after.job_control) == (after,)


def test_gui_exec_structural_contract_requires_session_and_exact_snapshot_roles() -> None:
    state, before, owner = _setup()
    _, after = _plan(state, before, owner)
    event = process_exec_occurrence(
        host=_HOST, before=before, after=after, integrity_level="Medium", session=owner
    )
    assert process_exec_identities(event) == (before, after)
    with pytest.raises(ValueError, match="same lifetime|preserve known|advance one execution"):
        process_exec_occurrence(host=_HOST, before=before, after=after, integrity_level="Medium")
    with pytest.raises(ValueError, match="advance one execution|parentage"):
        process_exec_occurrence(
            host=_HOST,
            before=before,
            after=replace(after, parent_pid=99),
            integrity_level="Medium",
            session=owner,
        )


def test_gui_checkpoint_retains_preimage_membership_and_can_continue_and_close() -> None:
    state, before, owner = _setup()
    plan, after = _plan(state, before, owner)
    state.materialize_action_cohort(plan)
    restored = StateManager()
    participant = StateManagerParticipant(state)
    checkpoint = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    StateManagerParticipant(restored).restore_checkpoint(
        checkpoint.head.payload, tuple(segment.payload for segment in checkpoint.segments)
    )
    for manager in (state, restored):
        assert (
            manager.get_process_identity_at(_HOST.hostname, before.pid, before.started_at) == before
        )
        assert (
            manager.get_process_identity_at(_HOST.hostname, before.pid, after.executed_at) == after
        )
        assert manager.get_posix_group_members(after.job_control) == (after,)
        batch = manager.begin_action_cohort_materialization()
        next_image = batch.execute_process(
            after,
            image="/usr/bin/id",
            command_line="/usr/bin/id",
            executed_at=_START + timedelta(seconds=4),
        )
        manager.materialize_action_cohort(batch.seal())
        assert next_image.credentials == after.credentials
        assert next_image.job_control == after.job_control
        batch = manager.begin_action_cohort_materialization()
        batch.terminate_process(next_image, end_time=_START + timedelta(seconds=5))
        manager.materialize_action_cohort(batch.seal())
        assert manager.get_posix_group_members(after.job_control) == ()
    # Participant recorder callbacks have distinct process-local identities;
    # authoritative bytes, allocators and continued observations must agree.
    assert _capture_head(state) == _capture_head(restored)
    assert state._used_logon_ids == restored._used_logon_ids
    assert state._logon_id_second_ordinals == restored._logon_id_second_ordinals


@pytest.mark.parametrize("damage", ["no_proof", "image", "owner", "principal", "closed", "uid"])
def test_gui_exception_cannot_rewrite_an_arbitrary_process_or_login(damage: str) -> None:
    state, before, owner = _setup(
        image="/bin/zsh" if damage == "image" else "/usr/libexec/xpcproxy",
        credentials=PosixProcessCredentials(502, 502, 20, 20) if damage == "uid" else None,
    )
    if damage == "owner":
        owner = replace(owner, object_id="invented-foreign-session")
    if damage == "principal":
        owner = replace(owner, principal="someone-else")
    if damage == "closed":
        state.end_session(owner.logon_id, _START + timedelta(seconds=2, milliseconds=500))
    digest = state.materialization_digest()
    batch = state.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="GUI exec|preserve known|session"):
        batch.execute_process(
            before,
            image=_APP,
            command_line=_APP,
            executed_at=_START + timedelta(seconds=3),
            credentials=PosixProcessCredentials(501, 501, 20, 20, 501, 100000)
            if damage == "no_proof"
            else None,
            macos_gui_session=None if damage == "no_proof" else owner,
        )
        batch.seal()
    assert state.materialization_digest() == digest


def test_gui_sealed_plan_cannot_drop_its_session_authority() -> None:
    state, before, owner = _setup()
    plan, _ = _plan(state, before, owner)
    digest = state.materialization_digest()
    forged = replace(plan.process_executions[0], gui_session=None)
    with pytest.raises(StateError, match="integrity|capability|semantic|credentials"):
        state.materialize_action_cohort(replace(plan, _process_executions=(forged,)))
    assert state.materialization_digest() == digest


@pytest.mark.parametrize(
    ("exported", "missing", "fault", "completed"),
    [
        (False, None, False, False),
        (True, None, False, False),
        (True, None, True, False),
        (True, None, False, True),
        (True, "source_version", False, False),
        (True, "source_audit", False, False),
        (True, "environment", False, False),
        (True, "cwd", False, False),
    ],
)
def test_gui_exec_uses_native_v11_publication_without_fabricating_a_fork(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exported: bool,
    missing: str | None,
    fault: bool,
    completed: bool,
) -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.events.es_collector import ESCollectorRegistry
    from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
    from evidenceforge.events.macos_exec_image import MacosExecImage
    from evidenceforge.events.macos_exec_script import MacosExecScript
    from evidenceforge.formats.loader import load_format
    from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
    from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
    from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
    from evidenceforge.generation.emitters.macos_endpoint_security import (
        MacosEndpointSecurityEmitter,
    )
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from evidenceforge.generation.macos_es_source import initialize_macos_es_source
    from tests.unit.test_macos_es_source_profile import _system
    from tests.unit.test_macos_execution_directory import _directory
    from tests.unit.test_macos_launch_file import _manager
    from tests.unit.test_macos_native_sink_publication import _prepare
    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable

    content = _manager()
    records = []
    for ordinal, path in enumerate(("/usr/libexec/xpcproxy", _APP)):
        base = _executable()
        descriptor = replace(
            base,
            hostname=_HOST.hostname,
            principal="alex",
            native_path=path,
            seed_ref=f"invented-gui-image-{ordinal}",
            file_object_id=f"invented-image-{ordinal}",
            source_object_id=f"invented-source-{ordinal}",
            slot=f"invented-gui-slot-{ordinal}",
            macos_file=base.macos_file.model_copy(
                update={"inode": 800 + ordinal, "file_object_id": f"invented-image-{ordinal}"}
            ),
            code_signature=replace(
                base.code_signature,
                entitlements="absent",
                cdhash=("a" if ordinal == 0 else "b") * 40,
            ),
        )
        _publish(content, descriptor, _START + timedelta(seconds=1))
        records.append(content.build_record(descriptor))
    state, before, owner = _setup(
        executable_version=(
            None
            if missing == "source_version"
            else ProcessExecutableVersion.from_binary(records[0].binary)
        ),
        image_security=MacosImageSecurity(7, False, 3),
        credentials=PosixProcessCredentials(501, 501, 20, 20)
        if missing == "source_audit"
        else None,
    )
    state.register_boot_time(_HOST.hostname, _START - timedelta(hours=1))
    table = MacosDescriptorTable(
        _HOST.hostname,
        _START + timedelta(seconds=2, milliseconds=500),
        tuple(
            MacosDescriptorBinding(fd, "file", f"invented-stream-{fd}", False) for fd in range(3)
        ),
        native_last_fd=2,
    )
    batch = state.begin_action_cohort_materialization()
    batch.record_macos_descriptors(before, table=table)
    state.materialize_action_cohort(batch.seal())
    collector_plan = state.plan_process_materialization(
        system=_HOST.hostname,
        parent_pid=1,
        image="/usr/bin/eslogger",
        command_line="/usr/bin/eslogger fork exec exit",
        arguments=("/usr/bin/eslogger", "fork", "exec", "exit"),
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START,
        credentials=PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0),
    )
    state.materialize_process(collector_plan)
    source = initialize_macos_es_source(
        ESCollectionActionOwner(state, ESCollectorRegistry()),
        _system(_HOST.hostname),
        collector_plan.identity,
        known_from=_START + timedelta(seconds=2, milliseconds=750),
        known_until=_START + timedelta(hours=1),
    )
    output = MacosEndpointSecurityEmitter(load_format("macos_endpoint_security"), tmp_path)
    shadow = LifecycleShadow(state, LifecycleRegistry(shard_count=4))
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    dispatcher = EventDispatcher(
        state,
        {"macos_endpoint_security": output} if exported else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.local_artifact_registry = content.registry
    dispatcher.es_collectors = source.owner.collectors
    at = _START + timedelta(seconds=3)
    directory = replace(_directory(path="/"), hostname=_HOST.hostname, observed_at=at)
    batch = state.begin_action_cohort_materialization()
    after = batch.execute_process(
        before,
        image=_APP,
        command_line=_APP,
        arguments=(_APP,),
        environment=None if missing == "environment" else ("LANG=C",),
        executed_at=at,
        macos_gui_session=owner,
        executable_version=ProcessExecutableVersion.from_binary(records[1].binary),
        image_security=MacosImageSecurity(7, False, 3),
        exec_image=MacosExecImage(0, _APP),
        exec_script=MacosExecScript(),
        execution_directory=None if missing == "cwd" else directory,
    )
    cohort = batch.seal()
    event = process_exec_occurrence(
        host=_HOST, before=before, after=after, integrity_level="Medium", session=owner
    )
    try:
        if fault:
            from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

            original = ExternalSortedLineWriter._commit_exact_row
            failed = False

            def fail_after_write(writer: ExternalSortedLineWriter, *args: object) -> object:
                nonlocal failed
                result = original(writer, *args)
                if not failed:
                    failed = True
                    raise RuntimeError("invented GUI native write interruption")
                return result

            with monkeypatch.context() as scoped:
                scoped.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_after_write)
                publication = _prepare(
                    dispatcher, cohort, (event,), root=f"process-exec:{after.execution_id}"
                )
                with pytest.raises(RuntimeError, match="invented GUI native") as caught:
                    dispatcher.publish_prepared_action_cohort_batch(publication)
                digest = state.materialization_digest()
                connection = source.connection()
                dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
                assert state.materialization_digest() == digest
                assert source.connection() == connection
        else:
            publication = _prepare(
                dispatcher, cohort, (event,), root=f"process-exec:{after.execution_id}"
            )
            dispatcher.publish_prepared_action_cohort_batch(publication)
        if completed:
            from evidenceforge.events.process_outcome import PosixProcessExit
            from evidenceforge.generation.actions.posix_process import process_exit_occurrence

            outcome = PosixProcessExit(exit_code=0)
            end = at + timedelta(seconds=2)
            close = state.begin_action_cohort_materialization()
            close.terminate_process(after, end_time=end, exit_outcome=outcome)
            terminal = process_exit_occurrence(
                host=_HOST,
                process=after,
                timestamp=end,
                integrity_level="Medium",
                exit_outcome=outcome,
            )
            publication = _prepare(
                dispatcher, close.seal(), (terminal,), root=f"process-exit:{after.object_id}"
            )
            dispatcher.publish_prepared_action_cohort_batch(publication)
        dispatcher.assert_exact_projection_recoveries_drained()
        assert state.get_process_identity(_HOST.hostname, after.pid) == after
        assert (state.get_process(_HOST.hostname, after.pid) is None) == completed
        assert source.connection().next_delivery == 1 + int(completed)
        assert {
            item.event_type: item.next_sequence for item in source.connection().event_counters
        } == {9: 1, 11: 0, 15: int(completed)}
    finally:
        output.close()
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(exported and missing is None)
    if exported and missing is None:
        rows = paths[0].read_text().splitlines()  # Only this test's invented output.
        assert len(rows) == 1 + int(completed)
        wire = decode_endpoint_security_record(rows[0])
        target = wire.event.exec.target
        assert wire.version == 11 and wire.event_type == 9
        assert wire.process.executable.path == "/usr/libexec/xpcproxy"
        assert target.executable.path == _APP
        assert wire.process.audit_token.asid != target.audit_token.asid
        assert target.audit_token.pid == target.group_id and target.session_id == 1
        assert target.responsible_audit_token == target.audit_token
        assert wire.event.exec.cwd.path == "/"
        assert wire.process.tty is target.tty is None
        if completed:
            end_wire = decode_endpoint_security_record(rows[1])
            assert end_wire.event_type == 15 and end_wire.event.exit.stat == 0
            assert end_wire.process.audit_token == target.audit_token
