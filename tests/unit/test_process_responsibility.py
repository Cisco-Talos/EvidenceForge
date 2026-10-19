# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Responsibility is explicit, lifetime-scoped and independent of ancestry."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_posix_job_control import _START, _close, _fork, _root


def _reference(process: ProcessIdentity) -> ProcessResponsibility:
    return ProcessResponsibility(
        ResponsibleProcessReference(
            process.hostname,
            process.object_id,
            process.pid,
            process.started_at,
        )
    )


def _launch(
    state: StateManager,
    parent: ProcessIdentity,
    *,
    second: int,
    responsibility: ProcessResponsibility | None = None,
    fixed_pid: int | None = None,
    batch: bool = False,
) -> ProcessIdentity:
    builder = state.begin_materialization_batch() if batch else state
    method = builder.plan_process if batch else builder.plan_process_materialization
    plan = method(
        system=parent.hostname,
        parent_pid=parent.pid,
        image="/usr/bin/test-helper",
        command_line="test-helper",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=second),
        credentials=parent.credentials,
        responsibility=responsibility,
        fixed_pid=fixed_pid,
    )
    if batch:
        with state.prepared_materialization_batch(builder.seal()) as prepared:
            prepared.apply_provisional()
            prepared.finalize_no_fail()
    else:
        state.materialize_process(plan)
    return plan.identity


def _exec(state: StateManager, process: ProcessIdentity, second: int) -> ProcessIdentity:
    builder = state.begin_action_cohort_materialization()
    result = builder.execute_process(
        process,
        image="/usr/bin/new-helper",
        command_line="new-helper",
        executed_at=_START + timedelta(seconds=second),
        credentials=replace(process.credentials, effective_uid=501),
    )
    state.materialize_action_cohort(builder.seal())
    return result


@pytest.mark.parametrize("batch", [False, True])
def test_responsibility_tracks_exact_execution_independent_of_parent_and_inherits(
    batch: bool,
) -> None:
    state, parent = _root()
    owner = _launch(state, parent, second=1)
    subject = _launch(state, parent, second=2, responsibility=_reference(owner), batch=batch)
    child = _fork(state, subject, 3)
    at = _START + timedelta(seconds=3)
    captured = state.observe_process_responsibility(child, observed_at=at)
    assert captured.responsible == owner and captured.reason == "active"
    assert captured.responsible.pid != child.parent_pid
    new_owner = _exec(state, owner, 4)
    new_subject = _exec(state, subject, 5)
    assert new_subject.responsibility == child.responsibility == _reference(owner)
    later = state.observe_process_responsibility(child, observed_at=_START + timedelta(seconds=5))
    assert later.responsible == new_owner
    assert captured.responsible == owner and captured.responsible.credentials.effective_uid == 0
    assert later.responsible.credentials.effective_uid == 501
    _close(state, new_owner, 6)
    after_exit = state.observe_process_responsibility(
        child, observed_at=_START + timedelta(seconds=6)
    )
    assert after_exit.reason == "exited" and after_exit.responsible == child
    assert after_exit.responsible_exit_at == _START + timedelta(seconds=6)
    reused = _launch(state, parent, second=7, fixed_pid=owner.pid)
    assert reused.object_id != owner.object_id
    assert (
        state.observe_process_responsibility(
            child, observed_at=_START + timedelta(seconds=8)
        ).responsible
        == child
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.observe_process_responsibility(child, observed_at=at) == captured
    assert (
        restored.observe_process_responsibility(child, observed_at=_START + timedelta(seconds=6))
        == after_exit
    )
    inherited = _fork(restored, child, 9)
    assert inherited.responsibility == child.responsibility
    assert (
        restored.observe_process_responsibility(
            inherited, observed_at=_START + timedelta(seconds=10)
        ).reason
        == "exited"
    )


def test_unknown_absent_and_expired_responsibility_are_distinct() -> None:
    state, root = _root()
    at = _START + timedelta(seconds=1)
    with pytest.raises(StateError, match="unknown"):
        state.observe_process_responsibility(root, observed_at=at)
    absent = _launch(state, root, second=1, responsibility=ProcessResponsibility(None))
    observed = state.observe_process_responsibility(absent, observed_at=at)
    assert observed.responsible == absent and observed.reason == "absent"
    child = _launch(state, root, second=2, responsibility=_reference(absent))
    _close(state, absent, 3)
    state._ended_processes_by_object_id.pop(absent.object_id)
    with pytest.raises(StateError, match="retained lifetime"):
        state.observe_process_responsibility(child, observed_at=_START + timedelta(seconds=4))


@pytest.mark.parametrize("damage", ["unknown_id", "pid", "time", "host", "future", "naive"])
def test_invalid_responsibility_cannot_consume_allocator_state(damage: str) -> None:
    state, root = _root()
    owner = _launch(state, root, second=1)
    fields = dict(
        hostname=owner.hostname,
        object_id=owner.object_id,
        pid=owner.pid,
        started_at=owner.started_at,
    )
    if damage == "unknown_id":
        fields["object_id"] = "missing-lifetime"
    elif damage == "pid":
        fields["pid"] += 100
    elif damage == "time":
        fields["started_at"] -= timedelta(seconds=1)
    elif damage == "host":
        fields["hostname"] = "OTHER-MAC"
    elif damage == "future":
        fields["started_at"] += timedelta(days=1)
    else:
        fields["started_at"] = fields["started_at"].replace(tzinfo=None)
    before = state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        _launch(
            state,
            root,
            second=2,
            responsibility=ProcessResponsibility(ResponsibleProcessReference(**fields)),
        )
    assert state.materialization_digest() == before


def test_reference_to_exited_owner_is_not_a_new_launch_fact() -> None:
    state, root = _root()
    owner = _launch(state, root, second=1)
    _close(state, owner, 2)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="active lifetime"):
        _launch(state, root, second=3, responsibility=_reference(owner))
    assert state.materialization_digest() == before


def test_state_codec_preserves_explicit_absence_and_migrates_unknown_legacy() -> None:
    state, root = _root()
    subject = _launch(state, root, second=1, responsibility=ProcessResponsibility(None))
    assert decode_state_value(encode_state_value(subject)) == subject
    encoded = encode_state_value(subject)
    assert encoded[1] == "process-identity-v12"
    legacy = [*encoded[:2], encoded[2][:21]]
    legacy[1] = "process-identity-v8"
    assert decode_state_value(legacy) == replace(subject, responsibility=None)
    running = state.get_process(subject.hostname, subject.pid)
    encoded = encode_state_value(running)
    assert encoded[1] == "running-process-v17"
    legacy = [*encoded[:2], encoded[2][:37]]
    legacy[1] = "running-process-v13"
    assert decode_state_value(legacy).responsibility is None


@pytest.mark.parametrize("damage", ["reference", "prior", "platform"])
def test_restore_rejects_conflicting_responsibility_before_publishing(damage: str) -> None:
    state, root = _root()
    owner = _launch(state, root, second=1)
    subject = _launch(state, root, second=2, responsibility=_reference(owner))
    subject = _exec(state, subject, 3)
    running = state.get_process(subject.hostname, subject.pid)
    if damage == "reference":
        running.responsibility = ProcessResponsibility(
            replace(subject.responsibility.responsible, pid=owner.pid + 10)
        )
        running.prior_executions = tuple(
            replace(p, responsibility=running.responsibility) for p in running.prior_executions
        )
    elif damage == "prior":
        running.prior_executions = tuple(
            replace(p, responsibility=None) for p in running.prior_executions
        )
    else:
        state._pid_os[root.hostname] = "linux"
    fresh = StateManager()
    before = fresh.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="responsibility"):
        _restore_head(fresh, _capture_head(state))
    assert fresh.materialization_digest() == before


def test_staged_responsible_lifetime_and_rollback_are_owned_by_the_same_batch() -> None:
    state, root = _root()
    before = state.materialization_digest()
    builder = state.begin_materialization_batch()
    owner = builder.plan_process(
        system=root.hostname,
        parent_pid=root.pid,
        image="/usr/bin/owner",
        command_line="owner",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=1),
    )
    subject = builder.plan_process(
        system=root.hostname,
        parent_pid=root.pid,
        image="/usr/bin/subject",
        command_line="subject",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=2),
        responsibility=_reference(owner.identity),
    )
    plan = builder.seal()
    assert state.materialization_digest() == before
    with pytest.raises(RuntimeError, match="abort"):
        with state.prepared_materialization_batch(plan) as prepared:
            prepared.apply_provisional()
            assert (
                state.observe_process_responsibility(
                    subject.identity,
                    observed_at=subject.identity.started_at,
                ).responsible
                == owner.identity
            )
            raise RuntimeError("abort")
    assert state.materialization_digest() == before
    assert state.get_process_identity_by_object_id(subject.identity.object_id) is None


def test_fork_and_exec_projection_preserve_responsibility_through_atomic_dispatch(
    tmp_path: Path,
) -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
    from evidenceforge.generation.actions.posix_process import (
        process_exec_occurrence,
        process_fork_occurrence,
    )
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from tests.unit.test_process_exit_projection import _prepare

    state, root = _root()
    owner = _launch(state, root, second=1)
    subject = _launch(state, root, second=2, responsibility=_reference(owner))
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=True)
    dispatcher = EventDispatcher(
        state, {"ecar": emitter}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    host = HostContext(
        hostname=root.hostname,
        ip="192.0.2.10",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(subject, forked_at=_START + timedelta(seconds=3)).identity
    event = process_fork_occurrence(
        host=host, parent=subject, child=child, integrity_level="System"
    )
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher, builder.seal(), event, exact=True, root=f"process-fork:{child.object_id}"
        )
    )
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        child,
        image="/usr/bin/another",
        command_line="another",
        executed_at=_START + timedelta(seconds=4),
    )
    event = process_exec_occurrence(host=host, before=child, after=after, integrity_level="System")
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher, builder.seal(), event, exact=True, root=f"process-exec:{after.execution_id}"
        )
    )
    assert (
        state.observe_process_responsibility(
            after, observed_at=after.execution_started_at
        ).responsible
        == owner
    )
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert sum(len(p.read_text().splitlines()) for p in tmp_path.rglob("ecar.json")) == 2


@pytest.mark.parametrize("damage", ["stale", "forged", "inactive", "naive"])
def test_observation_rejects_unproven_subject(damage: str) -> None:
    state, parent = _root()
    subject = _launch(state, parent, second=1, responsibility=ProcessResponsibility(None))
    at = _START + timedelta(seconds=3)
    if damage == "stale":
        _exec(state, subject, 2)
    elif damage == "forged":
        subject = replace(subject, image="/usr/bin/forged")
    elif damage == "inactive":
        _close(state, subject, 2)
    else:
        at = at.replace(tzinfo=None)
    with pytest.raises(StateError, match="stale|aware"):
        state.observe_process_responsibility(subject, observed_at=at)


def test_responsibility_observation_rejects_malformed_reason_and_false_fallback() -> None:
    state, parent = _root()
    owner = _launch(state, parent, second=1)
    subject = _launch(state, parent, second=2, responsibility=_reference(owner))
    captured = state.observe_process_responsibility(subject, observed_at=subject.started_at)
    with pytest.raises(ValueError, match="known facts"):
        replace(captured, reason=[])
    with pytest.raises(ValueError, match="explicit absence"):
        replace(captured, responsible=subject, reason="absent")
    with pytest.raises(ValueError, match="explicit exit"):
        replace(captured, responsible=subject, reason="exited")


def test_restore_rejects_cyclic_responsibility_at_equal_birth_times() -> None:
    state, root = _root()
    owner = _launch(state, root, second=1)
    child = _launch(state, root, second=1, responsibility=_reference(owner))
    state.get_process(owner.hostname, owner.pid).responsibility = _reference(child)
    fresh = StateManager()
    before = fresh.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="responsibility"):
        _restore_head(fresh, _capture_head(state))
    assert fresh.materialization_digest() == before


@pytest.mark.parametrize("staged", [False, True])
@pytest.mark.parametrize("birth", [2, 3, 4])
def test_new_responsibility_respects_same_cohort_owner_exit(staged: bool, birth: int) -> None:
    state, root = _root()
    owner = None if staged else _launch(state, root, second=1)
    builder = state.begin_action_cohort_materialization()
    fields = dict(
        system=root.hostname,
        parent_pid=root.pid,
        image="/usr/bin/helper",
        command_line="helper",
        username="root",
        integrity_level="System",
        os_category="macos",
        credentials=root.credentials,
    )
    if staged:
        owner_plan = builder.plan_process(**fields, start_time=_START + timedelta(seconds=1))
        owner = owner_plan.identity
        builder.terminate_process(owner_plan, end_time=_START + timedelta(seconds=3))
    else:
        builder.terminate_process(owner, end_time=_START + timedelta(seconds=3))
    builder.plan_process(
        **fields, start_time=_START + timedelta(seconds=birth), responsibility=_reference(owner)
    )
    before = state.materialization_digest()
    if birth < 3:
        state.materialize_action_cohort(builder.seal())
    else:
        with pytest.raises(StateError, match="responsib"):
            state.materialize_action_cohort(builder.seal())
        assert state.materialization_digest() == before


def test_inheritance_retains_responsibility_after_same_cohort_owner_exit() -> None:
    state, root = _root()
    owner = _launch(state, root, second=1)
    parent = _launch(state, root, second=2, responsibility=_reference(owner))
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(owner, end_time=_START + timedelta(seconds=3))
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=4))
    state.materialize_action_cohort(builder.seal())
    captured = state.observe_process_responsibility(
        child.identity, observed_at=_START + timedelta(seconds=5)
    )
    assert captured.reason == "exited" and captured.responsible == child.identity
