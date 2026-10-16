# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""POSIX helper exits retain exact State ownership and recoverable source delivery."""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.process import process_exit_identity
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_process_exec_projection import _START, _environment


def _plan(
    state: StateManager, platform: str = "macos", *, timestamp: datetime | None = None
) -> tuple[ActionCohortMaterializationPlan, OccurrenceBuilder]:
    running = next(iter(state._running_processes.values()))
    identity = state.get_process_identity("HOST-01", running.pid)
    timestamp = timestamp or _START + timedelta(seconds=3)
    event = process_exit_occurrence(
        host=HostContext(
            hostname="HOST-01",
            ip="192.0.2.20",
            os="macOS 26" if platform == "macos" else "Linux",
            os_category=platform,
            system_type="workstation",
        ),
        process=identity,
        timestamp=timestamp,
        integrity_level=running.integrity_level,
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(identity, end_time=timestamp)
    return builder.seal(), event


def _prepare(
    dispatcher: EventDispatcher,
    plan: ActionCohortMaterializationPlan,
    event: OccurrenceBuilder,
    *,
    exact: bool = False,
    duplicate: bool = False,
    root: str | None = None,
) -> PreparedActionCohortBatch:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    root = root or f"process-exit:{event.identity_plan.subject.object_id}"
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    return dispatcher.prepare_action_cohort_batch(
        root,
        plan,
        (dispatch, dispatch) if duplicate else (dispatch,),
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=exact,
    )


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_exit_publishes_current_execution_and_closes_one_lifetime(platform: str) -> None:
    state, dispatcher, emitter = _environment(platform)
    plan, event = _plan(state, platform)
    identity = process_exit_identity(event)
    batch = _prepare(dispatcher, plan, event)
    assert state.get_process_identity(identity.hostname, identity.pid) == identity
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process(identity.hostname, identity.pid) is None
    assert process_exit_identity(emitter.emit.call_args.args[0]) == identity
    assert emitter.emit.call_count == 1


def test_exit_cancellation_keeps_process_live_and_can_replan() -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    identity = process_exit_identity(event)
    assert dispatcher.cancel_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    assert state.get_process_identity(identity.hostname, identity.pid) == identity
    emitter.emit.assert_not_called()
    retry, retried = _plan(state)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, retry, retried))
    assert state.get_process(identity.hostname, identity.pid) is None


@pytest.mark.parametrize("damage", ["image", "actor", "host", "phase", "early", "naive", "auth"])
def test_exit_structural_contract_rejects_changed_facts(damage: str) -> None:
    state, _, _ = _environment()
    _, event = _plan(state)
    if damage == "image":
        event.process.image = "/bin/other"
    elif damage == "actor":
        event.identity_plan = replace(event.identity_plan, actor=event.identity_plan.subject)
    elif damage == "host":
        event.src_host.os_category = "windows"
    elif damage == "phase":
        event.lifecycle = replace(event.lifecycle, phase="dependent")
    elif damage == "early":
        event.timestamp = _START - timedelta(seconds=1)
    elif damage == "naive":
        event.timestamp = event.timestamp.replace(tzinfo=None)
    else:
        event.auth = AuthContext(username="unowned", logon_id="other")
    with pytest.raises(ValueError):
        process_exit_identity(event)


@pytest.mark.parametrize("damage", ["integrity", "platform", "duplicate", "time", "root", "auth"])
def test_exit_projection_rejects_state_or_owner_substitution(damage: str) -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    root = None
    if damage == "integrity":
        event.process.integrity_level = "System"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    elif damage == "root":
        root = "process-exit:other"
    elif damage == "auth":
        event.auth = AuthContext(username="unowned", logon_id="other")
    with pytest.raises((EventContractError, StateError)):
        _prepare(dispatcher, plan, event, exact=True, duplicate=damage == "duplicate", root=root)
    assert len(state._running_processes) == 1
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("exact", [False, True])
def test_exit_without_collection_still_closes_canonical_process(exact: bool) -> None:
    state, dispatcher, emitter = _environment()
    dispatcher.emitters.clear()
    plan, event = _plan(state)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=exact))
    assert not state._running_processes
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("threaded", [False, True])
def test_exit_exact_output_uses_existing_ecar_termination(tmp_path: Path, threaded: bool) -> None:
    from evidenceforge.evaluation.parsers.ecar import EcarParser

    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher.emitters["ecar"] = emitter
    plan, event = _plan(state)
    identity = process_exit_identity(event)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    emitter.close()
    rows = [row for path in tmp_path.rglob("ecar.json") for row in EcarParser().parse_file(path)]
    assert len(rows) == 1 and not rows[0].parse_errors
    assert rows[0].fields["action"] == "TERMINATE"
    assert rows[0].fields["objectID"] == identity.object_id
    assert "exit_code" not in rows[0].fields


def test_exit_lost_sink_return_recovers_without_repeating_state_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_return(
        writer: ExternalSortedLineWriter, key: tuple[str, int, int], digest: str, frozen: object
    ) -> None:
        nonlocal attempts
        attempts += 1
        original(writer, key, digest, frozen)
        if attempts == 1:
            raise RuntimeError("injected exit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    plan, event = _plan(state)
    batch = _prepare(dispatcher, plan, event, exact=True)
    with pytest.raises(RuntimeError, match="exit lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert not state._running_processes
    version = state.materialization_version
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert result.projections[0].status == "succeeded"
    assert state.materialization_version == version
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == 1 and attempts == 2


def test_exit_cannot_close_before_a_lifecycle_hold() -> None:
    state, dispatcher, emitter = _environment()
    process = next(iter(state._running_processes.values()))
    dispatcher._lifecycle_authority.add_process_hold(
        hostname="HOST-01",
        pid=process.pid,
        acquired_at=_START,
        hold_until=_START + timedelta(seconds=10),
        reason="SSH helper still needed",
    )
    with pytest.raises((StateError, EventContractError)):
        plan, event = _plan(state)
        dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    assert state.get_process("HOST-01", process.pid) is not None
    emitter.emit.assert_not_called()


def test_exit_stale_before_exec_identity_cannot_close_new_execution() -> None:
    from tests.unit.test_process_exec_projection import _prepare as prepare_exec

    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    _, after, _, batch = prepare_exec(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    emitter.reset_mock()
    with pytest.raises((StateError, EventContractError)):
        _prepare(dispatcher, plan, event)
    assert state.get_process_identity(after.hostname, after.pid) == after
    emitter.emit.assert_not_called()


def test_exit_rejects_an_unrelated_process_start_in_exact_cohort(tmp_path: Path) -> None:
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    _, event = _plan(state)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(event.identity_plan.subject, end_time=event.timestamp)
    builder.plan_process(
        system="HOST-01",
        parent_pid=0,
        image="/bin/other",
        command_line="other",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=event.timestamp,
    )
    with pytest.raises(EventContractError, match="cover every exact State start"):
        _prepare(dispatcher, builder.seal(), event, exact=True)
    assert len(state._running_processes) == 1
    emitter.close()


def test_exact_exit_after_fork_exec_preserves_parent_and_checkpoint_history(tmp_path: Path) -> None:
    from evidenceforge.generation.actions.posix_process import process_exec_occurrence
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from tests.unit.test_process_fork_projection import _plan as plan_fork
    from tests.unit.test_process_fork_projection import _prepare as prepare_fork

    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    fork_plan, fork_event = plan_fork(state)
    parent, child = fork_event.identity_plan.actor, fork_event.identity_plan.subject
    dispatcher.publish_prepared_action_cohort_batch(
        prepare_fork(dispatcher, fork_plan, fork_event, exact=True)
    )
    builder = state.begin_action_cohort_materialization()
    executed = builder.execute_process(
        child,
        image="/usr/bin/true",
        command_line="/usr/bin/true",
        executed_at=child.started_at + timedelta(microseconds=1),
    )
    execution = process_exec_occurrence(
        host=fork_event.src_host,
        before=child,
        after=executed,
        integrity_level="Medium",
    )
    # Shared source preparation uses the existing execution owner key.
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher,
            builder.seal(),
            execution,
            exact=True,
            root=f"process-exec:{executed.execution_id}",
        )
    )
    close_at = executed.execution_started_at + timedelta(microseconds=1)
    event = process_exit_occurrence(
        host=fork_event.src_host,
        process=executed,
        timestamp=close_at,
        integrity_level="Medium",
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(executed, end_time=close_at)
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(dispatcher, builder.seal(), event, exact=True)
    )
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert [row["action"] for row in rows] == ["CREATE", "MODIFY", "TERMINATE"]
    assert len({row["objectID"] for row in rows}) == 1
    assert [row["timestamp_ms"] for row in rows] == sorted(row["timestamp_ms"] for row in rows)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for manager in (state, restored):
        assert manager.get_process_identity(parent.hostname, parent.pid) == parent
        assert manager.get_process(child.hostname, child.pid) is None
        assert (
            manager.get_process_identity_by_object_id(child.object_id, event_time=child.started_at)
            == child
        )
        assert (
            manager.get_process_identity_by_object_id(
                child.object_id, event_time=executed.execution_started_at
            )
            == executed
        )
        assert (
            manager.get_process_identity_by_object_id(child.object_id, event_time=close_at) is None
        )
