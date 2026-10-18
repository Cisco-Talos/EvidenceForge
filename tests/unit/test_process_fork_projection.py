# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit POSIX fork observations share authenticated State and lifecycle ownership."""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.process import process_fork_identities
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_fork_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_process_exec_projection import _START, _environment


def _plan(
    state: StateManager, platform: str = "macos", *, fork: bool = True, at: datetime | None = None
) -> tuple[ActionCohortMaterializationPlan, OccurrenceBuilder]:
    running = next(iter(state._running_processes.values()))
    parent = state.get_process_identity("HOST-01", running.pid)
    builder = state.begin_action_cohort_materialization()
    at = at or _START + timedelta(seconds=1)
    if fork:
        child = builder.fork_process(parent, forked_at=at)
    else:
        child = builder.plan_process(
            system=parent.hostname,
            parent_pid=parent.pid,
            image=parent.image,
            command_line=parent.command_line,
            username=parent.principal,
            integrity_level="Medium",
            os_category=platform,
            start_time=at,
        )
    event = process_fork_occurrence(
        host=HostContext(
            hostname="HOST-01",
            ip="192.0.2.20",
            os="macOS 26" if platform == "macos" else "Linux",
            os_category=platform,
            system_type="workstation",
        ),
        parent=parent,
        child=child.identity,
        integrity_level="Medium",
    )
    return builder.seal(), event


def _prepare(
    dispatcher: EventDispatcher,
    plan: ActionCohortMaterializationPlan,
    event: OccurrenceBuilder,
    *,
    exact: bool = False,
    duplicate: bool = False,
) -> PreparedActionCohortBatch:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    root = f"process-fork:{event.identity_plan.subject.object_id}"
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
def test_fork_publication_creates_one_inherited_child_and_preserves_parent(platform: str) -> None:
    state, dispatcher, emitter = _environment(platform)
    plan, event = _plan(state, platform)
    parent, child = process_fork_identities(event)
    batch = _prepare(dispatcher, plan, event)
    assert state.get_process("HOST-01", child.pid) is None
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", parent.pid) == parent
    assert state.get_process_identity("HOST-01", child.pid) == child
    assert len(state._running_processes) == 2
    assert process_fork_identities(emitter.emit.call_args.args[0]) == (parent, child)
    assert emitter.emit.call_count == 1


def test_fork_cancel_and_replan_preserve_identity_and_allocator() -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    child = event.identity_plan.subject
    batch = _prepare(dispatcher, plan, event)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert state.get_process("HOST-01", child.pid) is None
    emitter.emit.assert_not_called()
    retry, retried_event = _plan(state)
    assert retried_event.identity_plan.subject == child
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, retry, retried_event))
    assert state.get_process_identity("HOST-01", child.pid) == child


def test_generic_process_start_cannot_substitute_for_explicit_fork() -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state, fork=False)
    with pytest.raises(EventContractError, match="fork provenance"):
        _prepare(dispatcher, plan, event)
    emitter.emit.assert_not_called()
    assert len(state._running_processes) == 1


def test_fork_cannot_be_hidden_in_generic_process_start() -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    event.event_type = "process_create"
    with pytest.raises(EventContractError, match="fork provenance"):
        _prepare(dispatcher, plan, event)
    emitter.emit.assert_not_called()


def test_fork_cannot_use_compatibility_dispatch() -> None:
    state, dispatcher, emitter = _environment()
    _, event = _plan(state)
    with pytest.raises(EventContractError, match="exact State action cohort"):
        dispatcher.dispatch_builder(event)
    emitter.emit.assert_not_called()
    assert len(state._running_processes) == 1


@pytest.mark.parametrize(
    "damage", ["pid", "actor", "image", "credentials", "time", "phase", "host", "parent_image"]
)
def test_fork_contract_rejects_substituted_facts(damage: str) -> None:
    state, _, _ = _environment()
    _, event = _plan(state)
    parent, child = process_fork_identities(event)
    if damage == "pid":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(child, parent_pid=child.pid, parentage=None)
        )
    elif damage == "actor":
        event.identity_plan = replace(event.identity_plan, actor=child)
    elif damage == "image":
        event.process.image = "/bin/other"
    elif damage == "credentials":
        event.identity_plan = replace(event.identity_plan, subject=replace(child, principal="root"))
    elif damage == "time":
        event.timestamp += timedelta(microseconds=1)
    elif damage == "phase":
        event.lifecycle = replace(event.lifecycle, phase="dependent")
    elif damage == "host":
        event.src_host.os_category = "windows"
    else:
        event.process.parent_image = "/bin/other"
    assert not shadow_seal(event).valid


@pytest.mark.parametrize("damage", ["integrity", "platform", "duplicate", "provenance"])
def test_fork_projection_binds_exact_state_start(damage: str) -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    if damage == "integrity":
        event.process.integrity_level = "System"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    elif damage == "provenance":
        start = plan.processes[0]
        object.__setattr__(start, "_payload", replace(start._payload, forked=False))
    with pytest.raises((EventContractError, StateError), match="fork|integrity|repeats|State plan"):
        _prepare(dispatcher, plan, event, duplicate=damage == "duplicate")
    emitter.emit.assert_not_called()
    assert len(state._running_processes) == 1


@pytest.mark.parametrize("exact", [False, True])
def test_fork_with_no_output_still_creates_one_canonical_child(exact: bool) -> None:
    state, dispatcher, emitter = _environment()
    dispatcher.emitters.clear()
    plan, event = _plan(state)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=exact))
    assert len(state._running_processes) == 2
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("threaded", [False, True])
def test_fork_exact_output_preserves_parent_execution_and_new_child(
    tmp_path: Path, threaded: bool
) -> None:
    from evidenceforge.evaluation.parsers.ecar import EcarParser

    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher.emitters["ecar"] = emitter
    plan, event = _plan(state)
    parent, child = process_fork_identities(event)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    emitter.close()
    rows = [row for path in tmp_path.rglob("ecar.json") for row in EcarParser().parse_file(path)]
    assert len(rows) == 1 and not rows[0].parse_errors
    fields = rows[0].fields
    assert fields["action"] == "CREATE"
    assert fields["objectID"] == child.object_id
    assert fields["actorID"] == parent.object_id
    assert fields["operation"] == "fork"
    assert fields["execution_id"] == child.execution_id
    assert fields["parent_execution_id"] == parent.execution_id


def test_fork_exact_sink_lost_return_recovers_without_allocating_another_child(
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
            raise RuntimeError("injected fork lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    plan, event = _plan(state)
    batch = _prepare(dispatcher, plan, event, exact=True)
    with pytest.raises(RuntimeError, match="fork lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert len(state._running_processes) == 2
    version = state.materialization_version
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert result.projections[0].status == "succeeded"
    assert state.materialization_version == version
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1 and attempts == 2
    assert json.loads(rows[0])["properties"]["operation"] == "fork"


def test_fork_rejects_naive_time() -> None:
    state, _, _ = _environment()
    parent = state.get_process_identity(
        "HOST-01", next(iter(state._running_processes.values())).pid
    )
    with pytest.raises(StateError, match="aware datetime"):
        state.begin_action_cohort_materialization().fork_process(
            parent, forked_at=_START.replace(tzinfo=None)
        )


@pytest.mark.parametrize("restore", [False, True])
def test_fork_cannot_render_before_inherited_parent_execution(restore: bool) -> None:
    from evidenceforge.generation.checkpoints.source_timing_head import (
        SourceTimingPlannerParticipant,
    )
    from evidenceforge.generation.source_timing import SourceTimingPlanner, ecar_process_render_key
    from tests.unit.test_process_exec_projection import _prepare as prepare_exec

    state, dispatcher, emitter = _environment()
    _, parent, _, executed = prepare_exec(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(executed)
    planner = dispatcher.source_timing_planner
    exec_time = planner.admission_time(emitter.emit.call_args.args[0], "ecar")
    if restore:
        del executed
        checkpoint = SourceTimingPlannerParticipant(planner).prepare_checkpoint(0)
        planner = SourceTimingPlanner()
        SourceTimingPlannerParticipant(planner).restore_checkpoint(
            checkpoint.head.payload, tuple(segment.payload for segment in checkpoint.segments)
        )
        dispatcher.source_timing_planner = planner
    plan, event = _plan(state, at=parent.execution_started_at + timedelta(microseconds=1))
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    fork = emitter.emit.call_args.args[0]
    assert (
        fork.source_timing.finalized_times[ecar_process_render_key("create", "HOST-01")] > exec_time
    )


def test_fork_birth_provenance_survives_parent_child_planning_in_one_cohort() -> None:
    state, _, _ = _environment()
    parent = state.get_process_identity(
        "HOST-01", next(iter(state._running_processes.values())).pid
    )
    builder = state.begin_action_cohort_materialization()
    fork = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    child = builder.plan_process(
        system=parent.hostname,
        parent_pid=fork.identity.pid,
        image="/bin/other",
        command_line="other",
        username=parent.principal,
        integrity_level="Medium",
        os_category="macos",
        parent_plan=fork,
        start_time=_START + timedelta(seconds=2),
    )
    plan = builder.seal()
    assert plan.processes[0].forked and not plan.processes[1].forked
    state.materialize_action_cohort(plan)
    assert state.get_process_identity("HOST-01", child.identity.pid) == child.identity


def test_internal_fork_is_not_a_new_authored_scenario_event() -> None:
    from pydantic import TypeAdapter, ValidationError

    from evidenceforge.models.scenario import EventSpec

    with pytest.raises(ValidationError):
        TypeAdapter(EventSpec).validate_python({"type": "process_fork", "process_name": "sh"})


def test_fork_exec_and_exit_preserve_distinct_lifetimes_and_checkpoint_history() -> None:
    from evidenceforge.events.identity import EventIdentityPlan
    from evidenceforge.generation.actions.posix_process import process_exec_occurrence
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.source_timing import ecar_process_render_key

    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    parent, child = process_fork_identities(event)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    builder = state.begin_action_cohort_materialization()
    executed = builder.execute_process(
        child,
        image="/usr/bin/true",
        command_line="/usr/bin/true",
        executed_at=child.started_at + timedelta(microseconds=1),
    )
    execution = process_exec_occurrence(
        host=event.src_host,
        before=child,
        after=executed,
        integrity_level="Medium",
    )
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), execution))
    close_at = executed.execution_started_at + timedelta(seconds=1)
    closed = OccurrenceBuilder(
        timestamp=close_at,
        event_type="process_terminate",
        src_host=event.src_host,
        process=execution.process,
        identity_plan=EventIdentityPlan(subject=executed),
        lifecycle=replace(execution.lifecycle, phase="closure"),
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(executed, end_time=close_at)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), closed))
    fork_row, exec_row, exit_row = [call.args[0] for call in emitter.emit.call_args_list]
    assert (
        fork_row.source_timing.finalized_times[ecar_process_render_key("create", "HOST-01")]
        < dispatcher.source_timing_planner.admission_time(exec_row, "ecar")
        < exit_row.source_timing.finalized_times[ecar_process_render_key("terminate", "HOST-01")]
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for manager in (state, restored):
        assert manager.get_process_identity("HOST-01", parent.pid) == parent
        assert manager.get_process("HOST-01", child.pid) is None
        for timestamp, expected in (
            (child.started_at, child),
            (executed.execution_started_at, executed),
            (close_at, None),
        ):
            assert (
                manager.get_process_identity_by_object_id(child.object_id, event_time=timestamp)
                == expected
            )


def test_fork_cannot_publish_after_parent_execution_changes() -> None:
    state, dispatcher, emitter = _environment()
    plan, event = _plan(state)
    parent, child = process_fork_identities(event)
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        parent, image="/bin/zsh", command_line="zsh", executed_at=_START + timedelta(milliseconds=1)
    )
    state.materialize_action_cohort(builder.seal())
    with pytest.raises((StateError, EventContractError), match="stale|version|State|identity"):
        _prepare(dispatcher, plan, event)
    assert state.get_process("HOST-01", child.pid) is None
    emitter.emit.assert_not_called()


def test_fork_rejects_unowned_auth_context_and_invalid_timestamps() -> None:
    from evidenceforge.events.contexts import AuthContext

    state, _, _ = _environment()
    _, event = _plan(state)
    event.auth = AuthContext(username="other", logon_id="unowned")
    assert not shadow_seal(event).valid
    event.auth = None
    for timestamp in (None, "2026-10-15", _START.replace(tzinfo=None)):
        event.timestamp = timestamp
        assert not shadow_seal(event).valid
