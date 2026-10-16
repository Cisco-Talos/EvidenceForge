# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""POSIX image replacement uses one authenticated lifetime and one dependent row."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.events.process import process_exec_identities
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_exec_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_dispatcher_action_cohort import _ROOT_ACTION_ID, _START, _zero_node_entry


def _environment(platform: str = "macos") -> tuple[StateManager, EventDispatcher, MagicMock]:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process = builder.plan_process(
        system="HOST-01",
        parent_pid=0,
        image="/bin/sh",
        command_line="sh",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        start_time=_START,
    )
    state.materialize_action_cohort(builder.seal())
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state, {"ecar": emitter}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    assert state.get_process_identity("HOST-01", process.identity.pid) == process.identity
    return state, dispatcher, emitter


def _exec_event(
    before: ProcessIdentity, after: ProcessIdentity, platform: str = "macos"
) -> OccurrenceBuilder:
    return process_exec_occurrence(
        host=HostContext(
            hostname=after.hostname,
            ip="192.0.2.20",
            os="macOS 26" if platform == "macos" else "Linux",
            os_category=platform,
            system_type="workstation",
        ),
        before=before,
        after=after,
        integrity_level="Medium",
    )


def _prepare(
    state: StateManager,
    dispatcher: EventDispatcher,
    platform: str = "macos",
    *,
    exact_projection: bool = False,
    delay: timedelta = timedelta(seconds=2),
) -> tuple[ProcessIdentity, ProcessIdentity, OccurrenceBuilder, PreparedActionCohortBatch]:
    before = next(iter(state._running_processes.values()))
    before = state.get_process_identity("HOST-01", before.pid)
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/bin/zsh",
        command_line="zsh -l",
        executed_at=before.execution_started_at + delay,
    )
    plan = builder.seal()
    event = _exec_event(before, after, platform)
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    root = f"process-exec:{after.execution_id}"
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    batch = dispatcher.prepare_action_cohort_batch(
        root,
        plan,
        (dispatch,),
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=exact_projection,
    )
    return before, after, event, batch


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_exec_publication_advances_state_and_registry_without_new_lifetime(platform: str) -> None:
    state, dispatcher, emitter = _environment(platform)
    before, after, _, batch = _prepare(state, dispatcher, platform)
    assert state.get_process_identity("HOST-01", before.pid) == before
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    assert len(state._running_processes) == 1
    event = emitter.emit.call_args.args[0]
    assert process_exec_identities(event) == (before, after)
    assert event.lifecycle.phase == "dependent"
    assert emitter.emit.call_count == 1


def test_exec_cancellation_keeps_original_execution_and_emits_nothing() -> None:
    state, dispatcher, emitter = _environment()
    before, _, _, batch = _prepare(state, dispatcher)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == before
    emitter.emit.assert_not_called()
    _, after, _, retry = _prepare(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(retry)
    assert state.get_process_identity("HOST-01", before.pid) == after


def test_exec_cannot_use_compatibility_dispatch() -> None:
    state, dispatcher, _ = _environment()
    _, _, event, batch = _prepare(state, dispatcher)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    with pytest.raises(EventContractError, match="exact State action cohort"):
        dispatcher.dispatch_builder(event)


@pytest.mark.parametrize(
    "damage", ["pid", "principal", "ordinal", "time", "context", "host", "lifecycle", "actor"]
)
def test_exec_contract_rejects_mismatched_source_facts(damage: str) -> None:
    state, dispatcher, _ = _environment()
    before, after, event, batch = _prepare(state, dispatcher)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    if damage == "pid":
        event.identity_plan = replace(event.identity_plan, subject=replace(after, parent_pid=88))
    elif damage == "principal":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(after, principal="other")
        )
    elif damage == "ordinal":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(after, execution_ordinal=3)
        )
    elif damage == "time":
        event.timestamp += timedelta(seconds=1)
    elif damage == "context":
        event.process.image = before.image
    elif damage == "host":
        event.src_host.os_category = "windows"
    elif damage == "lifecycle":
        event.lifecycle = replace(event.lifecycle, phase="start")
    else:
        event.identity_plan = replace(event.identity_plan, actor=after)
    assert not shadow_seal(event).valid


def test_ecar_exec_extension_preserves_object_and_execution_ids(tmp_path: Path) -> None:
    state, dispatcher, _ = _environment()
    before, after, event, batch = _prepare(state, dispatcher)
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    captured: list[dict] = []
    emitter._emit_canonical_event = lambda data, occurrence: captured.append(data)
    emitter.emit(event.seal())
    record = json.loads(emitter._render_event(captured[0]))
    assert record["object"] == "PROCESS" and record["action"] == "MODIFY"
    assert record["objectID"] == record["actorID"] == before.object_id
    assert record["pid"] == before.pid
    assert record["tid"] == after.primary_thread.tid
    assert record["properties"]["execution_id"] == after.execution_id
    assert record["properties"]["previous_execution_id"] == before.execution_id
    assert record["properties"]["operation"] == "exec"
    assert record["properties"]["image_path"] == "/bin/zsh"
    assert all(type(value) is str for value in record["properties"].values())
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    emitter.close()


@pytest.mark.parametrize("threaded", [False, True])
def test_exec_real_ecar_output_parses_with_preserved_ids(tmp_path: Path, threaded: bool) -> None:
    from evidenceforge.evaluation.parsers.ecar import EcarParser

    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher.emitters["ecar"] = emitter
    before, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert result.projections[0].status == "succeeded"
    emitter.close()
    records = [
        record for path in tmp_path.rglob("ecar.json") for record in EcarParser().parse_file(path)
    ]
    assert len(records) == 1
    record = records[0]
    assert not record.parse_errors
    assert record.fields["objectID"] == before.object_id
    assert record.fields["execution_id"] == after.execution_id
    assert record.fields["action"] == "MODIFY"


@pytest.mark.parametrize(
    "damage", ["foreign_after", "foreign_before", "integrity", "platform", "duplicate", "missing"]
)
def test_exec_projection_requires_all_and_only_authenticated_state_changes(damage: str) -> None:
    state, dispatcher, emitter = _environment()
    before = state.get_process_identity(
        "HOST-01", next(iter(state._running_processes.values())).pid
    )
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before, image="/bin/zsh", command_line="zsh -l", executed_at=_START + timedelta(seconds=2)
    )
    plan = builder.seal()
    event = _exec_event(before, after)
    if damage == "foreign_after":
        event = _exec_event(before, replace(after, image="/bin/other"))
    elif damage == "foreign_before":
        event = _exec_event(replace(before, command_line="other-before"), after)
    elif damage == "integrity":
        event.process.integrity_level = "System"
    elif damage == "platform":
        event.src_host.os_category = "linux"
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    prepared = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    dispatches = (
        ()
        if damage == "missing"
        else (prepared, prepared)
        if damage == "duplicate"
        else (prepared,)
    )
    with pytest.raises(EventContractError):
        dispatcher.prepare_action_cohort_batch(
            _ROOT_ACTION_ID, plan, dispatches, (_zero_node_entry(),), (), ()
        )
    assert state.get_process_identity("HOST-01", before.pid) == before
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("exact_projection", [False, True])
def test_exec_with_no_selected_output_still_updates_canonical_state(exact_projection: bool) -> None:
    state, dispatcher, emitter = _environment()
    dispatcher.emitters.clear()
    before, after, _, batch = _prepare(state, dispatcher, exact_projection=exact_projection)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    emitter.emit.assert_not_called()


def test_exec_source_failure_does_not_repeat_committed_image_replacement() -> None:
    state, dispatcher, emitter = _environment()
    before, after, _, batch = _prepare(state, dispatcher)
    emitter.emit.side_effect = RuntimeError("injected source failure")
    with pytest.raises(RuntimeError, match="injected source failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    assert caught.value.action_cohort_receipt is not None
    with pytest.raises(EventContractError, match="stale|consumed"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert emitter.emit.call_count == 1


def test_exec_follows_create_and_precedes_termination_in_source_clock() -> None:
    from tests.unit.test_dispatcher_action_cohort import _dispatcher_environment

    cohort = _dispatcher_environment()
    dispatcher = cohort.dispatcher
    dispatcher.publish_prepared_action_cohort_batch(cohort.batch)
    before = cohort.process_plans[0].identity
    state = cohort.state
    _, after, _, batch = _prepare(state, dispatcher, "linux")
    dispatcher.publish_prepared_action_cohort_batch(batch)
    start, execution = [call.args[0] for call in cohort.emitter.emit.call_args_list]
    planner = dispatcher.source_timing_planner
    assert planner.admission_time(start, "ecar") < planner.admission_time(execution, "ecar")
    close = OccurrenceBuilder(
        timestamp=after.execution_started_at + timedelta(seconds=2),
        event_type="process_terminate",
        src_host=execution.src_host,
        process=execution.process,
        identity_plan=EventIdentityPlan(subject=after),
        lifecycle=replace(execution.lifecycle, phase="closure"),
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(after, end_time=close.timestamp)
    plan = builder.seal()
    with planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            close, source_timing_preparation=timing
        )
    prepared = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    batch = dispatcher.prepare_action_cohort_batch(
        _ROOT_ACTION_ID, plan, (prepared,), (_zero_node_entry(),), (), ()
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    terminal = cohort.emitter.emit.call_args.args[0]
    assert planner.admission_time(execution, "ecar") < planner.admission_time(terminal, "ecar")
    assert state.get_process("HOST-01", before.pid) is None


def test_exec_exact_sink_lost_return_recovers_one_row_without_reexecuting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
            raise RuntimeError("injected exec commit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    before, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    with pytest.raises(RuntimeError, match="exec commit lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    version = state.materialization_version
    receipt = caught.value.action_cohort_receipt
    assert caught.value.action_cohort_result.projections[0].status == "recoverable"
    assert dispatcher.resume_action_cohort_projection(receipt).projections[0].status == "succeeded"
    assert state.materialization_version == version
    assert state.get_process_identity("HOST-01", before.pid) == after
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1 and attempts == 2
    assert json.loads(rows[0])["properties"]["execution_id"] == after.execution_id


@pytest.mark.parametrize("restore", [False, True])
def test_new_image_file_activity_cannot_render_before_exec(restore: bool) -> None:
    from evidenceforge.events.contexts import FileContext
    from evidenceforge.events.identity import EntityIdentity

    state, dispatcher, emitter = _environment()
    _, after, _, batch = _prepare(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    execution = emitter.emit.call_args.args[0]
    planner = dispatcher.source_timing_planner
    exec_time = planner.admission_time(execution, "ecar")
    if restore:
        from evidenceforge.generation.checkpoints.source_timing_head import (
            SourceTimingPlannerParticipant,
        )
        from evidenceforge.generation.source_timing import SourceTimingPlanner

        del batch
        seal = SourceTimingPlannerParticipant(planner).prepare_checkpoint(0)
        planner = SourceTimingPlanner()
        SourceTimingPlannerParticipant(planner).restore_checkpoint(
            seal.head.payload, tuple(segment.payload for segment in seal.segments)
        )
    for ordinal in range(8):
        file = OccurrenceBuilder(
            timestamp=after.execution_started_at + timedelta(microseconds=1),
            event_type="file_create",
            src_host=execution.src_host,
            process=execution.process,
            file=FileContext(path=f"/tmp/result-{ordinal}", action="create"),
            identity_plan=EventIdentityPlan(
                actor=after, subject=EntityIdentity(object_id=f"result-{ordinal}", kind="file")
            ),
            lifecycle=execution.lifecycle,
        )
        observed = planner.plan_event(file, "ecar")
        assert planner.admission_time(observed, "ecar") > exec_time


def test_immediate_reexec_retains_order_and_distinct_execution_ids() -> None:
    state, dispatcher, emitter = _environment()
    before, first, _, batch = _prepare(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    _, second, _, batch = _prepare(state, dispatcher, delay=timedelta(microseconds=1))
    dispatcher.publish_prepared_action_cohort_batch(batch)
    first_event, second_event = [call.args[0] for call in emitter.emit.call_args_list]
    planner = dispatcher.source_timing_planner
    assert planner.admission_time(first_event, "ecar") < planner.admission_time(
        second_event, "ecar"
    )
    assert before.object_id == first.object_id == second.object_id
    assert len({before.execution_id, first.execution_id, second.execution_id}) == 3
    assert state.get_process_identity("HOST-01", before.pid) == second


def test_internal_exec_is_not_an_authored_scenario_event() -> None:
    from pydantic import TypeAdapter, ValidationError

    from evidenceforge.models.scenario import EventSpec

    with pytest.raises(ValidationError, match="union_tag_invalid"):
        TypeAdapter(EventSpec).validate_python({"type": "process_exec", "image": "/bin/zsh"})


def test_ecar_exec_preserves_known_zero_ids_and_omits_unknown_audit_facts(tmp_path: Path) -> None:
    from evidenceforge.events.identity import PosixProcessCredentials

    state, dispatcher, _ = _environment()
    before, after, prepared_event, batch = _prepare(state, dispatcher)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    before = replace(before, credentials=PosixProcessCredentials(501, 501, 20, 20))
    after = replace(after, credentials=PosixProcessCredentials(501, 0, 20, 0))
    event = _exec_event(before, after)
    event.occurrence_key = prepared_event.occurrence_key
    event.contract_seal = shadow_seal(event)
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    captured: list[dict] = []
    emitter._emit_canonical_event = lambda data, occurrence: captured.append(data)
    emitter.emit(event.seal())
    properties = json.loads(emitter._render_event(captured[0]))["properties"]
    assert properties["effective_uid"] == "0"
    assert properties["effective_gid"] == "0"
    assert properties["previous_effective_uid"] == "501"
    assert properties["real_uid"] == properties["previous_real_uid"] == "501"
    assert "audit_uid" not in properties and "previous_audit_uid" not in properties
    assert "audit_session_id" not in properties and "previous_audit_session_id" not in properties
    emitter.close()


@pytest.mark.parametrize("timestamp", [None, "2026-10-15", _START.replace(tzinfo=None)])
def test_exec_invalid_time_is_a_contract_violation(timestamp: object) -> None:
    state, dispatcher, _ = _environment()
    _, _, event, batch = _prepare(state, dispatcher)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    event.timestamp = timestamp
    seal = shadow_seal(event)
    assert not seal.valid
    assert any("aware canonical timestamp" in item.message for item in seal.violations)


def test_exec_rejects_unowned_authentication_context() -> None:
    from evidenceforge.events.contexts import AuthContext

    state, dispatcher, _ = _environment()
    _, _, event, batch = _prepare(state, dispatcher)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    event.auth = AuthContext(username="other", logon_id="unrelated")
    assert not shadow_seal(event).valid
