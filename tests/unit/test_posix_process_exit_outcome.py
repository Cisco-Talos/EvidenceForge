# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Terminal results survive canonical ownership, failure and durable recovery."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import ESExit
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_process_exec_projection import _START, _environment
from tests.unit.test_process_exit_projection import _plan, _prepare


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"exit_code": 0, "signal": 9},
        {"exit_code": 256},
        {"exit_code": -1},
        {"exit_code": True},
        {"exit_code": "1"},
        {"signal": 0},
        {"signal": 127},
        {"signal": False},
        {"signal": "9"},
        {"exit_code": 0, "core_dumped": True},
        {"signal": 11, "core_dumped": 1},
    ],
)
def test_terminal_result_rejects_ambiguous_or_coerced_facts(fields: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError, ValidationError)):
        PosixProcessExit(**fields)
    with pytest.raises((ValueError, TypeError, ValidationError)):
        TypeAdapter(PosixProcessExit).validate_python(fields)


@pytest.mark.parametrize(
    "outcome,status",
    [
        (PosixProcessExit(exit_code=0), 0),
        (PosixProcessExit(exit_code=1), 256),
        (PosixProcessExit(exit_code=255), 65280),
        (PosixProcessExit(signal=9), 9),
        (PosixProcessExit(signal=15), 15),
        (PosixProcessExit(signal=11, core_dumped=True), 139),
    ],
)
def test_darwin_terminal_encoding_does_not_confuse_exit_codes_and_signals(
    outcome: PosixProcessExit, status: int
) -> None:
    native = ESExit.from_process_exit(outcome)
    assert native.stat == status and native.process_exit() == outcome
    assert native.model_dump() == {"stat": status}
    assert decode_state_value(encode_state_value(outcome)) == outcome


@pytest.mark.parametrize("status", [-1, 65536, 128, 127, 0x137F, 0x117F, 32, 0x0109])
def test_raw_nonterminal_or_unsupported_status_is_not_a_canonical_exit(status: int) -> None:
    record = ESExit(stat=status)
    assert record.stat == status
    with pytest.raises(ValueError):
        record.process_exit()


@pytest.mark.parametrize("platform", ["macos", "linux"])
@pytest.mark.parametrize("outcome", [PosixProcessExit(exit_code=7), PosixProcessExit(signal=15)])
def test_explicit_exit_closes_exact_process_and_survives_checkpoint(
    platform: str, outcome: PosixProcessExit
) -> None:
    state, dispatcher, emitter = _environment(platform)
    _, event = _plan(state, platform)
    identity = event.identity_plan.subject
    event.process.exit_outcome = outcome
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(identity, end_time=event.timestamp, exit_outcome=outcome)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), event))
    assert emitter.emit.call_args.args[0].process.exit_outcome == outcome
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for manager in (state, restored):
        assert manager.get_process(identity.hostname, identity.pid) is None
        ended = manager._ended_processes_by_object_id.get(identity.object_id)
        assert ended.exit_outcome == outcome and ended.end_time == event.timestamp


@pytest.mark.parametrize("selected", [True, False])
def test_collection_does_not_change_a_terminal_result(selected: bool) -> None:
    state, dispatcher, emitter = _environment()
    if not selected:
        dispatcher.emitters.clear()
    _, event = _plan(state)
    identity = event.identity_plan.subject
    outcome = PosixProcessExit(exit_code=0)
    event.process.exit_outcome = outcome
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(identity, end_time=event.timestamp, exit_outcome=outcome)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), event))
    assert state._ended_processes_by_object_id.get(identity.object_id).exit_outcome == outcome
    assert emitter.emit.call_count == int(selected)


def test_legacy_exit_remains_unknown_in_new_and_old_checkpoint_records() -> None:
    state, _, _ = _environment()
    plan, _ = _plan(state)
    state.materialize_action_cohort(plan)
    row = state._ended_processes_by_object_id.get(plan.process_terminations[0].identity.object_id)
    assert row.exit_outcome is None
    encoded = encode_state_value(row)
    assert encoded[1] == "running-process-v20"
    legacy = ["record", "running-process-v7", encoded[2][:30]]
    assert decode_state_value(legacy) == replace(row, parentage=None)


@pytest.mark.parametrize("change", ["omit", "substitute"])
def test_projection_cannot_omit_or_replace_planned_result(change: str) -> None:
    state, dispatcher, emitter = _environment()
    _, event = _plan(state)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        event.identity_plan.subject,
        end_time=event.timestamp,
        exit_outcome=PosixProcessExit(exit_code=1),
    )
    if change == "substitute":
        event.process.exit_outcome = PosixProcessExit(signal=9)
    with pytest.raises(EventContractError, match="process-close projection"):
        _prepare(dispatcher, builder.seal(), event)
    assert len(state._running_processes) == 1
    emitter.emit.assert_not_called()


def test_result_requires_owned_termination_and_rejects_compatibility_dispatch() -> None:
    state, dispatcher, _ = _environment()
    _, event = _plan(state)
    event.process.exit_outcome = PosixProcessExit(exit_code=0)
    assert shadow_seal(event).valid
    with pytest.raises(EventContractError, match="State action cohort"):
        dispatcher.dispatch_builder(event)
    event.event_type = "process_create"
    assert not shadow_seal(event).valid


def test_terminal_result_rollback_restores_live_process_without_leaking_outcome() -> None:
    state, _, _ = _environment()
    _, event = _plan(state)
    identity = event.identity_plan.subject
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        identity, end_time=event.timestamp, exit_outcome=PosixProcessExit(signal=15)
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="later owner"):
        with state.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            assert (
                state._ended_processes_by_object_id.get(identity.object_id).exit_outcome.signal
                == 15
            )
            raise RuntimeError("later owner")
    assert state.materialization_digest() == before
    assert state.get_process(identity.hostname, identity.pid).exit_outcome is None
    state.materialize_action_cohort(plan)
    assert state._ended_processes_by_object_id.get(identity.object_id).exit_outcome.signal == 15


def test_live_process_checkpoint_cannot_claim_a_terminal_result() -> None:
    state, _, _ = _environment()
    row = next(iter(state._running_processes.values()))
    row.exit_outcome = PosixProcessExit(exit_code=0)
    with pytest.raises(CheckpointCorruptionError, match="exit outcome"):
        _restore_head(StateManager(), _capture_head(state))


def test_darwin_rejects_linux_signal_number_without_closing_process() -> None:
    state, _, _ = _environment()
    row = next(iter(state._running_processes.values()))
    with pytest.raises(StateError, match="Darwin signal range"):
        state.plan_process_termination_materialization(
            system=row.system,
            pid=row.pid,
            end_time=_START + timedelta(seconds=2),
            exit_outcome=PosixProcessExit(signal=64),
        )
    assert state.get_process(row.system, row.pid) is row
    with pytest.raises(ValueError, match="Darwin signal range"):
        ESExit.from_process_exit(PosixProcessExit(signal=64))


def test_staged_process_result_matches_its_terminal_state() -> None:
    state, _, _ = _environment()
    builder = state.begin_action_cohort_materialization()
    child = builder.plan_process(
        system="HOST-01",
        parent_pid=0,
        image="/usr/bin/true",
        command_line="true",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=1),
    )
    result = PosixProcessExit(exit_code=0)
    builder.terminate_process(child, end_time=_START + timedelta(seconds=2), exit_outcome=result)
    state.materialize_action_cohort(builder.seal())
    assert state._ended_processes_by_object_id.get(child.identity.object_id).exit_outcome == result


def test_exact_exit_retries_sink_without_repeating_terminal_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.emitters.ecar import EcarEmitter
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
            raise RuntimeError("terminal sink return lost")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters["ecar"] = emitter
    _, event = _plan(state)
    outcome = PosixProcessExit(signal=15)
    event.process.exit_outcome = outcome
    identity = event.identity_plan.subject
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(identity, end_time=event.timestamp, exit_outcome=outcome)
    batch = _prepare(dispatcher, builder.seal(), event, exact=True)
    try:
        with pytest.raises(RuntimeError, match="sink return lost") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
        assert state._ended_processes_by_object_id.get(identity.object_id).exit_outcome == outcome
        version = state.materialization_version
        dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
        assert state.materialization_version == version
        assert attempts == 2
        dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        emitter.close()
    assert (
        len(
            [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
        )
        == 1
    )


def test_exit_after_exec_retains_result_without_altering_prior_execution() -> None:
    from tests.unit.test_process_exec_projection import _prepare as prepare_exec

    state, dispatcher, _ = _environment()
    before, after, _, batch = prepare_exec(state, dispatcher)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    _, event = _plan(state)
    assert event.identity_plan.subject == after
    outcome = PosixProcessExit(exit_code=2)
    event.process.exit_outcome = outcome
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(after, end_time=event.timestamp, exit_outcome=outcome)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), event))
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    ended = restored._ended_processes_by_object_id.get(after.object_id)
    assert ended.exit_outcome == outcome
    assert ended.execution_ordinal == after.execution_ordinal
    assert (
        restored.get_process_identity_by_object_id(before.object_id, event_time=before.started_at)
        == before
    )


@pytest.mark.parametrize(
    "image,expected",
    [
        (
            r"C:\Windows\System32\svchost.exe",
            "network-connection-8ca0b37e-559b-41bb-8998-58cf58d1d1a8",
        ),
        ("/usr/bin/resolvectl", "network-connection-2498f63e-dea5-4a24-962f-dda9b4da17f3"),
        ("/usr/sbin/mDNSResponder", "network-connection-cdb1c3aa-fab5-4bf9-b45c-932959026632"),
    ],
)
def test_absent_exit_result_preserves_pre_extension_network_identity(
    image: str, expected: str
) -> None:
    from datetime import UTC, datetime

    from evidenceforge.events.contexts import DnsContext, ProcessContext
    from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
    from evidenceforge.generation.actions.network_identity import _trusted_network_request_stable_id

    # Independently computed with revision 213, before ProcessContext had an exit field.
    process = ProcessContext(
        pid=1200, parent_pid=1, image=image, command_line=image, username="synthetic-user"
    )
    request = NetworkConnectionRequest(
        src_ip="192.0.2.10",
        dst_ip="192.0.2.53",
        time=datetime(2026, 10, 18, 12, tzinfo=UTC),
        dst_port=53,
        proto="udp",
        dns=DnsContext(query="example.test", query_process=process),
    )
    assert request.stable_id == expected
    assert _trusted_network_request_stable_id(request, NetworkConnectionRequest) == expected
    process.exit_outcome = PosixProcessExit(exit_code=0)
    with pytest.raises(ValueError, match="terminal exit outcome"):
        _ = request.stable_id
    with pytest.raises(ValueError, match="terminal exit outcome"):
        _trusted_network_request_stable_id(request, NetworkConnectionRequest)
