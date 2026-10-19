# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented complete descriptor tables preserve fork/exec and history ownership."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
from evidenceforge.generation.actions.process_policy import record_failed_process_exec
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START, _execute, _process


def _table(seconds: int = 0) -> MacosDescriptorTable:
    return MacosDescriptorTable(
        "workstation-test",
        _START + timedelta(seconds=seconds),
        (
            MacosDescriptorBinding(0, "file", "invented-terminal-device", False),
            MacosDescriptorBinding(3, "pipe", "invented-pipe", True),
            MacosDescriptorBinding(8, "socket", "invented-socket", False),
        ),
    )


def test_unknown_empty_and_known_tables_remain_distinct_through_checkpoint() -> None:
    state, process = _process()
    assert state.process_descriptors_at(process, event_time=_START) is None
    builder = state.begin_action_cohort_materialization()
    empty = MacosDescriptorTable(process.hostname, _START, ())
    builder.record_macos_descriptors(process, table=empty)
    state.materialize_action_cohort(builder.seal())
    assert state.process_descriptors_at(process, event_time=_START) == empty
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.process_descriptors_at(process, event_time=_START) == empty
    assert restored.get_process_identity(process.hostname, process.pid) == process


def test_fork_shares_open_objects_but_has_an_independent_descriptor_table() -> None:
    state, parent = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(parent, table=_table())
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    before = state.materialization_digest()
    plan = builder.seal()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            state.process_descriptors_at(
                child.identity, event_time=child.identity.started_at
            ).bindings
            == _table().bindings
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    inherited = state.process_descriptors_at(child.identity, event_time=child.identity.started_at)
    builder = state.begin_action_cohort_materialization()
    closed = inherited.closed(3, observed_at=_START + timedelta(seconds=2))
    builder.record_macos_descriptors(child.identity, table=closed)
    state.materialize_action_cohort(builder.seal())
    assert [
        item.fd
        for item in state.process_descriptors_at(parent, event_time=closed.observed_at).bindings
    ] == [0, 3, 8]
    assert [
        item.fd
        for item in state.process_descriptors_at(
            child.identity, event_time=closed.observed_at
        ).bindings
    ] == [0, 8]


def test_successful_exec_closes_flags_but_failed_exec_preserves_all_descriptors() -> None:
    state, first = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(first, table=_table())
    state.materialize_action_cohort(builder.seal())
    record_failed_process_exec(
        state,
        actor=first,
        attempted_at=_START + timedelta(seconds=1),
        image="/missing/invented",
        command_line="invented",
        error_number=2,
    )
    assert state.process_descriptors_at(first, event_time=_START + timedelta(seconds=1)) == _table()
    second = _execute(state, first, seconds=2)
    table = state.process_descriptors_at(second, event_time=second.executed_at)
    assert [item.fd for item in table.bindings] == [0, 8]
    assert table.observed_at == second.executed_at
    assert table.bindings[0].object_id == _table().bindings[0].object_id
    assert state.process_descriptors_at(first, event_time=_START) == _table()
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.process_descriptors_at(second, event_time=second.executed_at) == table
    assert restored.process_descriptors_at(first, event_time=_START) == _table()


def test_prepared_exec_descriptor_effect_is_authenticated_and_rollback_safe() -> None:
    state, first = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(first, table=_table())
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    second = builder.execute_process(
        first, image="/usr/bin/true", command_line="true", executed_at=_START + timedelta(seconds=1)
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            len(state.process_descriptors_at(second, event_time=second.executed_at).bindings) == 2
        )
    assert state.materialization_digest() == before
    object.__setattr__(plan.process_executions[0], "descriptors_after", None)
    with pytest.raises(StateError):
        state.materialize_action_cohort(plan)
    assert state.materialization_digest() == before


def test_unknown_tables_do_not_become_empty_after_fork_or_exec() -> None:
    state, parent = _process()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    after = _execute(state, child.identity, seconds=2)
    assert state.process_descriptors_at(parent, event_time=_START) is None
    assert state.process_descriptors_at(after, event_time=after.executed_at) is None


@pytest.mark.parametrize("kind", ["foreign", "old", "linux", "duplicate_time"])
def test_invalid_descriptor_observation_cannot_mutate_state(kind: str) -> None:
    state, process = _process("linux" if kind == "linux" else "macos")
    table = _table()
    if kind == "foreign":
        table = replace(table, hostname="FOREIGN")
    elif kind == "old":
        table = replace(table, observed_at=_START - timedelta(seconds=1))
    elif kind == "duplicate_time":
        builder = state.begin_action_cohort_materialization()
        builder.record_macos_descriptors(process, table=table)
        state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="[Dd]escriptor"):
        builder.record_macos_descriptors(process, table=table)
    assert state.materialization_digest() == before


def test_live_descriptor_mutation_cannot_share_fork_or_exec_cohort() -> None:
    state, process = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(process, table=_table())
    builder.fork_process(process, forked_at=_START + timedelta(seconds=1))
    before = state.materialization_digest()
    with pytest.raises(StateError, match="own process cohort"):
        state.materialize_action_cohort(builder.seal())
    assert state.materialization_digest() == before


def test_tables_are_bounded_sorted_and_exact_with_explicit_duplicate_flags() -> None:
    source = _table()
    copied = source.duplicated(3, 9, observed_at=_START + timedelta(seconds=1), close_on_exec=False)
    assert copied.bindings[-1].object_id == source.bindings[1].object_id
    assert not copied.bindings[-1].close_on_exec
    assert [item.fd for item in copied.after_exec(_START + timedelta(seconds=2)).bindings] == [
        0,
        8,
        9,
    ]
    for bindings in (
        (source.bindings[0],) * 2,
        tuple(reversed(source.bindings)),
        source.bindings * 4096,
    ):
        with pytest.raises(ValueError):
            replace(source, bindings=bindings)
    for fd in (-1, True, 2**31):
        with pytest.raises(ValueError):
            replace(source.bindings[0], fd=fd)
    with pytest.raises(ValueError, match="unused"):
        source.duplicated(0, 8, observed_at=_START, close_on_exec=False)
    with pytest.raises(ValueError, match="existing"):
        source.closed(99, observed_at=_START)


def test_old_record_migrates_to_unknown_descriptors_and_new_history_is_bounded() -> None:
    state, process = _process()
    row = state.get_process(process.hostname, process.pid)
    fields = encode_state_value(row)[2]
    assert len(fields) == 45
    old = decode_state_value(["record", "running-process-v18", fields[:42]])
    assert old.descriptor_history == ()
    for second in range(70):
        builder = state.begin_action_cohort_materialization()
        builder.record_macos_descriptors(process, table=_table(second))
        state.materialize_action_cohort(builder.seal())
    assert len(row.descriptor_history) == 64
    assert state.process_descriptors_at(process, event_time=_START) is None


@pytest.mark.parametrize("kind", ["future", "foreign", "oversized", "object_kind"])
def test_corrupt_descriptor_history_cannot_restore(kind: str) -> None:
    state, process = _process()
    row = state.get_process(process.hostname, process.pid)
    if kind == "future":
        row.descriptor_history = (_table(99),)
    elif kind == "foreign":
        row.descriptor_history = (replace(_table(), hostname="FOREIGN"),)
    elif kind == "object_kind":
        changed = replace(
            _table(1),
            bindings=(replace(_table().bindings[0], kind="socket"),),
        )
        row.descriptor_history = (_table(), changed)
        row.last_activity_time = changed.observed_at
    else:
        row.descriptor_history = (_table(),) * 65
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="descriptor history"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


def test_descriptor_history_never_crosses_reused_pid_lifetimes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, original = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(original, table=_table())
    state.materialize_action_cohort(builder.seal())
    state.end_process(original.hostname, original.pid, _START + timedelta(seconds=2))
    preview = state._preview_linux_pid

    def reuse(**kwargs: object) -> tuple:
        _pid, position, patch, candidates = preview(**kwargs)
        return original.pid, position, patch, candidates

    monkeypatch.setattr(state, "_preview_linux_pid", reuse)
    plan = state.plan_process_materialization(
        system=original.hostname,
        parent_pid=0,
        image="/bin/cat",
        command_line="cat",
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=5),
    )
    state.materialize_process(plan)
    assert plan.identity.pid == original.pid and plan.identity.object_id != original.object_id
    assert state.process_descriptors_at(original, event_time=_START) == _table()
    assert state.process_descriptors_at(plan.identity, event_time=plan.identity.started_at) is None
    with pytest.raises(StateError, match="stale"):
        state.process_descriptors_at(original, event_time=plan.identity.started_at)


def test_staged_birth_accepts_only_its_exact_complete_table() -> None:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process = builder.plan_process(
        system="workstation-test",
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START,
    )
    with pytest.raises(StateError, match="exact process birth"):
        builder.record_macos_descriptors(process, table=_table(1))
    builder.record_macos_descriptors(process, table=_table())
    state.materialize_action_cohort(builder.seal())
    assert state.process_descriptors_at(process.identity, event_time=_START) == _table()


def test_known_descriptor_fork_uses_existing_dispatch_and_lifecycle_commit() -> None:
    from tests.unit.test_process_exec_projection import _environment
    from tests.unit.test_process_fork_projection import _plan, _prepare

    state, dispatcher, emitter = _environment()
    running = next(iter(state._running_processes.values()))
    parent = state.get_process_identity("HOST-01", running.pid)
    table = replace(_table(), hostname=parent.hostname, observed_at=parent.started_at)
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(parent, table=table)
    state.materialize_action_cohort(builder.seal())
    plan, event = _plan(state)
    batch = _prepare(dispatcher, plan, event)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    child = event.identity_plan.subject
    assert (
        state.process_descriptors_at(child, event_time=child.started_at).bindings == table.bindings
    )
    assert emitter.emit.call_count == 1


@pytest.mark.slow
def test_descriptor_fork_exec_recovery_is_fresh_process_deterministic() -> None:
    import os
    import subprocess
    import sys

    script = """
import json
from datetime import timedelta
from tests.unit.test_macos_descriptor_state import _table
from tests.unit.test_process_execution_state import _START, _process, _execute
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import encode_state_value
state, parent = _process()
builder = state.begin_action_cohort_materialization()
builder.record_macos_descriptors(parent, table=_table())
state.materialize_action_cohort(builder.seal())
builder = state.begin_action_cohort_materialization()
child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
state.materialize_action_cohort(builder.seal())
restored = StateManager()
_restore_head(restored, _capture_head(state))
results = []
for manager in (state, restored):
    after = _execute(manager, child.identity, seconds=2)
    table = manager.process_descriptors_at(after, event_time=after.executed_at)
    results.append([encode_state_value(after), encode_state_value(table)])
assert results[0] == results[1]
print(json.dumps(results[0], sort_keys=True))
"""
    results: list[str] = []
    for seed in ("17", "983"):
        run = subprocess.run(
            [sys.executable, "-c", script],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert run.returncode == 0, run.stdout + run.stderr
        results.append(run.stdout)
    assert results[0] == results[1]


@pytest.mark.parametrize("field,value", [(0, True), (0, "3"), (2, b"object"), (3, 1)])
def test_descriptor_codec_rejects_scalar_coercion(field: int, value: object) -> None:
    encoded = encode_state_value(_table().bindings[0])
    encoded[2][field] = encode_state_value(value)
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encoded)


def test_descriptor_codec_rejects_untyped_time_and_binding_container() -> None:
    for field, value in [(1, _START.isoformat()), (2, list(_table().bindings))]:
        encoded = encode_state_value(_table())
        encoded[2][field] = encode_state_value(value)
        with pytest.raises(CheckpointCorruptionError):
            decode_state_value(encoded)
