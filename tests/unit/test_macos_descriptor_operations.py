# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta

import pytest

from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_descriptor_state import _table
from tests.unit.test_process_execution_state import _START, _execute, _process


def test_dup2_replaces_only_destination_and_clears_its_close_flag() -> None:
    source = _table()
    target = source.duplicate_to(3, 8, observed_at=_START + timedelta(seconds=1))
    assert len(target.bindings) == len(source.bindings)
    assert target.bindings[1] == source.bindings[1]
    assert target.bindings[-1].object_id == source.bindings[1].object_id
    assert not target.bindings[-1].close_on_exec
    assert source.bindings[-1].object_id != target.bindings[-1].object_id
    assert [item.fd for item in target.after_exec(_START + timedelta(seconds=2)).bindings] == [0, 8]
    noop = source.duplicate_to(3, 3, observed_at=_START + timedelta(seconds=1))
    assert noop.bindings == source.bindings and noop.bindings[1].close_on_exec
    free = source.duplicate_to(3, 9, observed_at=_START + timedelta(seconds=1))
    assert len(free.bindings) == len(source.bindings) + 1
    assert free.bindings[-1].object_id == source.bindings[1].object_id


def test_explicit_flag_change_controls_exec_without_changing_shared_object() -> None:
    source = _table()
    changed = source.set_close_on_exec(3, False, observed_at=_START + timedelta(seconds=1))
    assert changed.bindings[1].object_id == source.bindings[1].object_id
    assert changed.after_exec(_START + timedelta(seconds=2)).bindings == changed.bindings
    reversed_flag = changed.set_close_on_exec(3, True, observed_at=_START + timedelta(seconds=2))
    assert reversed_flag.bindings == source.bindings


@pytest.mark.parametrize("source,target", [(True, 2), (3, True), (99, 8), (3, -1), (3, 2**31)])
def test_dup2_rejects_unknown_or_invalid_descriptors(source: object, target: object) -> None:
    with pytest.raises(ValueError):
        _table().duplicate_to(source, target, observed_at=_START)


@pytest.mark.parametrize("fd,flag", [(True, True), (99, True), (3, 1), (3, None)])
def test_flag_changes_reject_unknown_or_coerced_values(fd: object, flag: object) -> None:
    with pytest.raises(ValueError):
        _table().set_close_on_exec(fd, flag, observed_at=_START)


def test_child_descriptor_replacement_preserves_parent_and_recovers_before_exec() -> None:
    state, parent = _process()
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(parent, table=_table())
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    before = state.process_descriptors_at(child.identity, event_time=child.identity.started_at)
    replaced = before.duplicate_to(3, 8, observed_at=_START + timedelta(seconds=2))
    builder = state.begin_action_cohort_materialization()
    builder.record_macos_descriptors(child.identity, table=replaced)
    plan = builder.seal()
    digest = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
    assert state.materialization_digest() == digest
    state.materialize_action_cohort(plan)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    after = _execute(restored, child.identity, seconds=3)
    table = restored.process_descriptors_at(after, event_time=after.execution_started_at)
    assert [item.fd for item in table.bindings] == [0, 8]
    assert table.bindings[-1].object_id == _table().bindings[1].object_id
    assert (
        restored.process_descriptors_at(parent, event_time=after.execution_started_at) == _table()
    )
