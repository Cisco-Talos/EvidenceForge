# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented current-directory transitions preserve immutable execution observations."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.generation.actions.process_policy import record_failed_process_exec
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_execution_directory import _create, _directory
from tests.unit.test_process_execution_state import _START


def test_directory_change_is_atomic_and_does_not_replace_execution_identity() -> None:
    original = _directory()
    state, identity = _create(original)
    changed = _directory(seconds=5, path="/private/tmp/invented-work")
    builder = state.begin_action_cohort_materialization()
    builder.change_macos_process_directory(identity, directory=changed)
    plan = builder.seal()
    before = state.materialization_digest()
    assert state.process_directory_at(identity, event_time=changed.observed_at) == original
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.process_directory_at(identity, event_time=changed.observed_at) == changed
        assert state.get_process_identity(identity.hostname, identity.pid) == identity
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert state.get_process_identity(identity.hostname, identity.pid) == identity
    assert (
        state.process_directory_at(identity, event_time=_START + timedelta(seconds=4)) == original
    )
    assert state.process_directory_at(identity, event_time=changed.observed_at) == changed
    process = state.get_process(identity.hostname, identity.pid)
    assert process.last_activity_time == changed.observed_at
    assert process.execution_directory == original
    assert len(process.directory_history) == 2


def test_directory_lifetime_history_survives_exec_failure_success_and_checkpoint() -> None:
    state, first = _create(_directory())
    changed = _directory(seconds=1, path="/private/tmp/invented-work")
    builder = state.begin_action_cohort_materialization()
    builder.change_macos_process_directory(first, directory=changed)
    state.materialize_action_cohort(builder.seal())
    record_failed_process_exec(
        state,
        actor=first,
        attempted_at=_START + timedelta(seconds=2),
        image="/missing/invented",
        command_line="invented",
        error_number=2,
    )
    assert state.process_directory_at(first, event_time=_START + timedelta(seconds=2)) == changed
    builder = state.begin_action_cohort_materialization()
    second = builder.execute_process(
        first, image="/usr/bin/true", command_line="true", executed_at=_START + timedelta(seconds=3)
    )
    state.materialize_action_cohort(builder.seal())
    assert second.execution_directory is None
    assert state.process_directory_at(second, event_time=second.executed_at) == changed
    # The result keeps the original stat observation time; it is not a fresh exec snapshot.
    assert changed.observed_at < second.executed_at
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.process_directory_at(first, event_time=_START) == first.execution_directory
    assert restored.process_directory_at(first, event_time=_START + timedelta(seconds=2)) == changed
    assert restored.process_directory_at(second, event_time=second.executed_at) == changed
    with pytest.raises(StateError, match="stale"):
        restored.process_directory_at(first, event_time=second.executed_at)


def test_explicit_exec_directory_updates_tracker_but_fork_requires_new_observation() -> None:
    state, parent = _create(_directory())
    builder = state.begin_action_cohort_materialization()
    fresh = _directory(seconds=1, path="/private/var/empty")
    after = builder.execute_process(
        parent,
        image="/usr/bin/true",
        command_line="true",
        executed_at=fresh.observed_at,
        execution_directory=fresh,
    )
    state.materialize_action_cohort(builder.seal())
    assert state.process_directory_at(after, event_time=fresh.observed_at) == fresh
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=_START + timedelta(seconds=2))
    state.materialize_action_cohort(builder.seal())
    assert state.process_directory_at(child.identity, event_time=child.identity.started_at) is None


@pytest.mark.parametrize("kind", ["foreign", "old", "same_time", "linux", "staged"])
def test_invalid_directory_changes_leave_state_unchanged(kind: str) -> None:
    state, identity = _create(
        None if kind == "linux" else _directory(), platform="linux" if kind == "linux" else "macos"
    )
    builder = state.begin_action_cohort_materialization()
    directory = _directory(seconds=1)
    target = identity
    if kind == "foreign":
        directory = replace(directory, hostname="FOREIGN")
    elif kind == "old":
        directory = _directory(seconds=-1)
    elif kind == "same_time":
        directory = _directory()
    elif kind == "staged":
        target = builder.fork_process(identity, forked_at=_START + timedelta(seconds=1))
    before = state.materialization_digest()
    with pytest.raises((StateError, ValueError), match="[Dd]irectory|live process"):
        builder.change_macos_process_directory(target, directory=directory)
    assert state.materialization_digest() == before


def test_directory_change_cannot_share_exec_cohort_or_hide_changed_stat() -> None:
    state, identity = _create(_directory())
    builder = state.begin_action_cohort_materialization()
    builder.change_macos_process_directory(identity, directory=_directory(seconds=1))
    builder.execute_process(
        identity,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="own process cohort"):
        state.materialize_action_cohort(builder.seal())
    assert state.materialization_digest() == before
    builder = state.begin_action_cohort_materialization()
    builder.change_macos_process_directory(identity, directory=_directory(seconds=1))
    plan = builder.seal()
    object.__setattr__(plan.process_activity_patches[0], "directory_change", _directory(seconds=2))
    with pytest.raises(StateError):
        state.materialize_action_cohort(plan)
    assert state.materialization_digest() == before


def test_directory_history_is_bounded_and_retired_observations_remain_unknown() -> None:
    state, identity = _create(_directory())
    for second in range(1, 70):
        builder = state.begin_action_cohort_materialization()
        builder.change_macos_process_directory(identity, directory=_directory(seconds=second))
        state.materialize_action_cohort(builder.seal())
    process = state.get_process(identity.hostname, identity.pid)
    assert len(process.directory_history) == 64
    assert state.process_directory_at(identity, event_time=_START) is None
    assert state.process_directory_at(
        identity, event_time=_START + timedelta(seconds=69)
    ) == _directory(seconds=69)


def test_old_running_process_record_does_not_invent_current_directory_history() -> None:
    state, identity = _create(_directory())
    fields = encode_state_value(state.get_process(identity.hostname, identity.pid))[2]
    assert len(fields) == 45
    prior = decode_state_value(["record", "running-process-v17", fields[:41]])
    assert prior.directory_history == ()
    assert prior.execution_directory == identity.execution_directory
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(["record", "running-process-v17", fields])


@pytest.mark.parametrize("kind", ["foreign", "future", "duplicate", "oversized"])
def test_corrupt_directory_history_cannot_restore(kind: str) -> None:
    state, identity = _create(_directory())
    process = state.get_process(identity.hostname, identity.pid)
    if kind == "foreign":
        process.directory_history = (replace(_directory(), hostname="FOREIGN"),)
    elif kind == "future":
        process.directory_history = (_directory(seconds=99),)
    elif kind == "duplicate":
        process.directory_history = (_directory(), _directory())
    else:
        process.directory_history = (_directory(),) * 65
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="directory history"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before
