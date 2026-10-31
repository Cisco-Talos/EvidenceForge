# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exec file actions allocate descriptor and pipe truth with the existing atomic owner."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_metadata_producers import _Fixture, _terminal
from tests.unit.test_macos_metadata_producers import modeled as modeled


@pytest.mark.parametrize(
    "kind", ["login_standard", "login_pipes", "server_channels", "standard_only"]
)
def test_spawn_table_pipe_counter_and_observation_commit_rollback_and_restore_together(
    modeled: _Fixture, kind: str
) -> None:
    state, provider = modeled.state, modeled.producer
    parent = _terminal(modeled)
    state.materialize_process(parent)
    before = parent.identity
    if kind == "server_channels":
        builder = state.begin_action_cohort_materialization()
        child = provider.plan_fork(builder, state, before, at=modeled.start + timedelta(seconds=2))
        state.materialize_action_cohort(builder.seal())
        builder = state.begin_action_cohort_materialization()
        before = builder.change_posix_job_control(
            child.identity,
            operation="setsid",
            changed_at=modeled.start + timedelta(seconds=3),
            macos_terminal="absent",
        )
        state.materialize_action_cohort(builder.seal())
    count = 2 if kind == "server_channels" else 1 if kind == "login_pipes" else 0
    first = provider.profile.first_pipe_id
    intent = MacosSpawnIO(kind, first if count else None)
    at = modeled.start + timedelta(seconds=4)
    binary = provider._filesystem.deployed_binary(before.hostname, "/usr/bin/id", before.principal)
    builder = state.begin_action_cohort_materialization()
    prepared = provider.plan_exec(
        builder,
        state,
        before,
        at=at,
        image="/usr/bin/id",
        requested_path="/usr/bin/id",
        arguments=("/usr/bin/id",),
        binary=binary,
        spawn_io=intent,
    )
    plan, digest = builder.seal(), state.materialization_digest()
    table = plan.process_executions[0].descriptors_after
    assert prepared.descriptors.table == table
    assert table.native_last_fd == (4 if kind == "server_channels" else 5 if count else 2)
    pipes = [binding for binding in table.bindings if binding.kind == "pipe"]
    assert len({binding.native_pipe_id for binding in pipes}) == count
    if kind == "login_pipes":
        assert [binding.fd for binding in pipes] == [4, 5]
        assert pipes[0].object_id == pipes[1].object_id
    if kind == "server_channels":
        assert [binding.kind for binding in table.bindings] == [
            "socket",
            "socket",
            "pipe",
            "pipe",
            "file",
        ]
    for provisional in (True, False):
        if provisional:
            with state.prepared_action_cohort_materialization(plan) as claim:
                claim.certify_composite_commit(claim.expected_result)
                claim.apply_provisional()
                assert state.process_descriptors_at(prepared.process, event_time=at) == table
            assert state.materialization_digest() == digest
        else:
            state.materialize_action_cohort(plan)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for owner in (state, restored):
        assert owner.process_descriptors_at(prepared.process, event_time=at) == table
        assert owner.get_process_identity(before.hostname, before.pid) == prepared.process
        if count:
            assert owner._macos_pipe_counters[before.hostname] == (first, first + count - 1)


@pytest.mark.parametrize("damage", ["counter", "table", "intent"])
def test_spawn_cannot_publish_a_changed_pipe_allocation_or_layout(
    modeled: _Fixture, damage: str
) -> None:
    state, provider = modeled.state, modeled.producer
    parent = _terminal(modeled)
    state.materialize_process(parent)
    builder = state.begin_action_cohort_materialization()
    binary = provider._filesystem.deployed_binary("MAC-01", "/usr/bin/id", "alex")
    provider.plan_exec(
        builder,
        state,
        parent.identity,
        at=modeled.start + timedelta(seconds=2),
        image="/usr/bin/id",
        requested_path="/usr/bin/id",
        arguments=("/usr/bin/id",),
        binary=binary,
        spawn_io=MacosSpawnIO("login_pipes", provider.profile.first_pipe_id),
    )
    plan = builder.seal()
    execution = plan.process_executions[0]
    if damage == "counter":
        first, previous, last = execution.spawn_pipe_counter
        execution = replace(execution, spawn_pipe_counter=(first, previous, last + 1))
    elif damage == "intent":
        execution = replace(execution, spawn_io=None)
    else:
        table = execution.descriptors_after
        execution = replace(
            execution, descriptors_after=table.closed(5, observed_at=table.observed_at)
        )
    digest = state.materialization_digest()
    with pytest.raises(StateError):
        state.materialize_action_cohort(replace(plan, _process_executions=(execution,)))
    assert state.materialization_digest() == digest


@pytest.mark.parametrize(
    "kind,first",
    [("unknown", None), ("login_pipes", None), ("server_channels", True), ("standard_only", 1)],
)
def test_spawn_file_actions_reject_ambiguous_policy(kind: str, first: int | None) -> None:
    with pytest.raises(ValueError):
        MacosSpawnIO(kind, first)
