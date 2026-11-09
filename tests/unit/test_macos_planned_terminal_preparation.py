# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_terminal_process,
    prepare_runtime_es_process_snapshot,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _setup


def _terminal(
    state: StateManager, actor: ProcessIdentity, outcome: PosixProcessExit | None = None
) -> tuple[ActionCohortMaterializationPlan, MacosProcessCollectionObservation]:
    at = actor.execution_started_at + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(actor, end_time=at, exit_outcome=outcome)
    return builder.seal(), MacosProcessCollectionObservation(actor, at, False, "absent")


@pytest.mark.parametrize("version", [6, 9, 10])
@pytest.mark.parametrize(
    "outcome", [None, PosixProcessExit(exit_code=0), PosixProcessExit(signal=9)]
)
def test_terminal_process_freezes_before_close_without_inventing_outcome(
    version: int, outcome: PosixProcessExit | None
) -> None:
    state, content, actor, _ = _setup()
    plan, collection = _terminal(state, actor, outcome)
    digest = state.materialization_digest()
    prepared = prepare_planned_runtime_es_terminal_process(
        state, content.registry, cohort=plan, collection=collection, version=version
    )
    assert prepared == prepare_runtime_es_process_snapshot(
        state, content.registry, process=actor, collection=collection, version=version
    )
    assert state.materialization_digest() == digest
    encoded = prepared.model_dump_json()
    state.materialize_action_cohort(plan)
    assert not state.is_process_active_at(actor.hostname, actor.pid, collection.observed_at)
    assert state._ended_processes_by_object_id[actor.object_id].exit_outcome == outcome
    with pytest.raises(StateError, match="live Mac"):
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=actor, collection=collection, version=version
        )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored._ended_processes_by_object_id[actor.object_id].exit_outcome == outcome
    assert prepared.model_dump_json() == encoded


@pytest.mark.parametrize("damage", ["foreign", "time", "subject", "terminal", "missing_file"])
def test_terminal_preparation_rejects_unowned_or_incomplete_facts(damage: str) -> None:
    state, content, actor, original = _setup()
    plan, collection = _terminal(state, actor)
    if damage == "foreign":
        state = StateManager()
    elif damage == "time":
        collection = replace(collection, observed_at=collection.observed_at + timedelta(seconds=1))
    elif damage == "subject":
        collection = original
    elif damage == "terminal":
        plan = replace(
            plan,
            _process_terminations=(
                replace(
                    plan.process_terminations[0],
                    end_time=collection.observed_at + timedelta(seconds=1),
                ),
            ),
        )
    else:
        from tests.unit.test_macos_launch_file import _manager

        content = _manager()
    before = state.materialization_digest()
    with pytest.raises(StateError):
        prepare_planned_runtime_es_terminal_process(
            state, content.registry, cohort=plan, collection=collection, version=10
        )
    assert state.materialization_digest() == before


def test_reexec_after_preparation_invalidates_commit_without_changing_frozen_snapshot() -> None:
    state, content, actor, _ = _setup()
    plan, collection = _terminal(state, actor)
    prepared = prepare_planned_runtime_es_terminal_process(
        state, content.registry, cohort=plan, collection=collection, version=10
    )
    encoded = prepared.model_dump_json()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        actor,
        image="/usr/bin/true",
        command_line="true",
        executed_at=actor.execution_started_at + timedelta(seconds=1),
    )
    state.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError, match="stale"):
        state.materialize_action_cohort(plan)
    with pytest.raises(StateError, match="stale"):
        prepare_planned_runtime_es_terminal_process(
            state, content.registry, cohort=plan, collection=collection, version=10
        )
    assert prepared.model_dump_json() == encoded


def test_multiple_terminations_require_an_explicit_selected_member() -> None:
    from tests.unit.test_macos_process_relationship_projection import _family

    state, _, owner, actor = _family()
    builder = state.begin_action_cohort_materialization()
    at = actor.execution_started_at + timedelta(seconds=1)
    builder.terminate_process(actor, end_time=at)
    builder.terminate_process(owner, end_time=at)
    with pytest.raises(StateError, match="exact selected termination"):
        state.observe_planned_termination_relationships(builder.seal())


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_terminal_relationships_reject_non_mac_or_unknown_owners(platform: str) -> None:
    from tests.unit.test_process_execution_state import _process

    state, actor = _process(platform)
    plan, _ = _terminal(state, actor)
    with pytest.raises(StateError, match="Mac execution|known process facts"):
        state.observe_planned_termination_relationships(plan)
