# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_exec_target,
    prepare_runtime_es_process_snapshot,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _setup


def _plan(
    state: StateManager, process: ProcessIdentity
) -> tuple[ActionCohortMaterializationPlan, MacosProcessCollectionObservation]:
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        process,
        image=process.image,
        command_line=process.command_line,
        executed_at=process.execution_started_at + timedelta(seconds=1),
        executable_version=process.executable_version,
        image_security=process.image_security,
    )
    plan = builder.seal()
    collection = MacosProcessCollectionObservation(
        after, after.execution_started_at, False, "absent"
    )
    return plan, collection


@pytest.mark.parametrize("version", [6, 9, 10])
def test_exec_target_prepares_without_mutation_and_matches_published_process(version: int) -> None:
    state, content, actor, _ = _setup()
    plan, collection = _plan(state, actor)
    before = state.materialization_digest()
    prepared = prepare_planned_runtime_es_exec_target(
        state,
        content.registry,
        cohort=plan,
        collection=collection,
        version=version,
    )
    assert state.materialization_digest() == before
    assert state.get_process_identity(actor.hostname, actor.pid) == actor
    assert (
        prepared.audit_token
        != prepare_runtime_es_process_snapshot(
            state,
            content.registry,
            process=actor,
            collection=MacosProcessCollectionObservation(
                actor, actor.execution_started_at, False, "absent"
            ),
            version=version,
        ).audit_token
    )
    state.materialize_action_cohort(plan)
    assert (
        prepare_runtime_es_process_snapshot(
            state,
            content.registry,
            process=collection.process,
            collection=collection,
            version=version,
        )
        == prepared
    )
    with pytest.raises(StateError, match="stale"):
        prepare_planned_runtime_es_exec_target(
            state, content.registry, cohort=plan, collection=collection, version=version
        )


@pytest.mark.parametrize("damage", ["foreign", "identity", "time", "before", "missing_stat"])
def test_exec_target_rejects_foreign_stale_or_incomplete_preparation(damage: str) -> None:
    state, content, actor, original = _setup()
    plan, collection = _plan(state, actor)
    if damage == "foreign":
        state = StateManager()
    elif damage == "identity":
        plan = replace(
            plan,
            _process_executions=(
                replace(
                    plan.process_executions[0],
                    after=replace(collection.process, command_line="forged"),
                ),
            ),
        )
    elif damage == "time":
        collection = replace(collection, observed_at=collection.observed_at + timedelta(seconds=1))
    elif damage == "before":
        collection = original
    else:
        from tests.unit.test_macos_launch_file import _manager

        content = _manager()
    before = state.materialization_digest()
    with pytest.raises(StateError):
        prepare_planned_runtime_es_exec_target(
            state, content.registry, cohort=plan, collection=collection, version=10
        )
    assert state.materialization_digest() == before


def test_successful_preparation_cannot_authorize_replacement_after_live_state_changes() -> None:
    state, content, actor, _ = _setup()
    plan, collection = _plan(state, actor)
    prepared = prepare_planned_runtime_es_exec_target(
        state, content.registry, cohort=plan, collection=collection, version=10
    )
    encoded = prepared.model_dump_json()
    other, _ = _plan(state, actor)
    state.materialize_action_cohort(other)
    with pytest.raises(StateError, match="stale"):
        state.materialize_action_cohort(plan)
    assert prepared.model_dump_json() == encoded


def test_planned_exec_accepts_independent_births_and_retains_explicit_absence() -> None:
    state, _, actor, _ = _setup()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        actor,
        image=actor.image,
        command_line=actor.command_line,
        executed_at=actor.execution_started_at + timedelta(seconds=1),
    )
    builder.plan_process(
        system="OTHER-MAC",
        parent_pid=0,
        image="/bin/sh",
        command_line="sh",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=actor.execution_started_at + timedelta(seconds=1),
    )
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_execution_relationships(cohort)
    assert observed.parent.process == cohort.process_executions[0].after
    assert state.materialization_digest() == before
    from tests.unit.test_macos_process_relationship_projection import _family

    bare_state, _, owner, _ = _family()
    plan, collection = _plan(bare_state, owner)
    relationships = bare_state.observe_planned_execution_relationships(plan)
    assert relationships.responsibility.reason == "absent"
    assert relationships.responsibility.responsible == collection.process


def test_exited_responsibility_fallback_uses_new_execution_not_live_before_image() -> None:
    from tests.unit.test_macos_process_relationship_projection import _family

    state, _, owner, actor = _family()
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        owner, end_time=actor.execution_started_at + timedelta(milliseconds=500)
    )
    state.materialize_action_cohort(builder.seal())
    plan, collection = _plan(state, actor)
    relationships = state.observe_planned_execution_relationships(plan)
    assert relationships.responsibility.reason == "exited"
    assert relationships.responsibility.responsible == collection.process


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_planned_exec_rejects_foreign_platform_or_unknown_relationships(platform: str) -> None:
    from tests.unit.test_process_execution_state import _process

    state, actor = _process(platform)
    plan, _ = _plan(state, actor)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="Mac execution|known relationship"):
        state.observe_planned_execution_relationships(plan)
    assert state.materialization_digest() == before
