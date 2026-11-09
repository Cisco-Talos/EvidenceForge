# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from typing import Literal

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.macos_endpoint_security import (
    prepare_installed_es_process_snapshot,
    prepare_planned_installed_es_process_snapshot,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_installed_es_preparation import _setup
from tests.unit.test_macos_runtime_file_metadata import _metadata


def _plan(
    state: StateManager, actor: ProcessIdentity, phase: Literal["birth", "exec", "terminal"]
) -> tuple[ActionCohortMaterializationPlan, MacosProcessCollectionObservation]:
    at = actor.execution_started_at + timedelta(seconds=1)
    builder = state.begin_action_cohort_materialization()
    if phase == "birth":
        subject = builder.fork_process(actor, forked_at=at).identity
    elif phase == "exec":
        subject = builder.execute_process(
            actor,
            image=actor.image,
            command_line=actor.command_line,
            executed_at=at,
            executable_version=actor.executable_version,
            image_security=actor.image_security,
        )
    else:
        builder.terminate_process(actor, end_time=at)
        subject = actor
    return builder.seal(), MacosProcessCollectionObservation(subject, at, False, "absent")


@pytest.mark.parametrize("phase", ["birth", "exec", "terminal"])
@pytest.mark.parametrize("version", [6, 9, 10])
def test_installed_transition_preparation_matches_exact_live_observation_without_mutation(
    phase: Literal["birth", "exec", "terminal"], version: int
) -> None:
    state, deployments, actor, _ = _setup()
    plan, collection = _plan(state, actor, phase)
    metadata = _metadata(mode=0o100755, size_bytes=8192, allocated_blocks=8)
    before = state.materialization_digest()
    expected = prepare_planned_installed_es_process_snapshot(
        state,
        deployments,
        cohort=plan,
        collection=collection,
        metadata=metadata,
        phase=phase,
        version=version,
    )
    assert state.materialization_digest() == before
    if phase != "terminal":
        state.materialize_action_cohort(plan)
    assert (
        prepare_installed_es_process_snapshot(
            state,
            deployments,
            process=collection.process,
            collection=collection,
            metadata=metadata,
            version=version,
        )
        == expected
    )
    assert expected.executable.stat.st_size == 8192
    assert expected.executable.stat.st_blocks == 8
    if phase == "terminal":
        state.materialize_action_cohort(plan)
    with pytest.raises(StateError, match="stale|already live"):
        prepare_planned_installed_es_process_snapshot(
            state,
            deployments,
            cohort=plan,
            collection=collection,
            metadata=metadata,
            phase=phase,
            version=version,
        )


@pytest.mark.parametrize("damage", ["deployment", "stat", "time", "subject", "phase", "foreign"])
def test_planned_installed_process_rejects_missing_or_unowned_facts(damage: str) -> None:
    state, deployments, actor, original = _setup()
    plan, collection = _plan(state, actor, "exec")
    metadata = _metadata()
    phase = "exec"
    if damage == "deployment":
        deployments = DeploymentContentRegistry()
    elif damage == "stat":
        metadata = None
    elif damage == "time":
        collection = replace(collection, observed_at=collection.observed_at + timedelta(seconds=1))
    elif damage == "subject":
        collection = original
    elif damage == "phase":
        phase = "birth"
    else:
        state = StateManager()
    before = state.materialization_digest()
    with pytest.raises(StateError):
        prepare_planned_installed_es_process_snapshot(
            state,
            deployments,
            cohort=plan,
            collection=collection,
            metadata=metadata,
            phase=phase,
            version=10,
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize("phase", [True, "exit", None])
def test_unknown_phase_is_not_inferred_from_the_plan(phase: object) -> None:
    state, deployments, actor, _ = _setup()
    plan, collection = _plan(state, actor, "exec")
    with pytest.raises(StateError, match="phase"):
        prepare_planned_installed_es_process_snapshot(
            state,
            deployments,
            cohort=plan,
            collection=collection,
            metadata=_metadata(),
            phase=phase,
            version=10,
        )
