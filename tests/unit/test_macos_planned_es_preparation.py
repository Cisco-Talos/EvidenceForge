# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_process_snapshot,
    prepare_runtime_es_process_snapshot,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _setup
from tests.unit.test_process_responsibility import _exec


@pytest.mark.parametrize("version", [6, 9, 10])
def test_fork_snapshot_preflights_without_publication_and_matches_committed_state(
    version: int,
) -> None:
    state, content, parent, _ = _setup()
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        parent, forked_at=parent.execution_started_at + timedelta(seconds=1)
    )
    cohort = builder.seal()
    collection = MacosProcessCollectionObservation(
        child.identity, child.identity.started_at, False, "absent"
    )
    prepared = prepare_planned_runtime_es_process_snapshot(
        state, content.registry, cohort=cohort, collection=collection, version=version
    )
    assert state.materialization_digest() == before
    assert state.get_process(child.identity.hostname, child.identity.pid) is None
    state.materialize_action_cohort(cohort)
    assert (
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=child.identity, collection=collection, version=version
        )
        == prepared
    )
    with pytest.raises(StateError, match="stale|already live"):
        prepare_planned_runtime_es_process_snapshot(
            state, content.registry, cohort=cohort, collection=collection, version=version
        )


@pytest.mark.parametrize("damage", ["identity", "parent", "foreign"])
def test_modified_or_foreign_plan_is_not_observation_authority(damage: str) -> None:
    state, content, parent, _ = _setup()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        parent, forked_at=parent.execution_started_at + timedelta(seconds=1)
    )
    cohort = builder.seal()
    if damage == "identity":
        child = replace(child, _identity=replace(child.identity, image="/usr/bin/false"))
    elif damage == "parent":
        child = replace(child, _payload=replace(child._payload, parent_identity=None))
    else:
        state = StateManager()
    cohort = replace(cohort, _processes=(child,))
    collection = MacosProcessCollectionObservation(
        child.identity, child.identity.started_at, False, "absent"
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="integrity|semantic identity"):
        prepare_planned_runtime_es_process_snapshot(
            state, content.registry, cohort=cohort, collection=collection, version=10
        )
    assert state.materialization_digest() == before


def test_successful_preparation_does_not_authorize_commit_after_parent_exec() -> None:
    state, content, parent, _ = _setup()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        parent, forked_at=parent.execution_started_at + timedelta(seconds=2)
    )
    cohort = builder.seal()
    collection = MacosProcessCollectionObservation(
        child.identity, child.identity.started_at, False, "absent"
    )
    prepared = prepare_planned_runtime_es_process_snapshot(
        state, content.registry, cohort=cohort, collection=collection, version=10
    )
    encoded = prepared.model_dump_json()
    _exec(state, parent, 6)
    with pytest.raises(StateError, match="stale"):
        prepare_planned_runtime_es_process_snapshot(
            state, content.registry, cohort=cohort, collection=collection, version=10
        )
    assert prepared.model_dump_json() == encoded
    assert state.get_process(child.identity.hostname, child.identity.pid) is None


@pytest.mark.parametrize("damage", ["subject", "time", "stat"])
def test_preflight_rejects_incomplete_or_different_birth_without_child_allocation(
    damage: str,
) -> None:
    state, content, parent, observation = _setup()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(
        parent, forked_at=parent.execution_started_at + timedelta(seconds=1)
    )
    cohort = builder.seal()
    collection = MacosProcessCollectionObservation(
        child.identity, child.identity.started_at, False, "absent"
    )
    if damage == "subject":
        collection = observation
    elif damage == "time":
        collection = replace(collection, observed_at=collection.observed_at + timedelta(seconds=1))
    else:
        from tests.unit.test_macos_launch_file import _manager

        content = _manager()
    before = state.materialization_digest()
    with pytest.raises(StateError, match="birth observation|retained executable"):
        prepare_planned_runtime_es_process_snapshot(
            state, content.registry, cohort=cohort, collection=collection, version=10
        )
    assert state.materialization_digest() == before


def test_staged_parent_cannot_be_treated_as_already_live() -> None:
    state, _, parent, _ = _setup()
    builder = state.begin_action_cohort_materialization()
    first = builder.fork_process(
        parent, forked_at=parent.execution_started_at + timedelta(seconds=1)
    )
    builder.plan_process(
        system=parent.hostname,
        parent_pid=first.identity.pid,
        parent_plan=first,
        image=parent.image,
        command_line=parent.command_line,
        username=parent.principal,
        integrity_level="System",
        os_category="macos",
        start_time=first.identity.started_at,
        credentials=parent.credentials,
        responsibility=parent.responsibility,
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="single-start cohort"):
        state.observe_planned_process_relationships(builder.seal())
    assert state.materialization_digest() == before


@pytest.mark.parametrize("responsibility", ["absent", "exited", "unknown"])
def test_planned_responsibility_uses_known_absence_and_retained_exit_proof(
    responsibility: str,
) -> None:
    from evidenceforge.events.responsibility import ProcessResponsibility
    from tests.unit.test_posix_job_control import _close

    state, _, parent, _ = _setup()
    if responsibility == "exited":
        owner = state.get_process_identity_by_object_id(parent.responsibility.responsible.object_id)
        _close(state, owner, 6)
    elif responsibility == "absent":
        # Launch a new explicit owner; do not rewrite the existing process in place.
        builder = state.begin_action_cohort_materialization()
        known = builder.plan_process(
            system=parent.hostname,
            parent_pid=parent.pid,
            image=parent.image,
            command_line=parent.command_line,
            username=parent.principal,
            integrity_level="System",
            os_category="macos",
            start_time=parent.execution_started_at + timedelta(seconds=1),
            credentials=parent.credentials,
            responsibility=ProcessResponsibility(None),
        )
        state.materialize_action_cohort(builder.seal())
        parent = known.identity
    else:
        parent = state.get_process_identity(parent.hostname, parent.parent_pid)
        assert parent.responsibility is None
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=parent.started_at + timedelta(seconds=10))
    cohort = builder.seal()
    before = state.materialization_digest()
    if responsibility == "unknown":
        with pytest.raises(StateError, match="known process facts"):
            state.observe_planned_process_relationships(cohort)
    else:
        captured = state.observe_planned_process_relationships(cohort)
        assert captured.responsibility.reason == responsibility
        assert captured.responsibility.responsible == child.identity
        state.materialize_action_cohort(cohort)
        assert (
            state.observe_process_relationships(
                child.identity, observed_at=child.identity.started_at
            )
            == captured
        )
        return
    assert state.materialization_digest() == before


def test_linux_start_cannot_be_prepared_as_native_mac_metadata() -> None:
    from tests.unit.test_posix_job_control import _START

    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    builder.plan_process(
        system="test-linux",
        parent_pid=0,
        image="/usr/bin/test-helper",
        command_line="test-helper",
        username="root",
        integrity_level="System",
        os_category="linux",
    )
    before = state.materialization_digest()
    with pytest.raises(StateError, match="modeled Mac"):
        state.observe_planned_process_relationships(builder.seal())
    assert state.materialization_digest() == before
