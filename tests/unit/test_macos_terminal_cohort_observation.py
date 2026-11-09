# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Terminal-only observations use event-time ownership without transient State writes."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import ESProcess, decode_endpoint_security_record
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_terminal_process,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_exit_preparation import _fixture, _prepare
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_macos_runtime_es_preparation import _setup


@pytest.mark.parametrize("owner_offset", [-1, 0, 1])
@pytest.mark.parametrize("reverse", [False, True])
def test_selected_exit_observes_strictly_earlier_responsible_close_without_publication(
    owner_offset: int, reverse: bool
) -> None:
    state, _, owner, subject = _family()
    at = subject.started_at + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    rows = [(owner, at + timedelta(seconds=owner_offset)), (subject, at)]
    for identity, ended in reversed(rows) if reverse else rows:
        builder.terminate_process(identity, end_time=ended)
    cohort = builder.seal()
    before = state.materialization_digest()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    assert state.materialization_digest() == before
    assert state.get_process_identity(subject.hostname, subject.pid) == subject
    assert observed.parent.observed_at == at
    if owner_offset < 0:
        assert observed.responsibility.reason == "exited"
        assert observed.responsibility.responsible == subject
        assert observed.responsibility.responsible_exit_at == at - timedelta(seconds=1)
    else:
        assert observed.responsibility.reason == "active"
        assert observed.responsibility.responsible == owner
    state.materialize_action_cohort(cohort)
    assert not state.is_process_active_at(subject.hostname, subject.pid, at)
    # Frozen pre-close evidence survives the final State, including simultaneous exits.
    assert observed.parent.process == subject


@pytest.mark.parametrize("offset", [0, 1])
def test_parent_closing_at_or_after_selected_exit_remains_in_preclose_observation(
    offset: int,
) -> None:
    state, parent, _, subject = _family()
    at = subject.started_at + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(subject, end_time=at)
    builder.terminate_process(parent, end_time=at + timedelta(seconds=offset))
    cohort = builder.seal()
    observed = state.observe_planned_termination_relationships(cohort, process=subject)
    assert observed.parent.parent == parent
    state.materialize_action_cohort(cohort)
    assert observed.parent.parent == parent


def test_parent_closed_before_selected_exit_requires_explicit_adoption_overlay() -> None:
    state, parent, _, subject = _family()
    at = subject.started_at + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(subject, end_time=at)
    builder.terminate_process(parent, end_time=at - timedelta(seconds=1))
    before = state.materialization_digest()
    with pytest.raises(StateError, match="outlives its closing parent"):
        builder.seal()
    assert state.materialization_digest() == before


@pytest.mark.parametrize("damage", ["unselected", "changed", "foreign"])
def test_terminal_overlay_rejects_unowned_selection(
    damage: str,
) -> None:
    state, parent, owner, subject = _family()
    at = subject.started_at + timedelta(seconds=3)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(owner, end_time=at)
    builder.terminate_process(subject, end_time=at)
    cohort = builder.seal()
    if damage == "foreign":
        state = StateManager()
    selected = parent if damage == "unselected" else subject
    if damage == "changed":
        selected = replace(subject, image="/different")
    before = state.materialization_digest()
    with pytest.raises(StateError):
        state.observe_planned_termination_relationships(cohort, process=selected)
    assert state.materialization_digest() == before


def test_runtime_snapshot_matches_after_owner_checkpoint_restore_and_plan_reconstruction() -> None:
    state, content, subject, collection = _setup()
    responsible = state.get_process_identity_by_object_id(
        subject.responsibility.responsible.object_id
    )
    at = subject.execution_started_at + timedelta(seconds=3)
    collection = replace(collection, observed_at=at)

    def observe(current: StateManager) -> ESProcess:
        builder = current.begin_action_cohort_materialization()
        builder.terminate_process(responsible, end_time=at - timedelta(seconds=1))
        builder.terminate_process(subject, end_time=at)
        return prepare_planned_runtime_es_terminal_process(
            current, content.registry, cohort=builder.seal(), collection=collection, version=9
        )

    expected = observe(state)
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert observe(restored) == expected
    assert expected.responsible_audit_token == expected.audit_token


@pytest.mark.parametrize("installed", [False, True])
def test_native_exit_selects_its_own_outcome_and_freezes_the_temporal_relationships(
    installed: bool,
) -> None:
    fixture = _fixture(PosixProcessExit(exit_code=7), installed=installed)
    state = fixture.owner.state
    subject = fixture.process.process
    responsible = state.get_process_identity_by_object_id(
        subject.responsibility.responsible.object_id
    )
    at = fixture.process.observed_at
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        responsible, end_time=at - timedelta(seconds=1), exit_outcome=PosixProcessExit(signal=9)
    )
    builder.terminate_process(subject, end_time=at, exit_outcome=PosixProcessExit(exit_code=7))
    fixture.cohort = builder.seal()
    before = state.materialization_digest()
    with _prepare(fixture) as prepared:
        native = decode_endpoint_security_record(prepared.ndjson)
        assert native.process.responsible_audit_token == native.process.audit_token
        assert native.event.exit.process_exit() == PosixProcessExit(exit_code=7)
        assert native.seq_num == fixture.delivery.observation.seq_num
    assert state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


def test_native_exit_cannot_implicitly_disconnect_the_same_observing_collector() -> None:
    fixture = _fixture()
    state = fixture.owner.state
    at = fixture.process.observed_at
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(
        fixture.process.process, end_time=at, exit_outcome=PosixProcessExit(exit_code=0)
    )
    builder.terminate_process(fixture.collector, end_time=at)
    fixture.cohort = builder.seal()
    before = state.materialization_digest()
    with pytest.raises(StateError, match="observing collector"):
        with _prepare(fixture):
            pass
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.retained_native_projection(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)
