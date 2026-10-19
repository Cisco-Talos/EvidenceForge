# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from types import ModuleType

import pytest

from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.models.exceptions import StateError
from tests.unit import test_macos_es_exec_preparation as exec_preparation
from tests.unit import test_macos_es_exit_preparation as exit_preparation
from tests.unit.test_es_collector import _profile
from tests.unit.test_es_collector_ownership import _prepare, _setup
from tests.unit.test_process_execution_state import _START


def test_positive_lookup_is_exact_and_available_during_a_delivery_claim() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    at = _START + timedelta(seconds=5)
    with owner.prepared_commit(token, process):
        known = owner.collectors.known_connection_for_process(profile.hostname, profile.process, at)
        assert known == profile
        observation = MacosProcessCollectionObservation.from_attached_collector(
            process, known, observed_at=at, terminal="absent"
        )
        assert observation.is_es_client
        owner.validate_client_observation(observation)
        with pytest.raises(StateError, match="contradicts"):
            owner.validate_client_observation(replace(observation, is_es_client=False))
    assert owner.collectors.connection(profile.source_instance) == profile
    owner.collectors.cancel(token)


@pytest.mark.parametrize("change", ["host", "pid", "lifetime", "execution", "before"])
def test_unmatched_connection_is_unknown_instead_of_negative_membership(change: str) -> None:
    _, _, owner, profile = _setup()
    host, process, at = profile.hostname, profile.process, _START
    if change == "host":
        host = "ANOTHER-MAC"
    elif change == "pid":
        process = process.model_copy(update={"pid": process.pid + 1})
    elif change == "lifetime":
        process = process.model_copy(update={"object_id": "another-lifetime"})
    elif change == "execution":
        process = process.model_copy(update={"execution_ordinal": process.execution_ordinal + 1})
    else:
        at -= timedelta(microseconds=1)
    assert owner.collectors.known_connection_for_process(host, process, at) is None


def test_closed_epoch_preserves_its_interval_but_restart_does_not_invent_history() -> None:
    _, process, owner, profile = _setup()
    closed_at = _START + timedelta(seconds=10)
    terminal = owner.close(profile, process, closed_at)
    assert (
        owner.collectors.known_connection_for_process(profile.hostname, profile.process, _START)
        == terminal
    )
    assert (
        owner.collectors.known_connection_for_process(profile.hostname, profile.process, closed_at)
        is None
    )
    replacement = owner.open(
        profile.model_copy(
            update={
                "generation": 2,
                "opened_at": closed_at + timedelta(seconds=1),
                "last_delivery_at": closed_at + timedelta(seconds=1),
            }
        ),
        process,
    )
    assert (
        owner.collectors.known_connection_for_process(profile.hostname, profile.process, _START)
        is None
    )
    assert (
        owner.collectors.known_connection_for_process(
            profile.hostname, profile.process, replacement.opened_at
        )
        == replacement
    )


def test_multiple_sources_have_stable_positive_selection_and_no_negative_completeness_claim() -> (
    None
):
    _, process, owner, profile = _setup()
    other = owner.open(_profile(source_instance="aaa:first", hostname=profile.hostname), process)
    assert (
        owner.collectors.known_connection_for_process(profile.hostname, profile.process, _START)
        == other
    )
    terminal = owner.close(other, process, _START + timedelta(seconds=1))
    assert terminal.closed_at is not None
    assert (
        owner.collectors.known_connection_for_process(
            profile.hostname, profile.process, _START + timedelta(seconds=2)
        )
        == profile
    )
    unknown = replace(process, object_id="externally-modeled-execution", primary_thread=None)
    for membership in (True, False):
        owner.validate_client_observation(
            MacosProcessCollectionObservation(unknown, _START, membership, "absent")
        )


@pytest.mark.parametrize("module", [exec_preparation, exit_preparation])
def test_native_record_rejects_false_membership_for_another_known_client(
    module: ModuleType,
) -> None:
    fixture = module._fixture()
    observation = fixture.before if module is exec_preparation else fixture.process
    actor = observation.process
    fixture.owner.open(
        _profile(
            source_instance="other:client",
            hostname=actor.hostname,
            opened_at=actor.execution_started_at,
            last_delivery_at=actor.execution_started_at,
        ),
        actor,
    )
    before = fixture.owner.state.materialization_digest()
    connection = fixture.owner.collectors.connection(fixture.delivery.observation.source_instance)
    with pytest.raises(StateError, match="contradicts"):
        with module._prepare(fixture):
            pytest.fail("false membership was admitted")
    assert fixture.owner.state.materialization_digest() == before
    assert fixture.owner.collectors.connection(connection.source_instance) == connection
    field = "before" if module is exec_preparation else "process"
    setattr(fixture, field, replace(observation, is_es_client=True))
    with module._prepare(fixture) as prepared:
        assert '"is_es_client":true' in prepared.ndjson
    fixture.owner.collectors.cancel(fixture.delivery)
