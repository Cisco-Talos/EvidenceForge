# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Mac exits close only the clients owned by their exact executions."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_es_collector import _prepare as prepare_delivery
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_exact_exit_group import _prepare, _rows, _setup
from tests.unit.test_process_exec_projection import _START


def _bound(tmp_path: Path, *, collected: bool = True) -> tuple:
    state, dispatcher, emitter, plan, events, members = _setup(tmp_path, collected=collected)
    owner = ESCollectionActionOwner(state, dispatcher.es_collectors)
    profiles = tuple(
        owner.open(
            _profile(
                source_instance=f"invented-client-{index}",
                hostname=member.hostname,
                opened_at=member.started_at,
                last_delivery_at=member.started_at,
            ),
            member,
        )
        for index, member in enumerate(members[:2])
    )
    return state, dispatcher, emitter, plan, events, members, owner, profiles


@pytest.mark.parametrize("collected", [False, True])
def test_group_exit_closes_all_exact_member_clients_without_counter_allocation(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, plan, events, members, owner, profiles = _bound(
        tmp_path, collected=collected
    )
    batch = _prepare(dispatcher, plan, events)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert "es_closures" in dict(result.receipt.nested_publication_tokens)
    for profile in profiles:
        after = owner.collectors.connection(profile.source_instance)
        assert after.closed_at == plan.process_terminations[0].end_time
        assert after.next_delivery == profile.next_delivery
        assert after.next_global_sequence == profile.next_global_sequence
    assert all(state.get_process(member.hostname, member.pid) is None for member in members)
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == (3 if collected else 0)


def test_cancelled_exit_does_not_disconnect_any_client(tmp_path: Path) -> None:
    state, dispatcher, emitter, plan, events, _, owner, _ = _bound(tmp_path)
    before = owner.collectors.snapshot()
    digest = state.materialization_digest()
    assert dispatcher.cancel_prepared_action_cohort_batch(_prepare(dispatcher, plan, events))
    assert owner.collectors.snapshot() == before
    assert state.materialization_digest() == digest
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


def test_provisional_disconnect_failure_rolls_back_processes_and_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, plan, events, _, owner, _ = _bound(tmp_path)
    before = owner.collectors.snapshot()
    digest = state.materialization_digest()
    batch = _prepare(dispatcher, plan, events)
    original = ESCollectorRegistry._apply_closures

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        original(registry, handle)
        raise RuntimeError("injected disconnect application failure")

    monkeypatch.setattr(ESCollectorRegistry, "_apply_closures", fail)
    with pytest.raises(RuntimeError, match="disconnect application failure"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert owner.collectors.snapshot() == before
    assert state.materialization_digest() == digest
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


def test_lost_disconnect_completion_acknowledgement_is_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, dispatcher, emitter, plan, events, _, owner, profiles = _bound(tmp_path)
    batch = _prepare(dispatcher, plan, events)
    original = ESCollectorRegistry._finalize_closures
    calls = 0

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        nonlocal calls
        calls += 1
        original(registry, handle)
        raise RuntimeError("injected lost disconnect completion")

    monkeypatch.setattr(ESCollectorRegistry, "_finalize_closures", fail)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert calls == 1
    assert all(
        owner.collectors.connection(profile.source_instance).closed_at is not None
        for profile in profiles
    )
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


@pytest.mark.parametrize("change", ["pending", "delivered", "new_client"])
def test_changed_client_set_requires_replanning_before_process_exit(
    tmp_path: Path, change: str
) -> None:
    state, dispatcher, emitter, plan, events, members, owner, profiles = _bound(tmp_path)
    before = state.materialization_digest()
    batch = _prepare(dispatcher, plan, events)
    delivery = None
    if change == "new_client":
        owner.open(
            _profile(
                source_instance="late-client",
                hostname=members[2].hostname,
                opened_at=members[2].started_at,
                last_delivery_at=members[2].started_at,
            ),
            members[2],
        )
    else:
        delivery = prepare_delivery(
            owner.collectors,
            source_instance=profiles[0].source_instance,
            observed_at=_START + timedelta(seconds=5),
        )
        if change == "delivered":
            owner.collectors.commit(delivery)
    with pytest.raises((StateError, EventContractError)):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.materialization_digest() == before
    if change == "pending":
        assert owner.collectors.owns_pending_delivery(delivery)
        owner.collectors.cancel(delivery)
    assert all(item.closed_at is None for item in owner.collectors.snapshot())
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


@pytest.mark.parametrize("collect", [False, True])
def test_ordinary_process_exit_closes_client_and_keeps_surviving_child_live(
    tmp_path: Path, collect: bool
) -> None:
    from tests.unit.test_macos_ordinary_exit import _close
    from tests.unit.test_macos_ordinary_exit import _setup as ordinary_setup

    fixture = ordinary_setup(tmp_path, collect=collect)
    _, state, registry, _, dispatcher, emitter, _, _, _, child, descendant = fixture
    owner = ESCollectionActionOwner(state, dispatcher.es_collectors)
    profile = owner.open(
        _profile(
            hostname=child.hostname, opened_at=child.started_at, last_delivery_at=child.started_at
        ),
        child,
    )
    _close(fixture, child, 5)
    closed = owner.collectors.connection(profile.source_instance)
    assert closed.closed_at == registry.get_process(child.object_id).closed_at
    assert closed.next_global_sequence == profile.next_global_sequence
    assert state.get_process_identity_by_object_id(descendant.object_id).parent_pid == 1
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()


@pytest.mark.parametrize("after_write", [False, True])
def test_source_recovery_preserves_terminal_connections_without_reclosing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected source row failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    state, dispatcher, emitter, plan, events, _, owner, _ = _bound(tmp_path)
    batch = _prepare(dispatcher, plan, events)
    with pytest.raises(RuntimeError, match="source row failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    connections = owner.collectors.snapshot()
    assert all(item.closed_at is not None for item in connections)
    version = state.materialization_version
    dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert state.materialization_version == version
    assert owner.collectors.snapshot() == connections
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


def test_closed_process_and_collector_profiles_restore_together(tmp_path: Path) -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
        DispatcherObservationParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager

    state, dispatcher, emitter, plan, events, members, owner, _ = _bound(tmp_path, collected=False)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, events))
    checkpoint = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(state))
    restored = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(checkpoint.head.payload, ())
    assert restored.es_collectors.snapshot() == owner.collectors.snapshot()
    assert all(item.closed_at is not None for item in restored.es_collectors.snapshot())
    assert all(
        restored_state.get_process(member.hostname, member.pid) is None for member in members
    )
    emitter.close()


def test_exit_preserves_unrelated_and_unknown_owner_connections(tmp_path: Path) -> None:
    state, dispatcher, emitter, plan, events, _, owner, profiles = _bound(tmp_path)
    unrelated = _profile(source_instance="unrelated", hostname="OTHER-MAC")
    unknown = _profile(source_instance="unknown-owner", hostname=profiles[0].hostname)
    owner.collectors.open(unrelated)
    owner.collectors.open(unknown)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, events))
    assert owner.collectors.connection(unrelated.source_instance) == unrelated
    assert owner.collectors.connection(unknown.source_instance) == unknown
    assert all(
        owner.collectors.connection(item.source_instance).closed_at is not None for item in profiles
    )
    emitter.close()


def test_source_preparation_failure_releases_retained_disconnect_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, plan, events, _, owner, _ = _bound(tmp_path)
    before = owner.collectors.snapshot()
    digest = state.materialization_digest()

    def fail(*args: object) -> None:
        raise RuntimeError("injected source preparation failure")

    monkeypatch.setattr(dispatcher, "_prepare_action_cohort_exact_projection", fail)
    with pytest.raises(RuntimeError, match="source preparation failure"):
        _prepare(dispatcher, plan, events)
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    assert state.materialization_digest() == digest
    assert owner.collectors.snapshot() == before
    emitter.close()


def test_disconnect_requests_respect_existing_aggregate_retention_budget(tmp_path: Path) -> None:
    state, dispatcher, emitter, plan, events, _, owner, _ = _bound(tmp_path)
    batch = _prepare(dispatcher, plan, events)
    retained = dispatcher.action_cohort_publication_census().retained_bytes
    requests, _ = owner.process_exit_closures(plan)
    size = sum(len(item.model_dump_json().encode("utf-8")) for item in requests)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    dispatcher._action_cohort_byte_capacity = retained - size
    before = owner.collectors.snapshot()
    digest = state.materialization_digest()
    with pytest.raises(EventContractError, match="retained"):
        _prepare(dispatcher, plan, events)
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    assert state.materialization_digest() == digest
    assert owner.collectors.snapshot() == before
    emitter.close()


def test_observer_counters_and_other_client_disconnect_share_one_group_transaction(
    tmp_path: Path,
) -> None:
    from dataclasses import replace

    from tests.unit.test_macos_es_exit_batch_preparation import _group
    from tests.unit.test_macos_es_group_dispatch import _bind
    from tests.unit.test_macos_es_group_dispatch import _setup as native_setup

    group = _group(born_loaded=True)
    record = group.records[0]
    subject = record.process.process
    profile = group.owner.open(
        _profile(
            source_instance="terminal-client",
            hostname=subject.hostname,
            opened_at=subject.started_at,
            last_delivery_at=subject.started_at,
        ),
        subject,
    )
    group.records = (
        replace(record, process=replace(record.process, is_es_client=True)),
        *group.records[1:],
    )
    group, dispatcher, emitter, batch, frozen = native_setup(tmp_path, native_group=group)
    _bind(group, dispatcher, batch)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert {"es_closures", "es_collector"} <= dict(result.receipt.nested_publication_tokens).keys()
    assert (
        group.owner.collectors.connection(profile.source_instance).closed_at
        == record.process.observed_at
    )
    observer = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    assert observer.closed_at is None and observer.next_delivery == 3
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


@pytest.mark.slow
def test_process_owned_disconnects_are_stable_across_fresh_processes_and_filtering() -> None:
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""
        import json, sys, tempfile
        from pathlib import Path
        from tests.unit.test_macos_process_collector_exit import _bound
        from tests.unit.test_macos_exact_exit_group import _prepare
        with tempfile.TemporaryDirectory() as directory:
            state, dispatcher, emitter, plan, events, members, owner, profiles = _bound(
                Path(directory), collected=sys.argv[1] == 'True')
            dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, events))
            emitter.close()
            print(json.dumps({'state': state.materialization_digest(),
                'clients': [item.model_dump_json() for item in owner.collectors.snapshot()]}, sort_keys=True))
    """)
    results: list[str] = []
    for seed, collected in (("7", True), ("31", False)):
        result = subprocess.run(
            [sys.executable, "-c", script, str(collected)],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(result.stdout)
    assert results[0] == results[1]
