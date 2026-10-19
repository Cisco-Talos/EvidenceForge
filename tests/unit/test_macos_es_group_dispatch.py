# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen terminal batches join exact canonical groups without enabling native output."""

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_es_exit_batch_preparation import _group
from tests.unit.test_macos_es_exit_batch_preparation import _prepare as prepare_native
from tests.unit.test_macos_exact_exit_group import _prepare, _rows


def _setup(
    tmp_path: Path, *, installed: bool = False, collected: bool = True, threaded: bool = False
) -> tuple:
    group = _group(installed=installed, born_loaded=True)
    state = group.owner.state
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.es_collectors = group.owner.collectors
    if installed:
        dispatcher.deployment_registry = group.records[0].executables
    else:
        dispatcher.local_artifact_registry = group.records[0].executables
    with prepare_native(group) as native:
        frozen = native.ndjson
    events = []
    for termination in group.cohort.process_terminations:
        identity = termination.identity
        event = process_exit_occurrence(
            host=HostContext(
                hostname=identity.hostname,
                ip="192.0.2.41",
                os="macOS 26",
                os_category="macos",
                system_type="workstation",
            ),
            process=identity,
            timestamp=termination.end_time,
            integrity_level="Medium",
        )
        event.process.exit_outcome = termination.exit_outcome
        events.append(event)
    batch = _prepare(dispatcher, group.cohort, tuple(events))
    return group, dispatcher, emitter, batch, frozen


def _bind(group: object, dispatcher: EventDispatcher, batch: object) -> None:
    dispatcher.bind_es_delivery_to_action_cohort(
        batch, delivery=group.delivery, collector_process=group.collector
    )


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("collected", [False, True])
def test_group_commits_every_counter_once_with_canonical_closure(
    tmp_path: Path, installed: bool, collected: bool
) -> None:
    group, dispatcher, emitter, batch, frozen = _setup(
        tmp_path, installed=installed, collected=collected
    )
    _bind(group, dispatcher, batch)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert group.owner.collectors.completed_batch(group.delivery) is group.delivery.observations
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    assert (
        dict(result.receipt.nested_publication_tokens)["es_collector"]
        == group.delivery._proof.hex()
    )
    assert all(
        group.owner.state.get_process(item.identity.hostname, item.identity.pid) is None
        for item in group.cohort.process_terminations
    )
    assert all(item.status == "succeeded" for item in result.projections)
    # Middle native observation is filtered, independently of canonical/source visibility.
    assert group.delivery.observations[1].status == "filtered"
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == (3 if collected else 0)
    assert not list(tmp_path.rglob("*endpoint_security*"))


@pytest.mark.parametrize("damage", ["copy", "collector", "foreign", "completed", "double"])
def test_group_binding_rejects_an_unowned_or_completed_reservation(
    tmp_path: Path, damage: str
) -> None:
    group, dispatcher, emitter, batch, _ = _setup(tmp_path)
    delivery, collector = group.delivery, group.collector
    if damage == "copy":
        delivery = replace(delivery)
    elif damage == "collector":
        collector = replace(collector, image="/different")
    elif damage == "foreign":
        dispatcher.es_collectors = ESCollectorRegistry()
    elif damage == "completed":
        group.owner.commit_batch(delivery, collector)
    else:
        _bind(group, dispatcher, batch)
    before = group.owner.state.materialization_digest()
    with pytest.raises((EventContractError, StateError)):
        dispatcher.bind_es_delivery_to_action_cohort(
            batch, delivery=delivery, collector_process=collector
        )
    assert group.owner.state.materialization_digest() == before
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    if group.owner.collectors.owns_pending_batch(group.delivery):
        group.owner.collectors.cancel_batch(group.delivery)
    emitter.close()


@pytest.mark.parametrize("damage", [False, True])
def test_group_cancellation_releases_exact_counter_owner_even_with_damaged_locator(
    tmp_path: Path, damage: bool
) -> None:
    group, dispatcher, emitter, batch, _ = _setup(tmp_path)
    _bind(group, dispatcher, batch)
    before = group.owner.state.materialization_digest()
    connection = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    if damage:
        object.__setattr__(group.delivery, "observations", ())
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert group.owner.state.materialization_digest() == before
    assert not group.owner.collectors.owns_pending_batch(group.delivery)
    assert group.owner.collectors.connection(connection.source_instance) == connection
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


def test_provisional_counter_failure_rolls_back_the_whole_terminal_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    group, dispatcher, emitter, batch, _ = _setup(tmp_path)
    _bind(group, dispatcher, batch)
    before = group.owner.state.materialization_digest()
    connection = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    original = ESCollectorRegistry._apply_claimed_batch

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        original(registry, handle)
        raise RuntimeError("injected provisional group counters")

    monkeypatch.setattr(ESCollectorRegistry, "_apply_claimed_batch", fail)
    with pytest.raises(RuntimeError, match="provisional group counters"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert group.owner.state.materialization_digest() == before
    assert group.owner.collectors.connection(connection.source_instance) == connection
    assert group.owner.collectors.completed_batch(group.delivery) is None
    assert not group.owner.collectors.owns_pending_batch(group.delivery)
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


def test_lost_group_counter_completion_acknowledgement_is_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    group, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    _bind(group, dispatcher, batch)
    original = ESCollectorRegistry._finalize_claimed_batch
    calls = 0

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        nonlocal calls
        calls += 1
        original(registry, handle)
        raise RuntimeError("injected lost group completion acknowledgement")

    monkeypatch.setattr(ESCollectorRegistry, "_finalize_claimed_batch", fail)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert calls == 1
    assert group.owner.collectors.completed_batch(group.delivery) is group.delivery.observations
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


@pytest.mark.parametrize("after_write", [False, True])
@pytest.mark.parametrize("ordinal", [1, 2, 3])
def test_partial_source_retry_never_reallocates_completed_group_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool, ordinal: int
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == ordinal:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected group source failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    group, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    _bind(group, dispatcher, batch)
    with pytest.raises(RuntimeError, match="group source failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert group.owner.collectors.completed_batch(group.delivery) is group.delivery.observations
    connection = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    version = group.owner.state.materialization_version
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert group.owner.state.materialization_version == version
    assert group.owner.collectors.connection(connection.source_instance) == connection
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    assert all(item.status == "succeeded" for item in result.projections)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


@pytest.mark.parametrize("damage", ["occurrence", "order", "plan", "missing", "unfrozen"])
def test_authenticated_but_unrelated_native_batch_cannot_join_canonical_group(
    tmp_path: Path, damage: str
) -> None:
    from datetime import timedelta

    from evidenceforge.events.es_collector import ESDeliveryRequest
    from evidenceforge.events.observation import ObservationDecision

    group, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    registry = group.owner.collectors
    observations = group.delivery.observations
    registry.cancel_batch(group.delivery)
    requests = tuple(
        ESDeliveryRequest(
            occurrence_id=item.occurrence_id,
            event_type=item.event_type,
            observed_at=item.observed_at,
            decision=ObservationDecision(item.status, timedelta(0)),
        )
        for item in observations
    )
    if damage == "occurrence":
        requests = (
            requests[0],
            requests[1].model_copy(update={"occurrence_id": "unrelated"}),
            requests[2],
        )
    elif damage == "order":
        requests = (requests[0], requests[2], requests[1])
    elif damage == "missing":
        requests = requests[:-1]
        frozen = frozen[:-1]
    group.delivery = group.owner.prepare_batch(
        source_instance=observations[0].source_instance,
        process=group.collector,
        generation=observations[0].generation,
        delivery=observations[0].delivery,
        requests=requests,
    )
    if damage != "unfrozen":
        with group.owner.prepared_batch_commit(group.delivery, group.collector) as claim:
            claim.freeze_native_projections(
                frozen,
                canonical_token="0" * 64 if damage == "plan" else group.cohort.publication_token,
            )
    before = group.owner.state.materialization_digest()
    with pytest.raises((EventContractError, StateError)):
        _bind(group, dispatcher, batch)
    assert group.owner.state.materialization_digest() == before
    assert registry.owns_pending_batch(group.delivery)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    registry.cancel_batch(group.delivery)
    emitter.close()


def test_completed_group_checkpoint_restores_counters_and_all_terminal_members(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
        DispatcherObservationParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager

    group, dispatcher, emitter, batch, _ = _setup(tmp_path, collected=False)
    _bind(group, dispatcher, batch)
    participant = DispatcherObservationParticipant(dispatcher)
    with pytest.raises(StateError, match="checkpoint"):
        participant.prepare_checkpoint(1)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    seal = participant.prepare_checkpoint(1)
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(group.owner.state))
    restored = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(seal.head.payload, ())
    assert restored.es_collectors.snapshot() == dispatcher.es_collectors.snapshot()
    assert all(
        restored_state.get_process(item.identity.hostname, item.identity.pid) is None
        for item in group.cohort.process_terminations
    )
    assert (
        restored_state.get_process_identity(group.collector.hostname, group.collector.pid)
        == group.collector
    )
    emitter.close()


def test_group_native_bytes_count_toward_existing_retention_budget(tmp_path: Path) -> None:
    group, dispatcher, emitter, batch, _ = _setup(tmp_path)
    dispatcher._action_cohort_byte_capacity = (
        dispatcher.action_cohort_publication_census().retained_bytes
    )
    with pytest.raises(EventContractError, match="retained capacity"):
        _bind(group, dispatcher, batch)
    assert group.owner.collectors.owns_pending_batch(group.delivery)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    group.owner.collectors.cancel_batch(group.delivery)
    emitter.close()


@pytest.mark.slow
@pytest.mark.parametrize("installed", [False, True])
def test_joint_group_publication_is_stable_across_processes_filters_and_threads(
    installed: bool,
) -> None:
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""
        import json, sys, tempfile
        from pathlib import Path
        from tests.unit.test_macos_es_group_dispatch import _setup, _bind
        with tempfile.TemporaryDirectory() as directory:
            group, dispatcher, emitter, batch, frozen = _setup(
                Path(directory), installed=sys.argv[1] == "True",
                collected=sys.argv[2] == "True", threaded=sys.argv[3] == "True")
            _bind(group, dispatcher, batch)
            dispatcher.publish_prepared_action_cohort_batch(batch)
            emitter.close()
            print(json.dumps({"native": frozen,
                "state": group.owner.state.materialization_digest(),
                "collectors": [item.model_dump_json() for item in group.owner.collectors.snapshot()]}, sort_keys=True))
    """)
    results: list[str] = []
    for seed, collected, threaded in (
        ("17", True, False),
        ("83", True, True),
        ("137", False, True),
    ):
        completed = subprocess.run(
            [sys.executable, "-c", script, str(installed), str(collected), str(threaded)],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(completed.stdout)
    assert len(set(results)) == 1
