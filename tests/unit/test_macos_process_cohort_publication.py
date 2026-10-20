# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented mixed native cohorts exercise canonical and source recovery together."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import ESCollectorRegistry, ESDeliveryRequest, ESEventCounter
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.macos_endpoint_security import ESAction
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.macos_es_exit import MacosExitRecordInput
from evidenceforge.generation.actions.macos_es_process_batch import (
    MacosExecRecordInput,
    MacosForkRecordInput,
    prepared_es_process_records,
)
from evidenceforge.generation.actions.posix_process import (
    process_exec_occurrence,
    process_exit_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.macos_es_native_sink import create_es_native_sink
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_es_exec_preparation import _fixture
from tests.unit.test_macos_native_sink_publication import _prepare


def _setup(
    tmp_path: Path, *, retire: bool = False, collected: bool = True, filtered: bool = False
) -> tuple:
    fixture = _fixture(born_loaded=True)
    owner = fixture.owner
    owner.collectors.cancel(fixture.delivery)
    owner.collectors = ESCollectorRegistry()
    state = owner.state
    parent = fixture.before.process
    at = fixture.before.observed_at
    profile = _profile(
        hostname=parent.hostname,
        opened_at=parent.started_at,
        last_delivery_at=parent.started_at,
        event_counters=tuple(
            ESEventCounter(event_type=kind, next_sequence=0) for kind in (9, 11, 15)
        ),
    )
    owner.initialize_inventory(
        ESClientMembershipCoverage(
            hostname=parent.hostname,
            known_from=parent.started_at,
            known_until=at + timedelta(hours=1),
        ),
        ((profile, fixture.collector),),
    )
    builder = state.begin_action_cohort_materialization()
    birth = builder.fork_process(parent, forked_at=at)
    original = fixture.cohort.process_executions[0].after
    after = builder.execute_process(
        birth,
        image=original.image,
        command_line=original.command_line,
        executed_at=at + timedelta(seconds=1),
        arguments=original.arguments,
        environment=original.environment,
        image_security=original.image_security,
        exec_script=original.exec_script,
        exec_image=original.exec_image,
        execution_directory=replace(
            original.execution_directory, observed_at=at + timedelta(seconds=1)
        ),
        executable_version=original.executable_version,
    )
    end = at + timedelta(seconds=2)
    builder.terminate_process(after, end_time=end, exit_outcome=PosixProcessExit(exit_code=0))
    collector_after = None
    if retire:
        collector_after = builder.execute_process(
            fixture.collector,
            image="/usr/bin/invented-replacement",
            command_line="invented-replacement",
            executed_at=end + timedelta(seconds=1),
        )
    cohort = builder.seal()
    action = ESAction.model_validate({"result": {"result_type": 0, "result": {"auth": 0}}})
    before_observation = MacosProcessCollectionObservation(
        birth.identity, at + timedelta(seconds=1), False, "absent"
    )
    after_observation = replace(before_observation, process=after)
    records = (
        MacosForkRecordInput(
            fixture.artifacts,
            replace(fixture.before, observed_at=at),
            replace(before_observation, observed_at=at),
            parent.primary_thread,
            action,
            6,
        ),
        MacosExecRecordInput(
            fixture.artifacts,
            before_observation,
            after_observation,
            replace(fixture.descriptors, table=cohort.process_executions[0].descriptors_after),
            birth.identity.primary_thread,
            action,
            9,
        ),
        MacosExitRecordInput(
            fixture.artifacts,
            replace(after_observation, observed_at=end),
            after.primary_thread,
            action,
        ),
    )
    requests = tuple(
        ESDeliveryRequest(
            occurrence_id=occurrence_id,
            event_type=kind,
            observed_at=when,
            decision=ObservationDecision("filtered" if filtered else "visible"),
        )
        for occurrence_id, kind, when in (
            (f"process-fork:{birth.identity.object_id}", 11, at),
            (f"process-exec:{after.execution_id}", 9, at + timedelta(seconds=1)),
            (f"process-exit:{after.object_id}", 15, end),
        )
    )
    delivery = owner.prepare_batch(
        source_instance=profile.source_instance,
        process=fixture.collector,
        generation=1,
        delivery=0,
        requests=requests,
    )
    with prepared_es_process_records(
        owner,
        cohort=cohort,
        delivery=delivery,
        collector_process=fixture.collector,
        records=records,
        clock=fixture.clock,
    ) as prepared:
        frozen = prepared.ndjson
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.local_artifact_registry = fixture.artifacts
    dispatcher.es_collectors = owner.collectors
    host = HostContext(
        hostname=parent.hostname,
        ip="192.0.2.41",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    events = [
        process_fork_occurrence(
            host=host, parent=parent, child=birth.identity, integrity_level="Medium"
        ),
        process_exec_occurrence(
            host=host, before=birth.identity, after=after, integrity_level="Medium"
        ),
        process_exit_occurrence(host=host, process=after, timestamp=end, integrity_level="Medium"),
    ]
    events[2].process.exit_outcome = PosixProcessExit(exit_code=0)
    if collector_after is not None:
        events.append(
            process_exec_occurrence(
                host=host,
                before=fixture.collector,
                after=collector_after,
                integrity_level=state.get_process(
                    fixture.collector.hostname, fixture.collector.pid
                ).integrity_level,
            )
        )
    token = fixture.artifacts.prepare_version_retention(
        parent.executable_version.artifact_version_id,
        observed_at=at,
        retained_until=end + timedelta(days=10),
        lease_owner="invented-ordered-chain",
    )
    sink = create_es_native_sink(tmp_path / "native.ndjson")
    batch = _prepare(
        dispatcher,
        cohort,
        tuple(events),
        root=f"macos-process-cohort:{cohort.semantic_id}",
        es_delivery=delivery,
        es_collector_process=fixture.collector,
        es_native_sink=sink,
        artifact_publications=(token,),
    )
    return owner, dispatcher, emitter, sink, batch, delivery, frozen, after, cohort


@pytest.mark.parametrize("retire", [False, True])
@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_mixed_native_processes_and_collector_retirement_publish_once(
    tmp_path: Path, retire: bool, collected: bool, filtered: bool
) -> None:
    owner, dispatcher, emitter, sink, batch, delivery, frozen, after, cohort = _setup(
        tmp_path, retire=retire, collected=collected, filtered=filtered
    )
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert len(result.projections) == (4 if retire else 3)
    assert owner.collectors.completed_batch(delivery) == delivery.observations
    profile = owner.collectors.connection(delivery.observations[0].source_instance)
    assert profile.next_delivery == 3
    assert profile.closed_at == (
        cohort.process_executions[-1].after.execution_started_at if retire else None
    )
    assert owner.state.get_process(after.hostname, after.pid) is None
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    sink.close()
    lines = sink.output_path.read_text().splitlines() if sink.output_path.exists() else []
    assert lines == ([] if filtered else [line.rstrip("\n") for line in frozen])
    assert [json.loads(line)["event_type"] for line in lines] == ([] if filtered else [11, 9, 15])


@pytest.mark.parametrize("owner_step", ["counter", "closure"])
def test_canonical_failure_rolls_back_chain_counter_closure_and_artifact_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner_step: str
) -> None:
    owner, dispatcher, emitter, sink, batch, delivery, _, _, _ = _setup(tmp_path, retire=True)
    before = owner.state.materialization_digest()
    profile = owner.collectors.connection(delivery.observations[0].source_instance)
    name = "_apply_claimed_batch" if owner_step == "counter" else "_apply_closures"
    original = getattr(ESCollectorRegistry, name)

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        original(registry, handle)
        raise RuntimeError("invented combined owner failure")

    with monkeypatch.context() as patch:
        patch.setattr(ESCollectorRegistry, name, fail)
        with pytest.raises(RuntimeError, match="combined owner failure"):
            dispatcher.publish_prepared_action_cohort_batch(batch)
    assert owner.state.materialization_digest() == before
    assert owner.collectors.connection(profile.source_instance) == profile
    assert owner.collectors.completed_batch(delivery) is None
    assert not owner.collectors.authenticates_pending_batch(delivery)
    assert dispatcher.local_artifact_registry.census().prepared_publications == 0
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    assert sink.exact_journal_census().admitted_rows == 0
    emitter.close()
    sink.close()
    assert not sink.output_path.exists() or sink.output_path.read_bytes() == b""


@pytest.mark.parametrize("row", [1, 2, 3])
@pytest.mark.parametrize("after_write", [False, True])
@pytest.mark.parametrize("restart", [False, True])
def test_native_prefix_recovers_with_terminal_collector_and_exact_frozen_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: int, after_write: bool, restart: bool
) -> None:
    original = ExternalSortedLineWriter._commit_exact_row
    calls = 0
    sink = None

    def fail(writer: ExternalSortedLineWriter, key: tuple, digest: str, content: object) -> None:
        nonlocal calls
        if writer is sink:
            calls += 1
            if calls == row:
                if after_write:
                    original(writer, key, digest, content)
                raise RuntimeError("invented native prefix failure")
        original(writer, key, digest, content)

    with monkeypatch.context() as patch:
        patch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
        owner, dispatcher, emitter, sink, batch, delivery, frozen, _, _ = _setup(
            tmp_path, retire=True
        )
        with pytest.raises(RuntimeError, match="native prefix failure") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
        version = owner.state.materialization_version
        profile = owner.collectors.connection(delivery.observations[0].source_instance)
        assert profile.next_delivery == 3 and profile.closed_at is not None
        assert owner.collectors.completed_batch(delivery) == delivery.observations
        if restart:
            replacement = owner.state.get_process_identity(profile.hostname, profile.process.pid)
            opened = profile.closed_at + timedelta(seconds=1)
            profile = owner.open(
                _profile(
                    hostname=profile.hostname,
                    generation=2,
                    opened_at=opened,
                    last_delivery_at=opened,
                ),
                replacement,
            )
            assert owner.collectors.completed_batch(delivery) == delivery.observations
        result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
        assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
        assert owner.state.materialization_version == version
        assert owner.collectors.connection(profile.source_instance) == profile
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    sink.close()
    assert sink.output_path.read_text() == "".join(frozen)
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == 4


@pytest.mark.slow
def test_mixed_native_publication_is_deterministic_in_fresh_processes(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    script = """
import hashlib, json, sys
from pathlib import Path
from tests.unit.test_macos_process_cohort_publication import _setup
root = Path(sys.argv[1])
owner, dispatcher, emitter, sink, batch, delivery, frozen, after, cohort = _setup(root, retire=True)
dispatcher.publish_prepared_action_cohort_batch(batch)
dispatcher.assert_exact_projection_recoveries_drained()
emitter.close()
sink.close()
paths = [*root.rglob("ecar.json"), sink.output_path]
print(json.dumps({str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}, sort_keys=True))
"""
    results = []
    for index, seed in enumerate(("1", "98765")):
        output = tmp_path / str(index)
        output.mkdir()
        result = subprocess.run(
            [sys.executable, "-c", script, str(output)],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            check=True,
            capture_output=True,
            text=True,
        )
        results.append(json.loads(result.stdout))
    assert results[0] == results[1] and len(results[0]) == 2
