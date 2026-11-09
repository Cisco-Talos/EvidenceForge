# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESDeliveryBatchPreparation, ESDeliveryRequest
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import ESAction, decode_endpoint_security_record
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.actions.macos_es_exit import (
    MacosExitRecordInput,
    PreparedMacosExitRecords,
    prepared_es_exit_records,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MacosBootClock
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_exit_preparation import _fixture
from tests.unit.test_macos_runtime_file_metadata import _metadata


@dataclass
class _Group:
    owner: ESCollectionActionOwner
    cohort: ActionCohortMaterializationPlan
    delivery: ESDeliveryBatchPreparation
    collector: ProcessIdentity
    records: tuple[MacosExitRecordInput, ...]
    clock: MacosBootClock


def _group(
    installed: bool = False, unknown_last: bool = False, *, born_loaded: bool = False
) -> _Group:
    base = _fixture(installed=installed, born_loaded=born_loaded)
    owner = base.owner
    owner.collectors.cancel(base.delivery)
    subject = base.process.process
    builder = owner.state.begin_action_cohort_materialization()
    first = builder.fork_process(
        subject, forked_at=subject.execution_started_at + timedelta(seconds=0.5)
    )
    second = builder.fork_process(
        subject, forked_at=subject.execution_started_at + timedelta(seconds=1)
    )
    owner.state.materialize_action_cohort(builder.seal())
    at = base.process.observed_at
    selected = (
        (first.identity, at - timedelta(seconds=0.25)),
        (second.identity, at),
        (subject, at),
    )
    builder = owner.state.begin_action_cohort_materialization()
    for index, (identity, ended) in enumerate(selected):
        builder.terminate_process(
            identity,
            end_time=ended,
            exit_outcome=None if unknown_last and index == 2 else PosixProcessExit(exit_code=index),
        )
    cohort = builder.seal()
    profile = owner.collectors.connection(base.delivery.observation.source_instance)
    delivery = owner.prepare_batch(
        source_instance=profile.source_instance,
        process=base.collector,
        generation=profile.generation,
        delivery=profile.next_delivery,
        requests=tuple(
            ESDeliveryRequest(
                occurrence_id=f"process-exit:{identity.object_id}",
                event_type=15,
                observed_at=ended,
                decision=ObservationDecision("filtered" if index == 1 else "visible", timedelta(0)),
            )
            for index, (identity, ended) in enumerate(selected)
        ),
    )
    records = tuple(
        MacosExitRecordInput(
            executables=base.executables,
            process=MacosProcessCollectionObservation(identity, ended, False, "absent"),
            thread=identity.primary_thread,
            action=ESAction.model_validate({"result": {"result_type": 0, "result": {"auth": 0}}}),
            installed_file=_metadata(mode=0o100755, size_bytes=8192)
            if type(base.executables) is DeploymentContentRegistry
            else None,
        )
        for identity, ended in selected
    )
    return _Group(owner, cohort, delivery, base.collector, records, base.clock)


def _prepare(group: _Group, **changes: object) -> AbstractContextManager[PreparedMacosExitRecords]:
    return prepared_es_exit_records(
        group.owner,
        **(
            dict(
                cohort=group.cohort,
                delivery=group.delivery,
                collector_process=group.collector,
                records=group.records,
                clock=group.clock,
                version=9,
            )
            | changes
        ),
    )


@pytest.mark.parametrize("installed", [False, True])
def test_all_exit_rows_freeze_before_any_counter_or_canonical_transition(installed: bool) -> None:
    group = _group(installed)
    before = group.owner.state.materialization_digest()
    connection = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    with _prepare(group) as prepared:
        rows = tuple(decode_endpoint_security_record(line) for line in prepared.ndjson)
        assert [row.seq_num for row in rows] == [7, 8, 9]
        assert [row.global_seq_num for row in rows] == [19, 20, 21]
        assert [row.event.exit.process_exit().exit_code for row in rows] == [0, 1, 2]
        for native, canonical in zip(rows, group.records, strict=True):
            assert native.process.audit_token.pid == canonical.process.process.pid
            assert native.thread.thread_id == canonical.thread.tid
            assert native.mach_time == group.clock.ticks_at(canonical.process.observed_at)
        assert group.owner.collectors.connection(connection.source_instance) == connection
        assert group.owner.state.materialization_digest() == before
        frozen = prepared.ndjson
    assert (
        group.owner.collectors.retained_native_batch_projection(
            group.delivery, canonical_token=group.cohort.publication_token
        )
        == frozen
    )
    with _prepare(group) as prepared:
        assert prepared.ndjson == frozen
        prepared.collector.commit_no_fail()
    # Counter completion alone is explicitly not canonical publication authority.
    assert group.owner.state.materialization_digest() == before
    group.owner.state.materialize_action_cohort(group.cohort)
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    with pytest.raises(StateError, match="retained native bytes"):
        with _prepare(group):
            pass


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "duplicate",
        "reordered",
        "thread",
        "time",
        "unknown_outcome",
        "foreign_cohort",
        "version",
        "mutable_container",
    ],
)
def test_invalid_group_or_later_member_never_binds_a_native_prefix(damage: str) -> None:
    group = _group(unknown_last=damage == "unknown_outcome")
    changes: dict[str, object] = {}
    records = group.records
    if damage == "missing":
        records = records[:-1]
    elif damage == "duplicate":
        records = (records[0], records[1], records[1])
    elif damage == "reordered":
        records = tuple(reversed(records))
    elif damage == "thread":
        records = (*records[:-1], replace(records[-1], thread=records[0].thread))
    elif damage == "time":
        records = (
            *records[:-1],
            replace(
                records[-1],
                process=replace(
                    records[-1].process,
                    observed_at=records[-1].process.observed_at + timedelta(seconds=1),
                ),
            ),
        )
    elif damage == "foreign_cohort":
        changes["cohort"] = _group().cohort
    elif damage == "version":
        changes["version"] = 10
    elif damage == "mutable_container":
        changes["records"] = list(records)
    changes.setdefault("records", records)
    before = group.owner.state.materialization_digest()
    connection = group.owner.collectors.connection(group.delivery.observations[0].source_instance)
    with pytest.raises(StateError):
        with _prepare(group, **changes):
            pass
    assert group.owner.state.materialization_digest() == before
    assert group.owner.collectors.connection(connection.source_instance) == connection
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) is None
    group.owner.collectors.cancel_batch(group.delivery)


def test_native_batch_retry_cannot_change_later_record_metadata() -> None:
    group = _group()
    with _prepare(group) as prepared:
        frozen = prepared.ndjson
    action = ESAction.model_validate({"result": {"result_type": 0, "result": {"auth": 1}}})
    changed = (*group.records[:-1], replace(group.records[-1], action=action))
    with pytest.raises(StateError, match="changed for the same"):
        with _prepare(group, records=changed):
            pass
    assert group.owner.collectors.retained_native_batch_projection(group.delivery) == frozen
    group.owner.collectors.cancel_batch(group.delivery)


@pytest.mark.slow
@pytest.mark.parametrize("installed", [False, True])
def test_group_bytes_are_identical_in_fresh_processes(installed: bool) -> None:
    import os
    import subprocess
    import sys

    code = f"""
from tests.unit.test_macos_es_exit_batch_preparation import _group, _prepare
with _prepare(_group(installed={installed!r})) as prepared:
    print(''.join(prepared.ndjson), end='')
"""
    outputs = []
    for seed in ("17", "91"):
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            check=True,
            timeout=60,
        )
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
    assert len(outputs[0].splitlines()) == 3
