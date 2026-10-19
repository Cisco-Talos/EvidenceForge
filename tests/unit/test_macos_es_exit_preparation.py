# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESDeliveryPreparation,
    ESEventCounter,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.formats.macos_endpoint_security import ESAction, decode_endpoint_security_record
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.actions.macos_es_exit import (
    PreparedMacosExitRecord,
    prepared_es_exit_record,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MachTimebase, MacosBootClock
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_runtime_es_preparation import _setup
from tests.unit.test_macos_runtime_file_metadata import _metadata


@dataclass
class _Fixture:
    owner: ESCollectionActionOwner
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry
    cohort: ActionCohortMaterializationPlan
    delivery: ESDeliveryPreparation
    process: MacosProcessCollectionObservation
    clock: MacosBootClock
    collector: ProcessIdentity


def _fixture(
    outcome: PosixProcessExit | None = PosixProcessExit(exit_code=0),
    *,
    installed: bool = False,
    status: str = "visible",
) -> _Fixture:
    if installed:
        from tests.unit.test_macos_installed_es_preparation import _setup as installed_setup

        state, executables, process, _ = installed_setup()
    else:
        state, content, process, _ = _setup()
        executables = content.registry
    collector = state.get_process_identity(process.hostname, process.parent_pid)
    assert collector is not None
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    profile = owner.open(
        _profile(
            hostname=process.hostname,
            opened_at=process.execution_started_at,
            last_delivery_at=process.execution_started_at,
            event_counters=(ESEventCounter(event_type=15, next_sequence=7),),
            next_global_sequence=19,
        ),
        collector,
    )
    at = process.execution_started_at + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(process, end_time=at, exit_outcome=outcome)
    cohort = builder.seal()
    delivery = owner.prepare(
        source_instance=profile.source_instance,
        process=collector,
        generation=1,
        delivery=0,
        occurrence_id=f"process-exit:{process.object_id}",
        event_type=15,
        observed_at=at,
        decision=ObservationDecision(
            status, timedelta(seconds=3) if status == "delayed" else timedelta(0)
        ),
    )
    return _Fixture(
        owner,
        executables,
        cohort,
        delivery,
        MacosProcessCollectionObservation(process, at, False, "absent"),
        MacosBootClock(
            process.hostname,
            process.started_at - timedelta(seconds=10),
            "c9c656cf-d78a-4ae6-a457-a0ff4087fced",
            MachTimebase(125, 3),
        ),
        collector,
    )


def _prepare(
    fixture: _Fixture, **changes: object
) -> AbstractContextManager[PreparedMacosExitRecord]:
    return prepared_es_exit_record(
        fixture.owner,
        fixture.executables,
        **(
            dict(
                cohort=fixture.cohort,
                delivery=fixture.delivery,
                collector_process=fixture.collector,
                process=fixture.process,
                thread=fixture.process.process.primary_thread,
                clock=fixture.clock,
                action=ESAction.model_validate(
                    {"result": {"result_type": 0, "result": {"auth": 0}}}
                ),
                version=9,
                installed_file=_metadata(mode=0o100755, size_bytes=8192)
                if type(fixture.executables) is DeploymentContentRegistry
                else None,
            )
            | changes
        ),
    )


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("status", ["visible", "delayed", "filtered", "dropped", "out_of_window"])
@pytest.mark.parametrize(
    "outcome",
    [
        PosixProcessExit(exit_code=7),
        PosixProcessExit(signal=9),
        PosixProcessExit(signal=11, core_dumped=True),
    ],
)
def test_terminal_record_uses_owned_outcome_counters_and_occurrence_time_without_commit(
    installed: bool, status: str, outcome: PosixProcessExit
) -> None:
    fixture = _fixture(outcome, installed=installed, status=status)
    before = fixture.owner.state.materialization_digest()
    connection = fixture.owner.collectors.connection(fixture.delivery.observation.source_instance)
    with _prepare(fixture) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        assert record.version == 9 and record.event_type == 15
        assert record.event.exit.process_exit() == outcome
        assert record.seq_num == 7 and record.global_seq_num == 19
        assert record.thread.thread_id == fixture.process.process.primary_thread.tid
        assert record.mach_time == fixture.clock.ticks_at(fixture.process.observed_at)
        assert record.time == fixture.process.observed_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"
        assert prepared.collector.observation.status == status
        assert not record.process.is_es_client
    assert fixture.owner.state.materialization_digest() == before
    assert fixture.owner.collectors.connection(connection.source_instance) == connection
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize(
    "damage",
    [
        "version6",
        "version10",
        "unknown_outcome",
        "time",
        "thread",
        "clock",
        "collector",
        "foreign_cohort",
        "runtime_stat",
        "missing_installed_stat",
    ],
)
def test_incomplete_or_unowned_exit_facts_do_not_publish_or_consume_counters(damage: str) -> None:
    fixture = _fixture(
        None if damage == "unknown_outcome" else PosixProcessExit(exit_code=0),
        installed=damage == "missing_installed_stat",
    )
    changes: dict[str, object] = {}
    if damage.startswith("version"):
        changes["version"] = int(damage.removeprefix("version"))
    elif damage == "time":
        changes["process"] = replace(
            fixture.process, observed_at=fixture.process.observed_at + timedelta(seconds=1)
        )
    elif damage == "thread":
        changes["thread"] = replace(fixture.process.process.primary_thread, tid=987654)
    elif damage == "clock":
        changes["clock"] = replace(fixture.clock, hostname="FOREIGN")
    elif damage == "collector":
        changes["collector_process"] = fixture.process.process
    elif damage == "foreign_cohort":
        changes["cohort"] = _fixture().cohort
    elif damage == "runtime_stat":
        changes["installed_file"] = _metadata()
    elif damage == "missing_installed_stat":
        changes["installed_file"] = None
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError):
        with _prepare(fixture, **changes):
            pytest.fail("unowned terminal record admitted")
    assert fixture.owner.state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("installed", [False, True])
def test_precommit_failure_restores_live_process_and_releases_collector_claim(
    installed: bool,
) -> None:
    fixture = _fixture(installed=installed)
    state = fixture.owner.state
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="injected"):
        with _prepare(fixture):
            with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
                canonical.certify_composite_commit(canonical.expected_result)
                canonical.apply_provisional()
                raise RuntimeError("injected terminal publication failure")
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("installed", [False, True])
def test_frozen_terminal_bytes_and_counter_proof_survive_process_exit_and_lost_return(
    installed: bool,
) -> None:
    fixture = _fixture(installed=installed)
    state = fixture.owner.state
    encoded = ""
    with pytest.raises(RuntimeError, match="lost return"):
        with _prepare(fixture) as prepared:
            encoded = prepared.ndjson
            with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
                canonical.certify_composite_commit(canonical.expected_result)
                canonical.apply_provisional()
                canonical.finalize_no_fail()
                prepared.collector.commit_no_fail()
                raise RuntimeError("lost return after both owners committed")
    actor = fixture.process.process
    assert not state.is_process_active_at(actor.hostname, actor.pid, fixture.process.observed_at)
    assert fixture.owner.commit(fixture.delivery, fixture.collector) == fixture.delivery.observation
    assert (
        fixture.owner.collectors.connection(
            fixture.delivery.observation.source_instance
        ).next_global_sequence
        == 20
    )
    assert decode_endpoint_security_record(encoded).event.exit.stat == 0
    with pytest.raises(StateError, match="reuse its retained native bytes"):
        with _prepare(fixture):
            pytest.fail("exited process was re-observed")


@pytest.mark.slow
@pytest.mark.parametrize("installed", [False, True])
def test_native_exit_bytes_are_stable_across_fresh_python_hash_seeds(installed: bool) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = """
from tests.unit.test_macos_es_exit_preparation import _fixture, _prepare
fixture = _fixture()
with _prepare(fixture) as prepared:
    print(prepared.ndjson, end="")
fixture.owner.collectors.cancel(fixture.delivery)
"""
    script = script.replace("_fixture()", f"_fixture(installed={installed!r})")
    outputs: list[str] = []
    for seed in ("1", "87654"):
        outputs.append(
            subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[2],
                env=dict(os.environ, PYTHONHASHSEED=seed),
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        )
    assert outputs[0] == outputs[1]
    assert decode_endpoint_security_record(outputs[0]).event_type == 15
