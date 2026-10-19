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
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.formats.macos_endpoint_security import ESAction, decode_endpoint_security_record
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.actions.macos_es_fork import (
    PreparedMacosForkRecord,
    prepared_es_fork_record,
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


@dataclass
class _Fixture:
    owner: ESCollectionActionOwner
    executables: LocalArtifactVersionRegistry | DeploymentContentRegistry
    cohort: ActionCohortMaterializationPlan
    delivery: ESDeliveryPreparation
    parent: MacosProcessCollectionObservation
    child: MacosProcessCollectionObservation
    clock: MacosBootClock


def _fixture(status: str = "visible", *, fork: bool = True, installed: bool = False) -> _Fixture:
    if installed:
        from tests.unit.test_macos_installed_es_preparation import _setup as installed_setup

        state, executables, parent, _ = installed_setup()
    else:
        state, content, parent, _ = _setup()
        executables = content.registry
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    profile = owner.open(
        _profile(
            hostname=parent.hostname,
            opened_at=parent.execution_started_at,
            last_delivery_at=parent.execution_started_at,
            event_counters=(ESEventCounter(event_type=11, next_sequence=7),),
            next_global_sequence=19,
        ),
        parent,
    )
    at = parent.execution_started_at + timedelta(seconds=1)
    builder = state.begin_action_cohort_materialization()
    child = (
        builder.fork_process(parent, forked_at=at)
        if fork
        else builder.plan_process(
            system=parent.hostname,
            parent_pid=parent.pid,
            image=parent.image,
            command_line=parent.command_line,
            username=parent.principal,
            integrity_level="Medium",
            os_category="macos",
            start_time=at,
        )
    )
    cohort = builder.seal()
    token = owner.prepare(
        source_instance=profile.source_instance,
        process=parent,
        generation=profile.generation,
        delivery=0,
        occurrence_id=f"process-fork:{child.identity.object_id}",
        event_type=11,
        observed_at=at,
        decision=ObservationDecision(
            status, timedelta(seconds=3) if status == "delayed" else timedelta(0)
        ),
    )
    return _Fixture(
        owner,
        executables,
        cohort,
        token,
        MacosProcessCollectionObservation(parent, at, True, "absent"),
        MacosProcessCollectionObservation(child.identity, at, False, "absent"),
        MacosBootClock(
            parent.hostname,
            parent.started_at - timedelta(seconds=10),
            "c9c656cf-d78a-4ae6-a457-a0ff4087fced",
            MachTimebase(125, 3),
        ),
    )


def _prepare(
    fixture: _Fixture, **changes: object
) -> AbstractContextManager[PreparedMacosForkRecord]:
    from tests.unit.test_macos_runtime_file_metadata import _metadata

    return prepared_es_fork_record(
        fixture.owner,
        fixture.executables,
        **(
            dict(
                cohort=fixture.cohort,
                delivery=fixture.delivery,
                collector_process=fixture.parent.process,
                parent=fixture.parent,
                child=fixture.child,
                thread=fixture.parent.process.primary_thread,
                clock=fixture.clock,
                action=ESAction.model_validate(
                    {"result": {"result_type": 0, "result": {"auth": 0}}}
                ),
                version=10,
                installed_file=_metadata(mode=0o100755, size_bytes=8192)
                if type(fixture.executables) is DeploymentContentRegistry
                else None,
            )
            | changes
        ),
    )


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("version", [6, 10])
@pytest.mark.parametrize("status", ["visible", "delayed", "filtered", "dropped", "out_of_window"])
def test_prepared_fork_joins_exact_snapshots_counters_and_clock_without_committing(
    version: int,
    status: str,
    installed: bool,
) -> None:
    fixture = _fixture(status, installed=installed)
    state = fixture.owner.state
    before = state.materialization_digest()
    connection = fixture.owner.collectors.connection(fixture.delivery.observation.source_instance)
    with _prepare(fixture, version=version) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        assert record.seq_num == 7 and record.global_seq_num == 19
        assert record.process.is_es_client and not record.event.fork.child.is_es_client
        assert record.thread.thread_id == fixture.parent.process.primary_thread.tid
        assert record.process.executable == record.event.fork.child.executable
        assert record.mach_time == fixture.clock.ticks_at(fixture.child.observed_at)
        assert record.time == fixture.child.observed_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"
        assert record.process.audit_token != record.event.fork.child.audit_token
        assert state.materialization_digest() == before
        assert fixture.owner.collectors.connection(connection.source_instance) == connection
        assert state.get_process(fixture.child.process.hostname, fixture.child.process.pid) is None
    fixture.owner.collectors.cancel(fixture.delivery)
    assert state.materialization_digest() == before


@pytest.mark.parametrize("installed", [False, True])
def test_precommit_failure_rolls_back_state_and_leaves_no_counter_prefix(installed: bool) -> None:
    fixture = _fixture(installed=installed)
    state = fixture.owner.state
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="injected"):
        with _prepare(fixture):
            with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
                canonical.certify_composite_commit(canonical.expected_result)
                canonical.apply_provisional()
                raise RuntimeError("injected native source preparation failure")
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("installed", [False, True])
def test_frozen_bytes_survive_canonical_commit_and_collector_lost_return(installed: bool) -> None:
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
                raise RuntimeError("lost return after all canonical owners committed")
    assert (
        state.get_process_identity(fixture.child.process.hostname, fixture.child.process.pid)
        == fixture.child.process
    )
    assert (
        fixture.owner.commit(fixture.delivery, fixture.parent.process)
        == fixture.delivery.observation
    )
    assert decode_endpoint_security_record(encoded).global_seq_num == 19
    assert (
        fixture.owner.collectors.connection(
            fixture.delivery.observation.source_instance
        ).next_global_sequence
        == 20
    )
    with pytest.raises(StateError, match="reuse its retained native bytes"):
        with _prepare(fixture):
            pytest.fail("committed fork was prepared a second time")


@pytest.mark.parametrize(
    "damage",
    [
        "generic_create",
        "version",
        "time",
        "parent",
        "thread",
        "clock",
        "copied_delivery",
        "missing_file",
        "known_collector",
    ],
)
def test_inconsistent_fork_owners_reject_before_state_or_counter_changes(damage: str) -> None:
    fixture = _fixture(fork=damage != "generic_create")
    changes: dict[str, object] = {}
    if damage == "version":
        changes["version"] = 9
    elif damage == "time":
        changes["child"] = replace(
            fixture.child, observed_at=fixture.child.observed_at + timedelta(seconds=1)
        )
    elif damage == "parent":
        changes["parent"] = fixture.child
    elif damage == "thread":
        changes["thread"] = replace(fixture.parent.process.primary_thread, tid=987654)
    elif damage == "clock":
        changes["clock"] = replace(fixture.clock, hostname="another-mac")
    elif damage == "copied_delivery":
        changes["delivery"] = replace(fixture.delivery)
    elif damage == "known_collector":
        changes["parent"] = replace(fixture.parent, is_es_client=False)
    elif damage == "missing_file":
        from tests.unit.test_macos_launch_file import _manager

        fixture.executables = _manager().registry
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError):
        with _prepare(fixture, **changes):
            pytest.fail("inconsistent native preparation accepted")
    assert fixture.owner.state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("installed", [False, True])
def test_failed_native_preparation_can_retry_the_same_reserved_delivery(installed: bool) -> None:
    fixture = _fixture(installed=installed)
    with pytest.raises(StateError, match="exact fork occurrence"):
        with _prepare(fixture, clock=replace(fixture.clock, hostname="another-mac")):
            pytest.fail("foreign clock accepted")
    with _prepare(fixture) as first:
        expected = first.ndjson
    with _prepare(fixture) as retry:
        assert retry.ndjson == expected
        assert retry.collector.observation.delivery == 0
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.slow
@pytest.mark.parametrize("installed", [False, True])
def test_native_fork_bytes_are_stable_across_fresh_python_hash_seeds(installed: bool) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = """
from tests.unit.test_macos_es_fork_preparation import _fixture, _prepare
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
    assert decode_endpoint_security_record(outputs[0]).event_type == 11


@pytest.mark.parametrize("damage", ["missing_stat", "foreign_registry", "runtime_override"])
def test_fork_executable_provider_requires_complete_exact_facts(damage: str) -> None:
    from tests.unit.test_macos_runtime_file_metadata import _metadata

    fixture = _fixture(installed=damage != "runtime_override")
    changes: dict[str, object] = {}
    if damage == "missing_stat":
        changes["installed_file"] = None
    elif damage == "foreign_registry":
        fixture.executables = DeploymentContentRegistry()
    else:
        changes["installed_file"] = _metadata()
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError):
        with _prepare(fixture, **changes):
            pytest.fail("incomplete fork facts accepted")
    assert fixture.owner.state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


def test_installed_fork_bytes_detach_explicit_stat_from_caller_mutation() -> None:
    from tests.unit.test_macos_runtime_file_metadata import _metadata

    fixture = _fixture(installed=True)
    metadata = _metadata(mode=0o100755, size_bytes=8192)
    with _prepare(fixture, installed_file=metadata) as prepared:
        expected = prepared.ndjson
        object.__setattr__(metadata, "size_bytes", 1)
        assert prepared.ndjson == expected
        record = decode_endpoint_security_record(expected)
        assert record.process.executable.stat.st_size == 8192
        assert record.process.executable == record.event.fork.child.executable
    fixture.owner.collectors.cancel(fixture.delivery)
