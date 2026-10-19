# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import shlex
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    SoftwareInstallationIdentity,
)
from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESDeliveryPreparation,
    ESEventCounter,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
from evidenceforge.events.macos_exec_descriptors import (
    MacosExecDescriptorObservation,
    MacosNativeDescriptor,
)
from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.formats.macos_endpoint_security import ESAction, decode_endpoint_security_record
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.actions.macos_es_exec import (
    PreparedMacosExecRecord,
    prepared_es_exec_record,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from evidenceforge.generation.timing.macos import MachTimebase, MacosBootClock
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_exec_script import _script
from tests.unit.test_macos_execution_directory import _directory
from tests.unit.test_macos_runtime_es_preparation import _publish, _setup
from tests.unit.test_macos_runtime_file_metadata import _executable, _metadata


@dataclass
class _Fixture:
    owner: ESCollectionActionOwner
    artifacts: LocalArtifactVersionRegistry
    cohort: ActionCohortMaterializationPlan
    delivery: ESDeliveryPreparation
    before: MacosProcessCollectionObservation
    after: MacosProcessCollectionObservation
    descriptors: MacosExecDescriptorObservation
    clock: MacosBootClock
    collector: ProcessIdentity
    deployments: DeploymentContentRegistry | None = None


def _fixture(
    *,
    script: bool = False,
    status: str = "visible",
    missing: str | None = None,
    providers: str = "rr",
) -> _Fixture:
    state, content, actor, _ = _setup()
    runtime_version = actor.executable_version
    deployments = None
    installed_version = None
    if "i" in providers:
        descriptor = _executable()
        binary = BinaryReleaseIdentity(
            BinaryReleaseKey(
                "invented-worker", "1.0", "test-build", "arm64", "macos", "invented-worker"
            ),
            code_signature=descriptor.code_signature,
            mach_o_image=descriptor.mach_o_image,
        )
        deployments = DeploymentContentRegistry(
            binary_releases=(binary,),
            installations=(
                SoftwareInstallationIdentity(
                    hostname=actor.hostname,
                    application_id="invented-worker",
                    release_id=binary.release_id,
                    platform="macos",
                    scope="machine",
                    image_paths=(actor.image,),
                ),
            ),
        )
        installed_version = ProcessExecutableVersion.from_binary(binary)
    if providers[0] == "i":
        builder = state.begin_action_cohort_materialization()
        actor = builder.execute_process(
            actor,
            image=actor.image,
            command_line=actor.command_line,
            executed_at=actor.execution_started_at + timedelta(seconds=1),
            executable_version=installed_version,
            image_security=actor.image_security,
        )
        state.materialize_action_cohort(builder.seal())
    collector = state.get_process_identity(actor.hostname, actor.parent_pid)
    assert collector is not None
    at = actor.execution_started_at + timedelta(seconds=2)
    table = MacosDescriptorTable(
        actor.hostname,
        at - timedelta(seconds=1),
        (
            MacosDescriptorBinding(0, "file", "invented-open-vnode", False),
            MacosDescriptorBinding(1, "file", "invented-open-vnode", False),
            MacosDescriptorBinding(8, "pipe", "invented-open-pipe", False),
            MacosDescriptorBinding(9, "file", "invented-close-on-exec", True),
        ),
    )
    if missing != "table":
        builder = state.begin_action_cohort_materialization()
        builder.record_macos_descriptors(actor, table=table)
        state.materialize_action_cohort(builder.seal())
    reference = MacosExecScript()
    if script:
        descriptor, record = _script(content, actor.hostname)
        _publish(content, descriptor, actor.execution_started_at)
        reference = MacosExecScript.from_runtime_record(record)
    argv = (actor.image, "--label", "invented spaced label", "")
    values = dict(
        image=actor.image,
        command_line=shlex.join(argv),
        executed_at=at,
        executable_version=installed_version if providers[1] == "i" else runtime_version,
        image_security=actor.image_security,
        arguments=argv,
        environment=("LANG=C", "EMPTY="),
        exec_image=MacosExecImage(0, "./invented-worker"),
        exec_script=reference,
        execution_directory=replace(_directory(), hostname=actor.hostname, observed_at=at),
    )
    if missing in values:
        values[missing] = None
    builder = state.begin_action_cohort_materialization()
    target = builder.execute_process(actor, **values)
    cohort = builder.seal()
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    profile = owner.open(
        _profile(
            hostname=actor.hostname,
            opened_at=actor.execution_started_at,
            last_delivery_at=actor.execution_started_at,
            event_counters=(ESEventCounter(event_type=9, next_sequence=7),),
            next_global_sequence=19,
        ),
        collector,
    )
    delivery = owner.prepare(
        source_instance=profile.source_instance,
        process=collector,
        generation=1,
        delivery=0,
        occurrence_id=f"process-exec:{target.execution_id}",
        event_type=9,
        observed_at=at,
        decision=ObservationDecision(
            status, timedelta(seconds=3) if status == "delayed" else timedelta(0)
        ),
    )
    return _Fixture(
        owner,
        content.registry,
        cohort,
        delivery,
        MacosProcessCollectionObservation(actor, at, False, "absent"),
        MacosProcessCollectionObservation(target, at, False, "absent"),
        MacosExecDescriptorObservation(
            table.after_exec(at),
            (
                MacosNativeDescriptor(0, "invented-open-vnode", 1),
                MacosNativeDescriptor(1, "invented-open-vnode", 1),
                MacosNativeDescriptor(8, "invented-open-pipe", 6, 735),
            ),
            17,
        ),
        MacosBootClock(
            actor.hostname,
            actor.started_at - timedelta(seconds=10),
            "c9c656cf-d78a-4ae6-a457-a0ff4087fced",
            MachTimebase(125, 3),
        ),
        collector,
        deployments,
    )


def _prepare(
    fixture: _Fixture, **changes: object
) -> AbstractContextManager[PreparedMacosExecRecord]:
    return prepared_es_exec_record(
        fixture.owner,
        fixture.artifacts,
        **(
            dict(
                cohort=fixture.cohort,
                delivery=fixture.delivery,
                collector_process=fixture.collector,
                before=fixture.before,
                after=fixture.after,
                descriptors=fixture.descriptors,
                thread=fixture.before.process.primary_thread,
                clock=fixture.clock,
                action=ESAction.model_validate(
                    {"result": {"result_type": 0, "result": {"auth": 0}}}
                ),
                version=9,
                deployments=fixture.deployments,
                before_installed_file=_metadata(mode=0o100755, size_bytes=8192)
                if fixture.before.process.executable_version.identity_kind == "installed_release"
                else None,
                after_installed_file=_metadata(mode=0o100755, size_bytes=8192)
                if fixture.after.process.executable_version.identity_kind == "installed_release"
                else None,
            )
            | changes
        ),
    )


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("script", [False, True])
@pytest.mark.parametrize("status", ["visible", "delayed", "filtered", "dropped", "out_of_window"])
def test_exec_freezes_exact_occurrence_facts_without_mutation(
    version: int, script: bool, status: str
) -> None:
    fixture = _fixture(script=script, status=status)
    state = fixture.owner.state
    before = state.materialization_digest()
    connection = fixture.owner.collectors.connection(fixture.delivery.observation.source_instance)
    with _prepare(fixture, version=version) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        execution = record.event.exec
        assert record.version == version and record.event_type == 9
        assert record.seq_num == 7 and record.global_seq_num == 19
        assert record.process.audit_token.pid == execution.target.audit_token.pid
        assert record.process.audit_token.pidversion != execution.target.audit_token.pidversion
        assert execution.args == fixture.after.process.arguments
        assert execution.env == ("LANG=C", "EMPTY=")
        assert (execution.script is not None) == script
        assert execution.cwd.path == fixture.after.process.execution_directory.native_path
        assert [item.fd for item in execution.fds] == [0, 1, 8]
        assert execution.fds[-1].pipe.pipe_id == 735
        assert execution.last_fd == 17  # Explicit native field, not max(fd) or table length.
        assert execution.image_cputype == 0x0100000C
        assert execution.image_cpusubtype == 0
        assert ("dyld_exec_path" in execution.model_fields_set) == (version == 9)
        assert record.thread.thread_id == fixture.before.process.primary_thread.tid
        assert record.thread.thread_id != fixture.after.process.primary_thread.tid
        assert record.mach_time == fixture.clock.ticks_at(fixture.after.observed_at)
        assert prepared.collector.observation.status == status
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.connection(connection.source_instance) == connection
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize(
    "missing",
    ["arguments", "environment", "execution_directory", "exec_image", "exec_script", "table"],
)
def test_unknown_exec_metadata_is_not_filled_from_defaults(missing: str) -> None:
    fixture = _fixture(missing=missing)
    before = fixture.owner.state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        with _prepare(fixture):
            pytest.fail("incomplete exec was admitted")
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize(
    "damage", ["version", "time", "thread", "clock", "fd_binding", "foreign_cohort"]
)
def test_foreign_or_inconsistent_exec_observation_rejects_without_commit(damage: str) -> None:
    fixture = _fixture()
    changes: dict[str, object] = {}
    if damage == "version":
        changes["version"] = 10
    elif damage == "time":
        changes["before"] = replace(
            fixture.before, observed_at=fixture.before.observed_at + timedelta(seconds=1)
        )
    elif damage == "thread":
        changes["thread"] = fixture.after.process.primary_thread
    elif damage == "clock":
        changes["clock"] = replace(fixture.clock, hostname="OTHER-MAC")
    elif damage == "fd_binding":
        altered = replace(
            fixture.descriptors.table, observed_at=fixture.after.observed_at + timedelta(seconds=1)
        )
        changes["descriptors"] = replace(fixture.descriptors, table=altered)
    else:
        changes["cohort"] = _fixture().cohort
    before = fixture.owner.state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        with _prepare(fixture, **changes):
            pytest.fail("unowned exec was admitted")
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


def test_prepared_bytes_survive_provisional_rollback_and_completed_delivery_retries() -> None:
    fixture = _fixture(script=True)
    state = fixture.owner.state
    before = state.materialization_digest()
    with _prepare(fixture) as first:
        expected = first.ndjson
        with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
            canonical.certify_composite_commit(canonical.expected_result)
            canonical.apply_provisional()
            assert (
                state.get_process_identity(
                    fixture.after.process.hostname, fixture.after.process.pid
                )
                == fixture.after.process
            )
    assert state.materialization_digest() == before
    with _prepare(fixture) as retry:
        assert retry.ndjson == expected
        state.materialize_action_cohort(fixture.cohort)
        retry.collector.commit_no_fail()
    assert fixture.owner.commit(fixture.delivery, fixture.collector) == fixture.delivery.observation
    with pytest.raises(StateError, match="retained native bytes"):
        with _prepare(fixture):
            pytest.fail("completed delivery was rebuilt")
    assert decode_endpoint_security_record(expected).event.exec.script is not None


@pytest.mark.parametrize(
    "damage", ["missing", "duplicate", "order", "object", "kind", "tag", "pipe", "bool", "last"]
)
def test_native_fd_observation_rejects_incomplete_or_conflicting_facts(damage: str) -> None:
    fixture = _fixture()
    observation = fixture.descriptors
    rows = observation.descriptors
    changes: dict[str, object] = {}
    with pytest.raises(ValueError):
        if damage == "missing":
            changes["descriptors"] = rows[:-1]
        elif damage == "duplicate":
            changes["descriptors"] = rows + (rows[-1],)
        elif damage == "order":
            changes["descriptors"] = tuple(reversed(rows))
        elif damage == "object":
            changes["descriptors"] = (replace(rows[0], object_id="foreign"), *rows[1:])
        elif damage == "kind":
            changes["descriptors"] = (replace(rows[0], fdtype=6, pipe_id=1), *rows[1:])
        elif damage == "tag":
            changes["descriptors"] = (replace(rows[0], fdtype=2), *rows[1:])
        elif damage == "pipe":
            changes["descriptors"] = (*rows[:-1], replace(rows[-1], pipe_id=None))
        elif damage == "bool":
            changes["descriptors"] = (replace(rows[0], fd=True), *rows[1:])
        else:
            changes["last_fd"] = None
        replace(observation, **changes)
    fixture.owner.collectors.cancel(fixture.delivery)


def test_known_empty_descriptors_preserve_explicit_native_field() -> None:
    fixture = _fixture()
    empty = replace(fixture.descriptors.table, bindings=())
    observation = MacosExecDescriptorObservation(empty, (), -1)
    assert observation.descriptors == () and observation.last_fd == -1
    fixture.owner.collectors.cancel(fixture.delivery)


def test_pipe_observations_preserve_shared_objects_without_conflating_pipe_endpoints() -> None:
    fixture = _fixture()
    table = replace(
        fixture.descriptors.table,
        bindings=(
            MacosDescriptorBinding(3, "pipe", "read-object", False),
            MacosDescriptorBinding(4, "pipe", "read-object", False),
            MacosDescriptorBinding(5, "pipe", "write-object", False),
        ),
    )
    rows = (
        MacosNativeDescriptor(3, "read-object", 6, 12345),
        MacosNativeDescriptor(4, "read-object", 6, 12345),
        MacosNativeDescriptor(5, "write-object", 6, 12345),
    )
    observation = MacosExecDescriptorObservation(table, rows, 8)
    assert observation.descriptors[-1].object_id != observation.descriptors[0].object_id
    with pytest.raises(ValueError, match="conflicting"):
        replace(observation, descriptors=(rows[0], replace(rows[1], pipe_id=999), rows[2]))
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.slow
@pytest.mark.parametrize("providers", ["rr", "ii", "ir", "ri"])
def test_historical_exec_preparation_is_stable_across_fresh_python_hash_seeds(
    providers: str,
) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = """
from tests.unit.test_macos_es_exec_preparation import _fixture, _prepare
fixture = _fixture(script=True)
with _prepare(fixture) as prepared:
    print(prepared.ndjson, end="")
fixture.owner.collectors.cancel(fixture.delivery)
"""
    script = script.replace(
        "_fixture(script=True)", f"_fixture(script=True, providers={providers!r})"
    )
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
    assert decode_endpoint_security_record(outputs[0]).event_type == 9


@pytest.mark.parametrize("providers", ["ii", "ir", "ri"])
@pytest.mark.parametrize("script", [False, True])
def test_installed_and_runtime_exec_images_keep_their_own_providers(
    providers: str, script: bool
) -> None:
    fixture = _fixture(providers=providers, script=script)
    before = fixture.owner.state.materialization_digest()
    with _prepare(fixture) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        assert record.process.executable.stat.st_size == (8192 if providers[0] == "i" else 512)
        assert record.event.exec.target.executable.stat.st_size == (
            8192 if providers[1] == "i" else 512
        )
        assert (record.event.exec.script is not None) == script
        assert (
            record.process.audit_token.pidversion != record.event.exec.target.audit_token.pidversion
        )
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize(
    "damage", ["before_stat", "after_stat", "deployments", "empty_deployments", "runtime_stat"]
)
def test_installed_exec_does_not_borrow_runtime_or_missing_deployment_facts(damage: str) -> None:
    fixture = _fixture(providers="ii" if damage != "runtime_stat" else "rr")
    changes: dict[str, object] = {}
    if damage == "before_stat":
        changes["before_installed_file"] = None
    elif damage == "after_stat":
        changes["after_installed_file"] = None
    elif damage == "deployments":
        changes["deployments"] = None
    elif damage == "empty_deployments":
        changes["deployments"] = DeploymentContentRegistry()
    else:
        changes["before_installed_file"] = _metadata()
    before = fixture.owner.state.materialization_digest()
    with pytest.raises((StateError, ValueError)):
        with _prepare(fixture, **changes):
            pytest.fail("incomplete image provider was admitted")
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("providers", ["rr", "ii", "ir", "ri"])
def test_recovered_owners_rebuild_the_same_exec_bytes_with_new_canonical_authority(
    providers: str,
) -> None:
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager
    from tests.unit.test_macos_runtime_file_metadata import _manager

    fixture = _fixture(script=True, providers=providers)
    with _prepare(fixture) as initial:
        expected = initial.ndjson
    fixture.owner.collectors.cancel(fixture.delivery)
    state = StateManager()
    _restore_head(state, _capture_head(fixture.owner.state))
    content = _manager()
    seal = LocalArtifactVersionRegistryParticipant(fixture.artifacts).prepare_checkpoint(1)
    LocalArtifactVersionRegistryParticipant(content.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    collectors = ESCollectorRegistry()
    collectors.restore(fixture.owner.collectors.snapshot())
    owner = ESCollectionActionOwner(state, collectors)
    actor = state.get_process_identity(fixture.before.process.hostname, fixture.before.process.pid)
    target = fixture.after.process
    builder = state.begin_action_cohort_materialization()
    recovered_target = builder.execute_process(
        actor,
        image=target.image,
        command_line=target.command_line,
        executed_at=target.execution_started_at,
        executable_version=target.executable_version,
        image_security=target.image_security,
        arguments=target.arguments,
        environment=target.environment,
        execution_directory=target.execution_directory,
        exec_image=target.exec_image,
        exec_script=target.exec_script,
    )
    assert recovered_target == target
    delivery = owner.prepare(
        source_instance=fixture.delivery.observation.source_instance,
        process=fixture.collector,
        generation=1,
        delivery=0,
        occurrence_id=f"process-exec:{target.execution_id}",
        event_type=9,
        observed_at=target.execution_started_at,
        decision=ObservationDecision("visible"),
    )
    recovered = replace(fixture, owner=owner, artifacts=content.registry, delivery=delivery)
    with pytest.raises(StateError):
        with _prepare(recovered):
            pytest.fail("foreign pre-recovery cohort authorized publication")
    recovered.cohort = builder.seal()
    with _prepare(recovered) as native:
        assert native.ndjson == expected
    collectors.cancel(delivery)


def test_successful_exec_cannot_render_a_denied_authorization_result() -> None:
    fixture = _fixture()
    denied = ESAction.model_validate({"result": {"result_type": 0, "result": {"auth": 1}}})
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError, match="denied authorization"):
        with _prepare(fixture, action=denied):
            pytest.fail("successful exec carried a denial result")
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


def test_pending_exec_retry_cannot_replace_previously_frozen_native_metadata() -> None:
    fixture = _fixture()
    original = fixture.descriptors
    with _prepare(fixture) as first:
        expected = first.ndjson
    fixture.descriptors = replace(original, last_fd=original.last_fd + 1)
    with pytest.raises(StateError, match="native projection"):
        with _prepare(fixture):
            pytest.fail("one reserved delivery acquired different native bytes")
    fixture.descriptors = original
    with _prepare(fixture) as retry:
        assert retry.ndjson == expected
    fixture.owner.collectors.cancel(fixture.delivery)
