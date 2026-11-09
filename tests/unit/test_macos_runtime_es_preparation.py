# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_endpoint_security import prepare_runtime_es_process_snapshot
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_file import _manager
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_macos_runtime_file_metadata import _executable


def _publish(
    content: RuntimeContentIdentityManager, descriptor: RuntimeArtifactDescriptor, at: datetime
) -> None:
    token = content.prepare_publication(descriptor, at)
    with content.registry.prepared_publication(token) as prepared:
        prepared.commit()


def _setup(
    *, born_loaded: bool = False
) -> tuple[
    StateManager, RuntimeContentIdentityManager, ProcessIdentity, MacosProcessCollectionObservation
]:
    state, _, _, process = _family()
    content = _manager()
    descriptor = replace(_executable(), hostname=process.hostname)
    _publish(content, descriptor, process.started_at)
    record = content.build_record(descriptor)
    builder = state.begin_action_cohort_materialization()
    if born_loaded:
        # Integrated lifecycle tests start with a loaded birth; the default below
        # deliberately exercises low-level executable replacement without dispatch.
        loaded = builder.plan_process(
            system=process.hostname,
            parent_pid=process.parent_pid,
            image=record.artifact.native_path,
            command_line="invented-worker",
            username=process.principal,
            integrity_level="Medium",
            os_category="macos",
            start_time=process.started_at + timedelta(seconds=1),
            credentials=process.credentials,
            responsibility=process.responsibility,
            executable_version=ProcessExecutableVersion.from_binary(record.binary),
            image_security=MacosImageSecurity(7, False, 3),
        )
        process = loaded.identity
    else:
        process = builder.execute_process(
            process,
            image=record.artifact.native_path,
            command_line="invented-worker",
            executed_at=process.started_at + timedelta(seconds=1),
            executable_version=ProcessExecutableVersion.from_binary(record.binary),
            image_security=MacosImageSecurity(7, False, 3),
        )
    state.materialize_action_cohort(builder.seal())
    collection = MacosProcessCollectionObservation(
        process, process.execution_started_at, False, "absent"
    )
    return state, content, process, collection


@pytest.mark.parametrize("version", [6, 9, 10])
def test_runtime_provider_joins_owned_facts_without_allocating_or_using_current_path(
    version: int,
) -> None:
    state, content, process, collection = _setup()
    before = state.materialization_digest()
    first = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=collection, version=version
    )
    assert state.materialization_digest() == before
    _publish(
        content,
        replace(
            _executable(),
            hostname=process.hostname,
            content_version=2,
            artifact_version=2,
            macos_file=None,
        ),
        collection.observed_at + timedelta(seconds=1),
    )
    # A newer path has incomplete stat and different content; the loaded version remains exact.
    second = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=collection, version=version
    )
    assert first == second
    assert first.executable.stat.st_ino == 735
    assert first.is_es_client is False and first.tty is None


def test_state_and_artifact_checkpoint_restore_preserves_the_same_complete_snapshot() -> None:
    state, content, process, collection = _setup()
    expected = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=collection, version=10
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    participant = LocalArtifactVersionRegistryParticipant(content.registry)
    seal = participant.prepare_checkpoint(1)
    new_content = _manager()
    LocalArtifactVersionRegistryParticipant(new_content.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert (
        prepare_runtime_es_process_snapshot(
            restored, new_content.registry, process=process, collection=collection, version=10
        )
        == expected
    )


def test_a_later_exec_cannot_reacquire_the_previous_snapshot_but_frozen_output_survives() -> None:
    state, content, process, collection = _setup()
    expected = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=collection, version=10
    )
    encoded = expected.model_dump_json()
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        process,
        image="/usr/bin/true",
        command_line="true",
        executed_at=collection.observed_at + timedelta(seconds=1),
    )
    state.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError, match="live Mac execution"):
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=process, collection=collection, version=10
        )
    assert expected.model_dump_json() == encoded


def test_missing_exact_version_does_not_fall_back_to_any_other_file() -> None:
    state, _, process, collection = _setup()
    empty = _manager()
    _publish(
        empty,
        replace(_executable(), hostname=process.hostname, content_version=2, artifact_version=2),
        collection.observed_at + timedelta(seconds=1),
    )
    with pytest.raises(StateError, match="exact retained executable"):
        prepare_runtime_es_process_snapshot(
            state, empty.registry, process=process, collection=collection, version=10
        )


def test_explicit_client_fact_is_preserved_and_another_execution_observation_is_rejected() -> None:
    state, content, process, collection = _setup()
    client = replace(collection, is_es_client=True)
    assert prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=client, version=10
    ).is_es_client
    other = state.get_process_identity(process.hostname, process.parent_pid)
    with pytest.raises(StateError, match="live Mac execution"):
        prepare_runtime_es_process_snapshot(
            state,
            content.registry,
            process=process,
            collection=replace(collection, process=other),
            version=10,
        )


def test_missing_stat_or_signing_remains_an_explicit_preparation_failure() -> None:
    state, content, process, collection = _setup()
    # Use the retained canonical version with omitted stat; no byte/hash facts change.
    incomplete = _manager()
    _publish(
        incomplete,
        replace(_executable(), hostname=process.hostname, macos_file=None),
        process.started_at,
    )
    with pytest.raises(StateError, match="Incomplete ES runtime process facts"):
        prepare_runtime_es_process_snapshot(
            state, incomplete.registry, process=process, collection=collection, version=10
        )


def test_exited_lifetime_cannot_be_reacquired_for_preparation() -> None:
    state, content, process, collection = _setup()
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(process, end_time=collection.observed_at + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    with pytest.raises(StateError, match="live Mac execution"):
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=process, collection=collection, version=10
        )
    assert state.materialization_digest() == before


def test_current_path_cannot_fill_an_unknown_execution_version() -> None:
    state, content, process, collection = _setup()
    builder = state.begin_action_cohort_materialization()
    unknown = builder.execute_process(
        process,
        image=process.image,
        command_line=process.command_line,
        executed_at=collection.observed_at + timedelta(seconds=1),
    )
    state.materialize_action_cohort(builder.seal())
    observation = MacosProcessCollectionObservation(
        unknown, unknown.execution_started_at, False, "absent"
    )
    with pytest.raises(StateError, match="known runtime executable version"):
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=unknown, collection=observation, version=10
        )
