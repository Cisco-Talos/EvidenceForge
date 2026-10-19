# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    SoftwareInstallationIdentity,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.macos_endpoint_security import prepare_installed_es_process_snapshot
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _setup as _runtime
from tests.unit.test_macos_runtime_file_metadata import _executable, _metadata


def _setup(
    *, born_loaded: bool = False
) -> tuple[
    StateManager, DeploymentContentRegistry, ProcessIdentity, MacosProcessCollectionObservation
]:
    state, _, process, _ = _runtime(born_loaded=born_loaded)
    descriptor = _executable()
    binary = BinaryReleaseIdentity(
        BinaryReleaseKey(
            "invented-worker", "1.0", "test-build", "arm64", "macos", "invented-worker"
        ),
        code_signature=descriptor.code_signature,
        mach_o_image=descriptor.mach_o_image,
    )
    installation = SoftwareInstallationIdentity(
        hostname=process.hostname,
        application_id="invented-worker",
        release_id=binary.release_id,
        platform="macos",
        scope="machine",
        image_paths=(process.image,),
    )
    deployments = DeploymentContentRegistry(
        binary_releases=(binary,),
        installations=(installation,),
    )
    builder = state.begin_action_cohort_materialization()
    if born_loaded:
        process = builder.plan_process(
            system=process.hostname,
            parent_pid=process.parent_pid,
            image=process.image,
            command_line=process.command_line,
            username=process.principal,
            integrity_level="Medium",
            os_category="macos",
            start_time=process.execution_started_at + timedelta(seconds=1),
            credentials=process.credentials,
            responsibility=process.responsibility,
            executable_version=ProcessExecutableVersion.from_binary(binary),
            image_security=process.image_security,
        ).identity
    else:
        process = builder.execute_process(
            process,
            image=process.image,
            command_line=process.command_line,
            executed_at=process.execution_started_at + timedelta(seconds=1),
            executable_version=ProcessExecutableVersion.from_binary(binary),
            image_security=process.image_security,
        )
    state.materialize_action_cohort(builder.seal())
    collection = MacosProcessCollectionObservation(
        process, process.execution_started_at, False, "absent"
    )
    return state, deployments, process, collection


@pytest.mark.parametrize("version", [6, 9, 10])
def test_installed_snapshot_joins_deployment_stat_and_runtime_without_mutation(
    version: int,
) -> None:
    state, deployments, process, collection = _setup()
    stat = _metadata(mode=0o100755, size_bytes=8192, allocated_blocks=8)
    before = state.materialization_digest()
    snapshot = prepare_installed_es_process_snapshot(
        state, deployments, process=process, collection=collection, metadata=stat, version=version
    )
    assert state.materialization_digest() == before
    assert snapshot.executable.path == process.image
    assert snapshot.executable.stat.st_size == 8192
    assert snapshot.executable.stat.st_blocks == 8  # Explicit allocation, not inferred from size.
    assert snapshot.executable.stat.st_ino == stat.inode
    assert snapshot.cdhash == _executable().code_signature.cdhash.lower()
    assert snapshot.tty is None and snapshot.is_es_client is False
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert (
        prepare_installed_es_process_snapshot(
            restored,
            deployments,
            process=process,
            collection=collection,
            metadata=stat,
            version=version,
        )
        == snapshot
    )


@pytest.mark.parametrize("damage", ["missing_deployment", "wrong_version", "stale_process", "stat"])
def test_installed_snapshot_rejects_incomplete_or_stale_owners(damage: str) -> None:
    state, deployments, process, collection = _setup()
    stat = _metadata()
    if damage == "missing_deployment":
        deployments = DeploymentContentRegistry()
    elif damage == "wrong_version":
        process = replace(
            process,
            executable_version=replace(process.executable_version, content_id="another-release"),
        )
        collection = replace(collection, process=process)
    elif damage == "stale_process":
        builder = state.begin_action_cohort_materialization()
        builder.execute_process(
            process,
            image=process.image,
            command_line=process.command_line,
            executed_at=collection.observed_at + timedelta(seconds=1),
        )
        state.materialize_action_cohort(builder.seal())
    else:
        stat = None
    before = state.materialization_digest()
    with pytest.raises(StateError, match="exact|Incomplete"):
        prepare_installed_es_process_snapshot(
            state, deployments, process=process, collection=collection, metadata=stat, version=10
        )
    assert state.materialization_digest() == before
