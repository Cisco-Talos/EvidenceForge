# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Placement removal cannot erase loaded definitions or resurrect old files."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_definition_from_file,
    macos_system_job_deployment_identity,
)
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_file import _descriptor, _manager, _publish, _spec
from tests.unit.test_macos_launch_registration import _START, _deployments


def test_remove_prevents_new_bootstrap_and_preserves_loaded_definition() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    installation = macos_system_job_deployment_identity(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label=_spec().label,
        installation_action_id="install-worker",
    )
    loaded = macos_system_job_definition_from_file(
        runtime_content=manager,
        deployment_identity=installation,
        principal="root",
        native_path=descriptor.native_path,
    )
    assert manager.registry.withdraw_execution_path(record, _START + timedelta(seconds=1))
    assert not manager.registry.withdraw_execution_path(record, _START + timedelta(seconds=1))
    with pytest.raises(ValueError, match="current file"):
        macos_system_job_definition_from_file(
            runtime_content=manager,
            deployment_identity=installation,
            principal="root",
            native_path=descriptor.native_path,
        )
    assert loaded.program == _spec().program
    assert loaded.plist == record.artifact
    assert manager.registry.get(record.artifact.artifact_version_id) == record.artifact


def test_removal_withdraws_older_leased_versions_even_after_latest_expires() -> None:
    manager = RuntimeContentIdentityManager(
        LocalArtifactVersionRegistry(capacity=8, retention=timedelta(minutes=1))
    )
    first = _descriptor(_spec())
    _publish(manager, first)
    manager.registry.acquire_lease(
        manager.build_record(first).artifact.artifact_version_id,
        "historical-event",
        _START + timedelta(hours=1),
    )
    latest = _descriptor(_spec(), version=2)
    _publish(manager, latest)
    manager.registry.withdraw_execution_path(manager.build_record(latest), _START)
    manager.advance_watermark(_START + timedelta(minutes=2))
    assert manager.resolve_record("MAC-A", "root", latest.native_path, "macos") is None
    assert manager.registry.get(manager.build_record(first).artifact.artifact_version_id)


def test_replayed_publication_cannot_restore_removed_placement() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    manager.registry.withdraw_execution_path(manager.build_record(descriptor), _START)
    _publish(manager, descriptor)
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None


def test_new_write_is_available_but_stale_remove_cannot_delete_replacement() -> None:
    manager = _manager()
    first = _descriptor(_spec())
    _publish(manager, first)
    manager.registry.withdraw_execution_path(manager.build_record(first), _START)
    replacement = _descriptor(_spec(), version=2)
    _publish(manager, replacement)
    with pytest.raises(StateError, match="current file version"):
        manager.registry.withdraw_execution_path(manager.build_record(first), _START)
    assert manager.resolve_record(
        "MAC-A", "root", first.native_path, "macos"
    ) == manager.build_record(replacement)


@pytest.mark.parametrize(
    "changes",
    [
        {"hostname": "MAC-B"},
        {"principal": "another-user"},
        {"native_path": "/Library/LaunchDaemons/org.example.other.plist"},
    ],
)
def test_removal_is_scoped_to_exact_placement(changes: dict[str, str]) -> None:
    manager = _manager()
    first = _descriptor(_spec())
    other = replace(first, source_object_id="other-job-file", **changes)
    _publish(manager, first)
    _publish(manager, other)
    manager.registry.withdraw_execution_path(manager.build_record(first), _START)
    assert manager.resolve_record(
        other.hostname, other.principal, other.native_path, "macos"
    ) == manager.build_record(other)


def test_pending_replacement_fences_removal_until_cancelled() -> None:
    manager = _manager()
    first = _descriptor(_spec())
    _publish(manager, first)
    pending = manager.prepare_publication(_descriptor(_spec(), version=2), _START)
    with pytest.raises(StateError, match="prepared publication"):
        manager.registry.withdraw_execution_path(manager.build_record(first), _START)
    assert manager.resolve_record("MAC-A", "root", first.native_path, "macos")
    assert manager.registry.cancel_prepared(pending)
    assert manager.registry.withdraw_execution_path(manager.build_record(first), _START)


def test_withdrawal_roundtrips_checkpoint_and_existing_content_stays_historical() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    manager.registry.withdraw_execution_path(manager.build_record(descriptor), _START)
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert restored.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None
    assert restored.registry.get(manager.build_record(descriptor).artifact.artifact_version_id)
    assert not restored.registry.withdraw_execution_path(manager.build_record(descriptor), _START)


def test_schema_two_job_file_restores_as_present() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    document = loads(seal.head.payload)
    document["schema_version"] = "2"
    for row in document["records"]:
        row.pop()
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        dumps(document), ()
    )
    assert restored.resolve_record(
        "MAC-A", "root", descriptor.native_path, "macos"
    ) == manager.build_record(descriptor)


@pytest.mark.parametrize("value", [0, 1, "false", None])
def test_corrupt_placement_flag_is_rejected(value: object) -> None:
    manager = _manager()
    _publish(manager, _descriptor(_spec()))
    document = loads(
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    document["records"][0][-1] = value
    with pytest.raises(CheckpointCorruptionError, match="placement flag"):
        LocalArtifactVersionRegistryParticipant(_manager().registry).restore_checkpoint(
            dumps(document), ()
        )


def test_reused_handle_does_not_inherit_withdrawal() -> None:
    manager = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=1, shard_count=1))
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    manager.registry.withdraw_execution_path(manager.build_record(descriptor), _START)
    later = _START + timedelta(days=365)
    manager.advance_watermark(later)
    token = manager.prepare_publication(_descriptor(_spec(), version=2), later)
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit()
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")


def test_registered_job_can_activate_after_its_file_is_removed() -> None:
    from tests.unit.test_macos_launch_activation import _activation, _process, _setup

    runtime = _manager()
    state, registry, authority, adapter, job = _setup(runtime)
    plist = job.instance_identity.launchd_job.plist
    current = runtime.resolve_record(plist.hostname, plist.principal, plist.native_path, "macos")
    assert current is not None
    runtime.registry.withdraw_execution_path(current, _START)
    process = _process(state, job)
    activation = _activation(registry, authority, job, process)
    result = authority.materialize_process_service_composite(
        process, adapter.prepare_service_publication(activation)
    )
    assert result.process.ecar_object_id == process.identity.object_id
    assert registry.get_service_instance(job.instance_identity.object_id).closed_at is None
    assert (
        runtime.resolve_record(plist.hostname, plist.principal, plist.native_path, "macos") is None
    )


def test_removal_older_than_watermark_cannot_mutate_current_file() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    manager.advance_watermark(_START + timedelta(seconds=1))
    with pytest.raises(StateError, match="watermark"):
        manager.registry.withdraw_execution_path(manager.build_record(descriptor), _START)
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")


def test_removal_covers_distinct_artifact_owners_sharing_a_path() -> None:
    manager = RuntimeContentIdentityManager(
        LocalArtifactVersionRegistry(capacity=64, shard_count=8)
    )
    descriptors = [
        replace(_descriptor(_spec(), version=index + 1), source_object_id=f"install-{index}")
        for index in range(8)
    ]
    for descriptor in descriptors:
        _publish(manager, descriptor)
    manager.registry.withdraw_execution_path(manager.build_record(descriptors[-1]), _START)
    for descriptor in descriptors:
        _publish(manager, descriptor)
        assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None


def test_checkpoint_capture_rejects_noncanonical_live_placement_flags() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    shard, handle = manager.registry._existing_locator(
        manager.build_record(descriptor).artifact.artifact_version_id
    )
    shard.store._withdrawn[handle] = 2
    with pytest.raises(RuntimeError, match="placement state diverged"):
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)


@pytest.mark.parametrize("legacy_version", ["1", "2"])
def test_controller_restores_legacy_artifact_head_then_checkpoints_withdrawal(
    tmp_path: Path, legacy_version: str
) -> None:
    from evidenceforge.generation.checkpoints.participants import ParticipantSeal
    from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
    from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
    from tests.unit.test_incremental_checkpoints import _cursor
    from tests.unit.test_runtime_content import _descriptor as _ordinary_descriptor

    class LegacyParticipant(LocalArtifactVersionRegistryParticipant):
        checkpoint_schema_version = legacy_version

        def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
            seal = super().prepare_checkpoint(sequence)
            document = loads(seal.head.payload)
            for row in document["records"]:
                assert row.pop() is False
            return replace(seal, head=replace(seal.head, payload=dumps(document)))

    manager = _manager()
    descriptor = _ordinary_descriptor() if legacy_version == "1" else _descriptor(_spec())
    _publish(manager, descriptor)
    store = IncrementalCheckpointStore(tmp_path / "output")
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint="2" * 64,
        checkpoint_hours=6,
        resolved_scenario=b"schema_version: '2.0'\n",
    )
    controller.commit(cursor=_cursor(6), participants=(LegacyParticipant(manager.registry),))
    restored = _manager()
    participant = LocalArtifactVersionRegistryParticipant(restored.registry)
    controller.restore_participants(recovery=store.recover(), participants=(participant,))
    record = manager.build_record(descriptor)
    assert (
        restored.resolve_record(
            descriptor.hostname, descriptor.principal, descriptor.native_path, descriptor.platform
        )
        == record
    )
    assert restored.registry.withdraw_execution_path(record, _START)
    manifest = controller.commit(cursor=_cursor(12), participants=(participant,))
    assert manifest.participant_heads[0].schema_version == "3"
    final = _manager()
    controller.restore_participants(
        recovery=store.recover(),
        participants=(LocalArtifactVersionRegistryParticipant(final.registry),),
    )
    assert (
        final.resolve_record(
            descriptor.hostname, descriptor.principal, descriptor.native_path, descriptor.platform
        )
        is None
    )
    assert final.registry.get(record.artifact.artifact_version_id) == record.artifact
