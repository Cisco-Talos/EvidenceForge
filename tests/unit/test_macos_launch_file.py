# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical file versions retain bounded job semantics without plist artifacts."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
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
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)
from evidenceforge.utils.rng import generation_seed_scope
from tests.unit.test_macos_launch_registration import _START, _deployments
from tests.unit.test_runtime_content import _descriptor as _windows_descriptor


def _spec() -> LaunchdSystemJobSpec:
    return LaunchdSystemJobSpec(
        label="org.example.worker",
        program="/usr/local/libexec/worker",
        arguments=("worker", "--quiet"),
        principal="root",
    )


def _descriptor(spec: LaunchdSystemJobSpec, version: int = 1) -> RuntimeArtifactDescriptor:
    return RuntimeArtifactDescriptor(
        hostname="MAC-A",
        principal="root",
        platform="macos",
        user_profile_id="system:root",
        application_profile_id="runtime-files",
        application_id="runtime-filesystem",
        family="launchd-definition",
        source_object_id="invented-worker-plist",
        native_path="/Library/LaunchDaemons/org.example.worker.plist",
        file_object_id="invented-worker-plist",
        content_version=version,
        artifact_version=version,
        size_bytes=512,
        mime_type="application/xml",
        seed_ref=spec.content_seed,
        launchd_job=spec,
    )


def _manager() -> RuntimeContentIdentityManager:
    return RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=8))


def _publish(manager: RuntimeContentIdentityManager, descriptor: RuntimeArtifactDescriptor) -> None:
    token = manager.prepare_publication(descriptor, _START)
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit()


def test_file_spec_is_owned_by_record_and_bootstrap_reads_current_version() -> None:
    manager = _manager()
    spec = _spec()
    descriptor = _descriptor(spec)
    _publish(manager, descriptor)
    installation = macos_system_job_deployment_identity(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label=spec.label,
        installation_action_id="install-worker",
    )
    first = macos_system_job_definition_from_file(
        runtime_content=manager,
        deployment_identity=installation,
        principal="root",
        native_path=descriptor.native_path,
    )
    assert first.program == spec.program
    assert first.arguments == spec.arguments
    updated = LaunchdSystemJobSpec(
        **(spec.model_dump() | {"program": "/usr/local/libexec/new-worker"})
    )
    _publish(manager, _descriptor(updated, version=2))
    second = macos_system_job_definition_from_file(
        runtime_content=manager,
        deployment_identity=installation,
        principal="root",
        native_path=descriptor.native_path,
    )
    assert second.program == updated.program
    assert first.program == spec.program
    assert first.plist.artifact_version_id != second.plist.artifact_version_id
    assert first.plist.content_id != second.plist.content_id


def test_spec_and_loaded_identity_do_not_change_with_ambient_generation_seed() -> None:
    manager = _manager()
    spec = _spec()
    with generation_seed_scope(71):
        _publish(manager, _descriptor(spec))
        installation = macos_system_job_deployment_identity(
            deployment_registry=_deployments(),
            hostname="MAC-A",
            label=spec.label,
            installation_action_id="install-worker",
        )
        loaded = macos_system_job_definition_from_file(
            runtime_content=manager,
            deployment_identity=installation,
            principal="root",
            native_path=_descriptor(spec).native_path,
        )
        key = loaded.logical_service_id
        content = spec.content_seed
    assert loaded.logical_service_id == key
    assert spec.content_seed == content
    assert type(loaded).model_validate_json(loaded.model_dump_json()) == loaded


@pytest.mark.parametrize(
    "changes",
    [
        {"platform": "linux"},
        {"seed_ref": "wrong-semantics"},
        {"executable": True, "architecture": "arm64"},
    ],
)
def test_wrong_content_or_file_kind_is_rejected_before_publication(
    changes: dict[str, object],
) -> None:
    manager = _manager()
    with pytest.raises(ValueError, match="launchd"):
        manager.prepare_publication(replace(_descriptor(_spec()), **changes), _START)
    assert manager.census().live_versions == 0


def test_mutating_caller_spec_does_not_change_published_canonical_file() -> None:
    manager = _manager()
    spec = _spec()
    descriptor = _descriptor(spec)
    _publish(manager, descriptor)
    object.__setattr__(spec, "program", "/bin/sh")
    record = manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")
    assert record.launchd_job.program == "/usr/local/libexec/worker"


def test_tampered_public_view_cannot_replace_reserved_canonical_job() -> None:
    manager = _manager()
    token = manager.prepare_publication(_descriptor(_spec()), _START)
    object.__setattr__(token.record.launchd_job, "program", "/bin/sh")
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit()
    record = manager.resolve_record("MAC-A", "root", _descriptor(_spec()).native_path, "macos")
    assert record.launchd_job == _spec()


def test_job_file_metadata_roundtrips_artifact_checkpoint_without_external_sidecar() -> None:
    manager = _manager()
    _publish(manager, _descriptor(_spec()))
    participant = LocalArtifactVersionRegistryParticipant(manager.registry)
    seal = participant.prepare_checkpoint(1)
    assert seal.head.schema_version == "6"
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert restored.resolve_record(
        "MAC-A", "root", _descriptor(_spec()).native_path, "macos"
    ) == manager.resolve_record("MAC-A", "root", _descriptor(_spec()).native_path, "macos")


def test_legacy_artifact_head_still_restores_windows_content() -> None:
    manager = _manager()
    descriptor = _windows_descriptor()
    _publish(manager, descriptor)
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    document = loads(seal.head.payload)
    document["schema_version"] = "1"
    for row in document["records"]:
        del row[9:]
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        dumps(document), ()
    )
    assert restored.resolve_record(
        descriptor.hostname, descriptor.principal, descriptor.native_path, descriptor.platform
    ) == manager.resolve_record(
        descriptor.hostname, descriptor.principal, descriptor.native_path, descriptor.platform
    )


def test_expired_file_cannot_supply_a_new_bootstrap_definition() -> None:
    manager = _manager()
    spec = _spec()
    _publish(manager, _descriptor(spec))
    installation = macos_system_job_deployment_identity(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label=spec.label,
        installation_action_id="install-worker",
    )
    manager.advance_watermark(_START + timedelta(days=365))
    with pytest.raises(ValueError, match="current file"):
        macos_system_job_definition_from_file(
            runtime_content=manager,
            deployment_identity=installation,
            principal="root",
            native_path=_descriptor(spec).native_path,
        )


def test_legacy_head_rejects_new_metadata_instead_of_dropping_it() -> None:
    manager = _manager()
    _publish(manager, _descriptor(_spec()))
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    document = loads(seal.head.payload)
    document["schema_version"] = "1"
    for row in document["records"]:
        del row[9:]
    with pytest.raises(CheckpointCorruptionError, match="record is invalid"):
        LocalArtifactVersionRegistryParticipant(_manager().registry).restore_checkpoint(
            dumps(document), ()
        )
