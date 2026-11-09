# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.dispatcher import PreparedDispatch
from evidenceforge.generation.actions.macos_launch_item import macos_system_job_remove_effect
from evidenceforge.generation.actions.process_execution import ProcessExecutionActionBundle
from evidenceforge.generation.actions.process_support.preflight import ProcessPreflightPlanner
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.packed import loads
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPublicationReceipt,
    LocalArtifactVersionRegistry,
    _LocalArtifactPreparedCommitPlan,
    _LocalArtifactPreparedReservation,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_generator_endpoint_effect_integration import _events, _NoAmbientEffectsRandom
from tests.unit.test_macos_launch_file import _descriptor, _manager, _publish, _spec
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_launch_write import _PATH, _TIME, _writer


def test_prepared_removal_cancels_and_then_commits_without_erasing_history() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    token = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    with manager.registry.prepared_publication(token):
        assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") == record
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") == record
    token = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    with manager.registry.prepared_publication(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert receipt.artifact_version_id == record.artifact.artifact_version_id
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None
    assert manager.registry.get(record.artifact.artifact_version_id) == record.artifact
    del receipt, prepared
    head = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        head.head.payload, ()
    )
    assert restored.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None
    assert restored.registry.get(record.artifact.artifact_version_id) == record.artifact


@pytest.mark.parametrize("replacement", ["prepared", "committed"])
def test_removal_rechecks_interleaved_writes_before_commit(replacement: str) -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    token = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    with manager.registry.prepared_publication(token) as prepared:
        new = manager.prepare_publication(_descriptor(_spec(), version=2), _START)
        if replacement == "committed":
            with manager.registry.prepared_publication(new) as publication:
                publication.commit_no_fail()
        with pytest.raises(StateError, match="current file|conflicts"):
            prepared.commit_no_fail()
        if replacement == "prepared":
            manager.registry.cancel_prepared(new)
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is not None
    assert manager.registry.census().prepared_publications == 0


def test_removal_failure_rolls_back_all_retained_versions_and_counters() -> None:
    manager = _manager()
    first, latest = _descriptor(_spec()), _descriptor(_spec(), version=2)
    _publish(manager, first)
    _publish(manager, latest)
    before = (
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    token = manager.registry.prepare_publish_version(
        manager.build_record(latest), _START, withdraw_placement=True
    )
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_after_withdrawal(
        self: LocalArtifactVersionRegistry,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        original(self, reservation, plan)
        raise RuntimeError("injected artifact tail failure")

    with patch.object(
        LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_after_withdrawal
    ):
        with pytest.raises(RuntimeError, match="injected"):
            with manager.registry.prepared_publication(token) as prepared:
                prepared.commit_no_fail()
    after = (
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    # Preparation ordinal legitimately advances; placement, history and store frontiers do not.
    assert manager.resolve_record(
        "MAC-A", "root", latest.native_path, "macos"
    ) == manager.build_record(latest)
    assert manager.registry.census().prepared_publications == 0
    before_doc, after_doc = loads(before), loads(after)
    before_doc.pop("next_reservation_id")
    after_doc.pop("next_reservation_id")
    assert before_doc == after_doc


@pytest.mark.parametrize("collected", [True, False])
def test_process_owned_removal_uses_atomic_effect_boundary(collected: bool) -> None:
    generator, state, emitter, manager, writer = _writer(collected)
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        ProcessExecutionActionBundle(generator, writer).execute()
    record = manager.resolve_record("MAC-TEST", "root", _PATH, "macos")
    token = manager.registry.prepare_publish_version(
        record, _TIME + timedelta(seconds=20), withdraw_placement=True
    )
    effect = macos_system_job_remove_effect(
        publication=token,
        instance_key="remove-job-file",
        retention_deadline=_TIME + timedelta(hours=1),
    )
    remover = replace(
        writer,
        time=_TIME + timedelta(seconds=15),
        process_name="/usr/local/libexec/remover",
        command_line="remover --job worker",
        requested_endpoint_effects=(effect,),
    )
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, remover).execute()
    assert manager.resolve_record("MAC-TEST", "root", _PATH, "macos") is None
    assert manager.registry.get(record.artifact.artifact_version_id) == record.artifact
    assert state.get_process("MAC-TEST", pid) is not None
    if collected:
        deletes = [
            event
            for event in _events(emitter)
            if event.event_type == "file_delete" and event.file.path == _PATH
        ]
        assert len(deletes) == 1
        assert deletes[0].file.content_identity == record.content
        assert (
            deletes[0].identity_plan.actor_id
            == state.get_process_identity("MAC-TEST", pid).object_id
        )
    else:
        emitter.emit.assert_not_called()


@pytest.mark.parametrize("fault", ["required-file", "artifact-tail"])
def test_failed_process_removal_restores_file_and_caller_allocation(fault: str) -> None:
    generator, state, emitter, manager, writer = _writer()
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        ProcessExecutionActionBundle(generator, writer).execute()
    record = manager.resolve_record("MAC-TEST", "root", _PATH, "macos")
    token = manager.registry.prepare_publish_version(
        record, _TIME + timedelta(seconds=20), withdraw_placement=True
    )
    effect = macos_system_job_remove_effect(
        publication=token, instance_key="remove-job", retention_deadline=_TIME + timedelta(hours=1)
    )
    remover = replace(
        writer,
        time=_TIME + timedelta(seconds=15),
        process_name="/usr/local/libexec/remover",
        command_line="remover --job worker",
        requested_endpoint_effects=(effect,),
    )
    before = state.materialization_digest()
    emitter.reset_mock()
    original_prepare = generator.dispatcher.prepare_builder
    original_commit = LocalArtifactVersionRegistry._commit_prepared_locked

    def prepare(builder: OccurrenceBuilder, **kwargs: object) -> PreparedDispatch:
        if builder.event_type == "file_delete":
            raise StateError("injected removal preparation failure")
        return original_prepare(builder, **kwargs)

    def commit(
        registry: LocalArtifactVersionRegistry,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        result = original_commit(registry, reservation, plan)
        if reservation.canonical_token.withdraw_placement:
            raise StateError("injected removal artifact failure")
        return result

    failure = (
        patch.object(generator.dispatcher, "prepare_builder", prepare)
        if fault == "required-file"
        else patch.object(LocalArtifactVersionRegistry, "_commit_prepared_locked", commit)
    )
    with (
        failure,
        patch.object(
            ProcessPreflightPlanner,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises(StateError, match="injected removal"),
    ):
        ProcessExecutionActionBundle(generator, remover).execute()
    assert state.materialization_digest() == before
    assert manager.resolve_record("MAC-TEST", "root", _PATH, "macos") == record
    assert manager.registry.census().prepared_publications == 0
    emitter.emit.assert_not_called()


def test_removal_does_not_resurrect_an_older_leased_placement_after_checkpoint() -> None:
    manager = _manager()
    first, latest = _descriptor(_spec()), _descriptor(_spec(), version=2)
    _publish(manager, first)
    old = manager.build_record(first)
    manager.registry.acquire_lease(
        old.artifact.artifact_version_id, "historical-observer", _START + timedelta(days=3)
    )
    _publish(manager, latest)
    token = manager.registry.prepare_publish_version(
        manager.build_record(latest), _START, withdraw_placement=True
    )
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit_no_fail()
    del prepared
    manager.advance_watermark(_START + timedelta(days=2))
    assert manager.registry.get(old.artifact.artifact_version_id) == old.artifact
    assert manager.resolve_record("MAC-A", "root", first.native_path, "macos") is None
    head = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        head.head.payload, ()
    )
    assert restored.resolve_record("MAC-A", "root", first.native_path, "macos") is None


@pytest.mark.parametrize("wrong_operation", [False, "yes"])
def test_changed_removal_capability_cannot_publish(wrong_operation: bool | str) -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    token = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    object.__setattr__(token, "withdraw_placement", wrong_operation)
    with pytest.raises(StateError):
        with manager.registry.prepared_publication(token):
            pass
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") == record
    assert manager.registry.census().prepared_publications == 0


def test_group_failure_undoes_removal_and_unrelated_new_publication() -> None:
    manager = _manager()
    descriptor = _descriptor(_spec())
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    removal = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    other = replace(
        descriptor,
        native_path="/Library/LaunchDaemons/org.example.other.plist",
        source_object_id="other-file",
    )
    write = manager.prepare_publication(other, _START)
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def commit(
        registry: LocalArtifactVersionRegistry,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        result = original(registry, reservation, plan)
        if not reservation.canonical_token.withdraw_placement:
            raise StateError("injected second member failure")
        return result

    with (
        patch.object(LocalArtifactVersionRegistry, "_commit_prepared_locked", commit),
        pytest.raises(StateError, match="second member"),
    ):
        with manager.registry.prepared_publication_group((removal, write)) as group:
            group.commit_no_fail()
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") == record
    assert manager.resolve_record("MAC-A", "root", other.native_path, "macos") is None
    assert manager.registry.census().prepared_publications == 0


def test_removal_keeps_registered_definition_available_for_later_activation() -> None:
    from evidenceforge.generation.actions.macos_launch_item import macos_system_job_launch_plan
    from tests.unit.test_macos_launch_activation import _setup

    manager = _manager()
    state, registry, authority, adapter, job = _setup(manager, known_boot_group=True)
    definition = job.instance_identity.launchd_job
    record = manager.resolve_record("MAC-A", "root", definition.plist.native_path, "macos")
    token = manager.registry.prepare_publish_version(record, _START, withdraw_placement=True)
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit_no_fail()
    launch = macos_system_job_launch_plan(
        lifecycle_registry=registry,
        lifecycle_authority=authority,
        state_manager=state,
        service_object_id=job.instance_identity.object_id,
        started_at=_START + timedelta(seconds=2),
        action_id="activate-after-removal",
    )
    authority.materialize_process_service_composite(
        launch.process, adapter.prepare_service_publication(launch.activation)
    )
    assert (
        registry.get_service_instance(job.instance_identity.object_id).identity.launchd_job
        == definition
    )
    assert (
        state.get_process_identity_by_object_id(launch.process.identity.object_id)
        == launch.process.identity
    )
    assert manager.resolve_record("MAC-A", "root", definition.plist.native_path, "macos") is None
