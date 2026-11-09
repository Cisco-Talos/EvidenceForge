# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Short native observation fences preserve file facts without holding cross-owner locks."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_dispatch_publication import _bind
from tests.unit.test_macos_es_dispatch_publication import _setup as _native
from tests.unit.test_macos_file_rename import _setup
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager


@pytest.mark.parametrize(
    "operation", ["withdraw", "prepare", "legacy", "release", "release_owner", "watermark"]
)
def test_claim_rejects_placement_mutation_and_eviction_then_releases(operation: str) -> None:
    manager, source = _setup()
    registry = manager.registry
    original = registry.observe_version_placement(source.artifact.artifact_version_id)
    with registry.claimed_placement_observations():
        with pytest.raises(StateError, match="fenced"):
            if operation == "withdraw":
                registry.withdraw_execution_path(source, _START)
            elif operation == "prepare":
                manager.prepare_publication(replace(_executable(), artifact_version=2), _START)
            elif operation == "legacy":
                registry.publish(source.artifact, _START)
            elif operation == "release":
                registry.release_lease(source.artifact.artifact_version_id, "invented-loaded-image")
            elif operation == "release_owner":
                registry.release_owner("invented-loaded-image")
            else:
                registry.advance_watermark(_START + timedelta(days=10))
        assert registry.observe_version_placement(source.artifact.artifact_version_id) == original
        with pytest.raises(CheckpointError, match="placement_observation_claims"):
            LocalArtifactVersionRegistryParticipant(registry).prepare_checkpoint(1)
    assert registry.withdraw_execution_path(source, _START + timedelta(seconds=1))


def test_already_prepared_unchanged_retention_can_commit_inside_the_fence() -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    token = registry.prepare_version_retention(
        version, observed_at=_START, retained_until=_START + timedelta(days=12)
    )
    with registry.prepared_publication(token) as prepared:
        with registry.claimed_placement_observations():
            prepared.commit()
    del prepared
    registry.advance_watermark(_START + timedelta(days=10))
    assert registry.resolve_version(version) == source
    assert registry.observe_version_placement(version).introduced_at == _START


@pytest.mark.parametrize("group", [False, True])
def test_already_prepared_new_placement_cannot_commit_inside_the_fence(group: bool) -> None:
    manager, source = _setup()
    registry = manager.registry
    token = manager.prepare_publication(
        replace(_executable(), artifact_version=2), _START + timedelta(seconds=1)
    )
    context = (
        registry.prepared_publication_group((token,))
        if group
        else registry.prepared_publication(token)
    )
    with context as prepared:
        with registry.claimed_placement_observations():
            with pytest.raises(StateError, match="fenced"):
                prepared.commit()
            assert registry.resolve_version(source.artifact.artifact_version_id) == source
            assert registry.resolve_version(token.record.artifact.artifact_version_id) is None
    assert not registry._placement_observation_claims


def test_nested_exception_and_concurrent_writer_release_without_deadlock() -> None:
    manager, source = _setup()
    registry = manager.registry
    with registry.claimed_placement_observations():
        with pytest.raises(RuntimeError, match="injected"):
            with registry.claimed_placement_observations():
                raise RuntimeError("injected owner rejection")
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(registry.withdraw_execution_path, source, _START)
            with pytest.raises(StateError, match="fenced"):
                pending.result(timeout=3)
    assert not registry._placement_observation_claims
    assert registry.withdraw_execution_path(source, _START)


def test_cancelling_due_preparation_defers_eviction_only_until_last_observer_leaves() -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    token = registry.prepare_version_retention(
        version, observed_at=_START, retained_until=_START + timedelta(days=12)
    )
    registry.advance_watermark(_START + timedelta(days=10))
    with registry.claimed_placement_observations():
        with registry.claimed_placement_observations():
            registry.cancel_prepared(token)
            assert registry.resolve_version(version) == source
        assert registry.resolve_version(version) == source
    assert registry.resolve_version(version) is None
    assert not registry._placement_deferred_expiry
    LocalArtifactVersionRegistryParticipant(registry).prepare_checkpoint(1)


def test_dispatch_claim_fences_runtime_metadata_until_canonical_completion(tmp_path: Path) -> None:
    native, dispatcher, emitter, batch, frozen = _native(tmp_path)
    registry = native.executables
    subject = native.process.process
    source = registry.resolve_version(subject.executable_version.artifact_version_id)
    _bind(native, dispatcher, batch)
    with dispatcher.claimed_action_cohort(batch) as claimed:
        with pytest.raises(StateError, match="fenced"):
            registry.withdraw_execution_path(source, native.process.observed_at)
        claimed.commit_no_fail()
    assert not registry._placement_observation_claims
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


def test_enter_failure_after_claim_admission_does_not_leave_a_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    registry = manager.registry
    original = LocalArtifactVersionRegistry._all_shards_locked
    calls = 0

    @contextmanager
    def failing_enter(owner: LocalArtifactVersionRegistry) -> Iterator[None]:
        nonlocal calls
        with original(owner):
            yield
        calls += 1
        if calls == 1:
            raise RuntimeError("injected observation entrance failure")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_all_shards_locked", failing_enter)
    with pytest.raises(RuntimeError, match="entrance"):
        with registry.claimed_placement_observations():
            pytest.fail("body cannot run after failed admission")
    assert not registry._placement_observation_claims
    assert registry.withdraw_execution_path(source, _START)


def test_failed_deferred_cleanup_keeps_retryable_expiry_without_a_live_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    token = registry.prepare_version_retention(
        version, observed_at=_START, retained_until=_START + timedelta(days=12)
    )
    cutoff = _START + timedelta(days=10)
    registry.advance_watermark(cutoff)
    original = LocalArtifactVersionRegistry._evict_pending_version
    failed = False

    def fail_once(owner: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal failed
        if not owner._placement_observation_claims and not failed:
            failed = True
            raise RuntimeError("injected deferred expiry failure")
        return original(owner, *args)

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_evict_pending_version", fail_once)
    with pytest.raises(RuntimeError, match="expiry"):
        with registry.claimed_placement_observations():
            registry.cancel_prepared(token)
    assert not registry._placement_observation_claims
    assert registry._placement_deferred_expiry
    assert registry.resolve_version(version) == source
    assert registry.advance_watermark(cutoff) == (source.artifact,)
    assert not registry._placement_deferred_expiry
    assert registry.resolve_version(version) is None


def test_restore_cannot_replace_an_empty_registry_under_an_observation_fence() -> None:
    manager, _ = _setup()
    payload = (
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    fresh = _manager().registry
    participant = LocalArtifactVersionRegistryParticipant(fresh)
    with fresh.claimed_placement_observations():
        with pytest.raises(CheckpointError, match="placement_observation_claims"):
            participant.restore_checkpoint(payload, ())
        assert fresh.census().live_versions == 0
    participant.restore_checkpoint(payload, ())
    assert fresh.census().live_versions == 1
