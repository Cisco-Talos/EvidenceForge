# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest

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
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager


def test_retained_loaded_version_survives_replacement_removal_and_checkpoint() -> None:
    content = _manager()
    first = _executable()
    second = replace(first, artifact_version=2, content_version=2)
    _publish(content, first, _START)
    _publish(content, second, _START)
    record = content.build_record(first)
    current = content.build_record(second)
    path = (first.hostname, first.principal, first.native_path, first.platform)
    token = content.registry.prepare_version_retention(
        record.artifact.artifact_version_id,
        observed_at=_START + timedelta(seconds=1),
        retained_until=_START + timedelta(days=10),
    )
    with content.registry.prepared_publication(token) as prepared:
        prepared.commit_no_fail()
    assert content.registry.resolve_record_for_execution_path(*path) == current
    removal = content.registry.prepare_publish_version(
        current, _START + timedelta(seconds=2), withdraw_placement=True
    )
    with content.registry.prepared_publication(removal) as prepared:
        prepared.commit_no_fail()
    # Extending an already withdrawn older version must not restore a placement.
    token = content.registry.prepare_version_retention(
        record.artifact.artifact_version_id,
        observed_at=_START + timedelta(seconds=3),
        retained_until=_START + timedelta(days=11),
    )
    with content.registry.prepared_publication(token) as prepared:
        prepared.commit_no_fail()
    assert content.registry.resolve_record_for_execution_path(*path) is None
    del prepared
    head = LocalArtifactVersionRegistryParticipant(content.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        head.head.payload, ()
    )
    restored.registry.advance_watermark(_START + timedelta(days=10))
    assert restored.registry.resolve_version(record.artifact.artifact_version_id) == record
    assert restored.registry.resolve_record_for_execution_path(*path) is None
    restored.registry.advance_watermark(_START + timedelta(days=11))
    assert restored.registry.resolve_version(record.artifact.artifact_version_id) is None


@pytest.mark.parametrize("failure", ["cancel", "tail"])
def test_retention_preparation_rolls_back_exact_registry_deadlines(failure: str) -> None:
    content = _manager()
    descriptor = _executable()
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    participant = LocalArtifactVersionRegistryParticipant(content.registry)
    before = participant.prepare_checkpoint(1).head.payload
    token = content.registry.prepare_version_retention(
        record.artifact.artifact_version_id,
        observed_at=_START,
        retained_until=_START + timedelta(days=10),
    )
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_after_retention(
        registry: LocalArtifactVersionRegistry,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        original(registry, reservation, plan)
        raise RuntimeError("injected retention tail failure")

    if failure == "tail":
        with patch.object(
            LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_after_retention
        ):
            with pytest.raises(RuntimeError, match="retention tail"):
                with content.registry.prepared_publication(token) as prepared:
                    prepared.commit_no_fail()
    else:
        with content.registry.prepared_publication(token):
            pass
    before_doc = loads(before)
    after_doc = loads(participant.prepare_checkpoint(2).head.payload)
    # Reservation IDs advance even when publication is cancelled.
    before_doc.pop("next_reservation_id")
    after_doc.pop("next_reservation_id")
    assert after_doc == before_doc


def test_eviction_between_lookup_and_reservation_cannot_resurrect_a_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = _manager()
    descriptor = _executable()
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    original = content.registry.prepare_publish_version
    at = _START + timedelta(days=10)

    def after_eviction(
        registry: LocalArtifactVersionRegistry, *args: object, **kwargs: object
    ) -> object:
        registry.advance_watermark(at)
        return original(*args, **kwargs)

    monkeypatch.setattr(LocalArtifactVersionRegistry, "prepare_publish_version", after_eviction)
    with pytest.raises(StateError, match="exact existing version"):
        content.registry.prepare_version_retention(
            record.artifact.artifact_version_id,
            observed_at=at,
            retained_until=at + timedelta(days=1),
        )
    assert content.registry.resolve_version(record.artifact.artifact_version_id) is None
    assert content.registry.census().prepared_publications == 0


@pytest.mark.parametrize("offset", [0, -1])
def test_retention_rejects_nonpositive_intervals_before_reservation(offset: int) -> None:
    content = _manager()
    descriptor = _executable()
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    with pytest.raises(StateError, match="ordered aware"):
        content.registry.prepare_version_retention(
            record.artifact.artifact_version_id,
            observed_at=_START,
            retained_until=_START + timedelta(seconds=offset),
        )
    assert content.registry.census().prepared_publications == 0


def test_shorter_retention_request_never_shortens_existing_history() -> None:
    content = _manager()
    descriptor = _executable()
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    for days in (10, 2):
        token = content.registry.prepare_version_retention(
            record.artifact.artifact_version_id,
            observed_at=_START,
            retained_until=_START + timedelta(days=days),
        )
        with content.registry.prepared_publication(token) as prepared:
            prepared.commit_no_fail()
    content.registry.advance_watermark(_START + timedelta(days=3))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    content.registry.advance_watermark(_START + timedelta(days=10))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) is None


def test_missing_version_guard_cannot_allocate_or_coerce_authority() -> None:
    content = _manager()
    record = content.build_record(_executable())
    with pytest.raises(StateError, match="exact existing version"):
        content.registry.prepare_publish_version(record, _START, require_existing=True)
    with pytest.raises(StateError, match="exact boolean"):
        content.registry.prepare_publish_version(record, _START, require_existing=1)
    assert content.registry.resolve_version(record.artifact.artifact_version_id) is None
    assert content.registry.census().prepared_publications == 0


def test_retention_uses_elapsed_time_across_repeated_local_clock_hour() -> None:
    content = _manager()
    descriptor = _executable()
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    zone = ZoneInfo("America/New_York")
    observed = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    deadline = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=1)
    token = content.registry.prepare_version_retention(
        record.artifact.artifact_version_id, observed_at=observed, retained_until=deadline
    )
    assert token.retained_until == deadline.astimezone(UTC)
    assert token.retained_until - token.observed_at == timedelta(hours=1)
    content.registry.cancel_prepared(token)
