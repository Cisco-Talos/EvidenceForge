# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Versioned loaded definitions and legacy service intervals survive hydration."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.lifecycle_head import (
    LifecycleRegistryParticipant,
    _capture,
    _restore,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.participants import ParticipantSeal
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    builtin_service_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceProcessClosureRequest,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_incremental_checkpoints import _cursor
from tests.unit.test_lifecycle_service_preparation import _START, _control, _publish


def _legacy_head(registry: LifecycleRegistry, version: str = "5") -> bytes:
    document = loads(_capture(registry))
    document["schema_version"] = version
    for partition in document["partitions"]:
        for service in partition[2]:
            if version in {"5", "6"}:
                assert service.pop() is None
            if version == "5":
                assert service[1].pop() is None
    return dumps(document)


def _sequential_windows_services() -> LifecycleRegistry:
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    first = builtin_service_publication_plan(
        hostname="WIN-A",
        logical_service_id="example-service",
        canonical_name="ExampleService",
        boot_time=_START - timedelta(hours=1),
        started_at=_START,
    )
    _publish(adapter, first)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(),
        service_closures=(
            _control(
                "service", first.instance_identity.object_id, at=_START + timedelta(minutes=1)
            ),
        ),
    )
    token = adapter.prepare_service_process_closure(request)
    with adapter.claimed_service_process_closure(token) as prepared:
        prepared.commit_no_fail()
    second = builtin_service_publication_plan(
        hostname="WIN-A",
        logical_service_id="example-service",
        canonical_name="ExampleService",
        boot_time=_START + timedelta(minutes=2),
        started_at=_START + timedelta(minutes=3),
    )
    _publish(adapter, second)
    return registry


@pytest.mark.parametrize("legacy", [False, True])
def test_sequential_windows_service_instances_restore_without_false_overlap(legacy: bool) -> None:
    registry = _sequential_windows_services()
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _legacy_head(registry) if legacy else _capture(registry))
    assert _capture(restored) == _capture(registry)


def test_corrupt_overlapping_service_intervals_cannot_replace_live_registry() -> None:
    original = _sequential_windows_services()
    document = loads(_capture(original))
    services = sorted(
        (row for partition in document["partitions"] for row in partition[2]),
        key=lambda row: row[1][5],
    )
    services[1][1][5] = (_START + timedelta(seconds=30)).isoformat()
    restored = LifecycleRegistry(shard_count=8)
    before = _capture(restored)
    with pytest.raises((StateError, CheckpointCorruptionError), match="overlap"):
        _restore(restored, dumps(document))
    assert _capture(restored) == before


class _LegacyLifecycleParticipant(LifecycleRegistryParticipant):
    checkpoint_schema_version = "5"

    def __init__(self, registry: LifecycleRegistry, version: str) -> None:
        super().__init__(registry)
        self.checkpoint_schema_version = version

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        seal = super().prepare_checkpoint(sequence)
        return replace(
            seal,
            head=replace(
                seal.head, payload=_legacy_head(self.registry, self.checkpoint_schema_version)
            ),
        )


@pytest.mark.parametrize("version", ["5", "6", "7", "8"])
def test_controller_loads_legacy_head_and_next_checkpoint_writes_new_schema(
    tmp_path: Path, version: str
) -> None:
    registry = _sequential_windows_services()
    store = IncrementalCheckpointStore(tmp_path / "output")
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint="1" * 64,
        checkpoint_hours=6,
        resolved_scenario=b"schema_version: '2.0'\n",
    )
    controller.commit(
        cursor=_cursor(6), participants=(_LegacyLifecycleParticipant(registry, version),)
    )
    recovery = store.recover()
    restored = LifecycleRegistry(shard_count=8)
    participant = LifecycleRegistryParticipant(restored)
    controller.restore_participants(recovery=recovery, participants=(participant,))
    assert _capture(restored) == _capture(registry)
    manifest = controller.commit(cursor=_cursor(12), participants=(participant,))
    assert manifest.participant_heads[0].schema_version == "9"


def test_legacy_head_does_not_accept_new_service_fields() -> None:
    document = loads(_capture(_sequential_windows_services()))
    document["schema_version"] = "5"
    with pytest.raises(CheckpointCorruptionError, match="legacy service"):
        _restore(LifecycleRegistry(shard_count=8), dumps(document))


def test_previous_loaded_job_head_restores_without_inventing_group_ownership() -> None:
    from tests.unit.test_macos_launch_activation import _setup

    _, registry, _, _, job = _setup()
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _legacy_head(registry, "6"))
    snapshot = restored.get_service_instance(job.instance_identity.object_id)
    assert snapshot.identity == job.instance_identity
    assert snapshot.process_group is None
