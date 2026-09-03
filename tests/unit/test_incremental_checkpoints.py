"""Tests for content-addressed incremental generation checkpoints."""

from __future__ import annotations

import json
import os
import random
import socket
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleForegroundLease,
    LifecycleHold,
    LifecycleMembership,
    LifecycleRetentionLease,
    LifecycleSingletonLease,
    LogicalServiceIdentity,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceProcessBindingIdentity,
    SessionLifecycleIdentity,
    TransportLifecycleIdentity,
    TransportSessionBindingIdentity,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.checkpoints.cadence import CheckpointCadence
from evidenceforge.generation.checkpoints.errors import (
    CheckpointCompatibilityError,
    CheckpointCorruptionError,
    CheckpointError,
    CheckpointLockError,
)
from evidenceforge.generation.checkpoints.lifecycle_head import LifecycleRegistryParticipant
from evidenceforge.generation.checkpoints.models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointStoreMetrics,
)
from evidenceforge.generation.checkpoints.owner_inventory import (
    LIFECYCLE_PARTITION_CHECKPOINT_FIELDS,
    LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS,
    STATE_MANAGER_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.participants import (
    OwnerStateField,
    ParticipantSeal,
)
from evidenceforge.generation.checkpoints.rng import (
    GenerationRngParticipant,
    decode_random_state,
    encode_random_state,
)
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.checkpoints.spools import (
    AppendOnlySpoolParticipant,
    ImmutableSpoolFilesParticipant,
)
from evidenceforge.generation.checkpoints.sqlite_spool import SQLiteSpoolParticipant
from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.checkpoints.state_values import (
    decode_state_value,
    encode_state_value,
)
from evidenceforge.generation.checkpoints.store import (
    HeadDraft,
    IncrementalCheckpointStore,
    RunLock,
    SegmentDraft,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.rng import _get_rng, generation_seed_scope, reset_thread_rng

_FINGERPRINT = "1" * 64


class _FakeParticipant:
    checkpoint_owner = "fake"
    checkpoint_schema_version = "1"
    checkpoint_state_fields = (
        OwnerStateField("head", "bounded-live-head"),
        OwnerStateField("delta", "immutable-incremental-segments"),
    )

    def __init__(self) -> None:
        self.committed_sequence = -1
        self.prepared_sequence: int | None = None
        self.aborted: list[int] = []
        self.restored: tuple[object, tuple[object, ...]] | None = None

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        if self.prepared_sequence not in {None, sequence}:
            raise RuntimeError("fake participant already has another prepared sequence")
        self.prepared_sequence = sequence
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps({"committed": self.committed_sequence, "pending": sequence}),
            ),
            segments=(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps([sequence]),
                    record_count=1,
                ),
            ),
        )

    def checkpoint_committed(self, sequence: int) -> None:
        assert self.prepared_sequence == sequence
        self.committed_sequence = sequence
        self.prepared_sequence = None

    def checkpoint_aborted(self, sequence: int) -> None:
        assert self.prepared_sequence == sequence
        self.aborted.append(sequence)
        self.prepared_sequence = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        self.restored = (loads(head), tuple(loads(segment) for segment in segments))


def _cursor(hour: int, *, tail: bool = False) -> CheckpointCursor:
    return CheckpointCursor(
        phase="tail" if tail else "collection",
        completed_simulated_hours=hour,
        next_hour=None if tail else f"2026-01-01T{hour:02d}:00:00+00:00",
    )


def _commit(
    store: IncrementalCheckpointStore,
    *,
    sequence: int,
    hour: int,
    inherited: tuple = (),
    payload: bytes | None = None,
    references: tuple[str, ...] = (),
    metrics: CheckpointStoreMetrics | None = None,
) -> CheckpointManifest:
    segments = (
        ()
        if payload is None
        else (
            SegmentDraft(
                owner="lifecycle",
                schema_version="1",
                payload=payload,
                record_count=1,
                compression="zlib-1",
            ),
        )
    )
    return store.commit(
        sequence=sequence,
        run_id="run-1",
        run_fingerprint=_FINGERPRINT,
        checkpoint_hours=6,
        cursor=_cursor(hour),
        resolved_scenario=b"schema_version: '2.0'\n",
        inherited_segments=inherited,
        new_segments=segments,
        heads=(
            HeadDraft(
                owner="engine",
                schema_version="1",
                payload=f'{{"hour":{hour}}}'.encode(),
                referenced_segments=references,
            ),
        ),
        metrics=metrics,
    )


def test_cursor_requires_exact_phase_position() -> None:
    with pytest.raises(ValidationError, match="require next_hour"):
        CheckpointCursor(phase="warmup", completed_simulated_hours=6)
    with pytest.raises(ValidationError, match="cannot name a next hour"):
        CheckpointCursor(
            phase="tail",
            completed_simulated_hours=6,
            next_hour="2026-01-01T06:00:00+00:00",
        )


def test_cadence_only_selects_positive_multiples_and_post_transition_phase() -> None:
    cadence = CheckpointCadence(6)
    collection_start = datetime(2026, 1, 1, 8, tzinfo=UTC)
    collection_end = datetime(2026, 1, 3, 8, tzinfo=UTC)

    assert (
        cadence.cursor_after_hour(
            completed_simulated_hours=5,
            next_hour=collection_start,
            collection_start=collection_start,
            collection_end=collection_end,
        )
        is None
    )
    boundary = cadence.cursor_after_hour(
        completed_simulated_hours=6,
        next_hour=collection_start,
        collection_start=collection_start,
        collection_end=collection_end,
    )
    assert boundary is not None
    assert boundary.phase == "collection"
    assert boundary.next_hour == collection_start.isoformat()
    tail = cadence.cursor_after_hour(
        completed_simulated_hours=54,
        next_hour=collection_end,
        collection_start=collection_start,
        collection_end=collection_end,
    )
    assert tail is not None
    assert tail.phase == "tail"
    assert tail.next_hour is None


def test_zero_cadence_disables_every_checkpoint() -> None:
    cadence = CheckpointCadence(0)
    assert not cadence.enabled
    assert not cadence.is_due(6)


def test_packed_primitive_codec_is_deterministic_and_inert() -> None:
    value = {"z": [None, True, -2, 3.5, b"bytes"], "a": "text"}
    encoded = dumps(value)
    assert encoded == dumps({"a": "text", "z": [None, True, -2, 3.5, b"bytes"]})
    assert loads(encoded) == value
    with pytest.raises(CheckpointCorruptionError, match="trailing bytes"):
        loads(encoded + b"x")
    with pytest.raises(TypeError, match="unsupported"):
        dumps(Path("unsafe"))


def test_rng_numeric_schema_restores_exact_stream() -> None:
    with generation_seed_scope(8675309):
        reset_thread_rng()
        rng = _get_rng()
        _ = [rng.random() for _ in range(10)]
        state = rng.getstate()
        document = encode_random_state(state)
        assert decode_random_state(document) == state
        participant = GenerationRngParticipant()
        seal = participant.prepare_checkpoint(0)
        participant.checkpoint_committed(0)
        expected = [rng.getrandbits(64) for _ in range(20)]
        _ = [rng.random() for _ in range(10)]

        participant.restore_checkpoint(seal.head.payload, ())

        assert [rng.getrandbits(64) for _ in range(20)] == expected


def test_rng_numeric_schema_rejects_invalid_word() -> None:
    state = encode_random_state(random.Random(1).getstate())
    words = state["state"]
    assert isinstance(words, list)
    words[0] = -1
    with pytest.raises(CheckpointCorruptionError, match="unsupported or corrupt"):
        decode_random_state(state)


def test_core_mutable_owners_have_complete_checkpoint_inventories() -> None:
    manager = StateManager()
    registry = LifecycleRegistry()

    assert_complete_owner_inventory(
        manager,
        STATE_MANAGER_CHECKPOINT_FIELDS,
        owner_name="state-manager",
    )
    assert_complete_owner_inventory(
        registry,
        LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS,
        owner_name="lifecycle-registry",
    )
    for index, partition in enumerate(registry._partitions):
        assert_complete_owner_inventory(
            partition,
            LIFECYCLE_PARTITION_CHECKPOINT_FIELDS,
            owner_name=f"lifecycle-partition-{index}",
        )


def test_checkpoint_barrier_rejects_transient_state() -> None:
    manager = StateManager()
    assert_transient_owner_state_empty(
        manager,
        STATE_MANAGER_CHECKPOINT_FIELDS,
        owner_name="state-manager",
    )

    manager._active_connection_preparations[1] = object()  # type: ignore[assignment]
    with pytest.raises(CheckpointError, match="_active_connection_preparations"):
        assert_transient_owner_state_empty(
            manager,
            STATE_MANAGER_CHECKPOINT_FIELDS,
            owner_name="state-manager",
        )


def test_lifecycle_head_round_trips_active_and_closed_entity_authority() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = LifecycleRegistry(shard_count=4)
    session = SessionLifecycleIdentity(
        hostname="host-1",
        object_id="session-1",
        logon_id="0x10001",
        principal="alice",
        session_kind="interactive",
        started_at=started,
    )
    process = ProcessLifecycleIdentity(
        hostname="host-1",
        object_id="process-1",
        pid=4100,
        started_at=started,
        image=r"C:\Windows\System32\cmd.exe",
    )
    registry.register_session(session, action_id="session", transition_id="session:start")
    registry.register_process(
        process,
        token=ProcessTokenIdentity(principal="alice", logon_id="0x10001"),
        membership=LifecycleMembership("session", "session-1", "session-1"),
        action_id="process",
        transition_id="process:start",
    )
    registry.record_dependent(
        process.ref,
        transition_id="process:dependent",
        canonical_time=started.replace(minute=1),
        action_id="dependent",
    )
    registry.add_hold(
        LifecycleHold(
            hold_id="process:hold",
            subject=process.ref,
            acquired_at=started.replace(minute=2),
            hold_until=started.replace(minute=5),
            action_id="hold",
            reason="child output",
        )
    )
    process_ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="process:barrier",
            subject=process.ref,
            requested_at=started.replace(minute=3),
            authority="generated",
            action_id="process-close",
        ),
        ticket_id="process:ticket",
    )
    registry.close(process_ticket.ticket_id)
    session_ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="session:barrier",
            subject=session.ref,
            requested_at=started.replace(minute=6),
            authority="generated",
            action_id="session-close",
        ),
        ticket_id="session:ticket",
    )
    registry.close(session_ticket.ticket_id)
    expected_process = registry.get_process("process-1")
    expected_session = registry.get_session("session-1")

    participant = LifecycleRegistryParticipant(registry)
    seal = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    restored_registry = LifecycleRegistry(shard_count=4)
    restored = LifecycleRegistryParticipant(restored_registry)
    restored.restore_checkpoint(seal.head.payload, ())

    assert restored_registry.get_process("process-1") == expected_process
    assert restored_registry.get_session("session-1") == expected_session


def test_lifecycle_head_round_trips_compacted_detail_as_bounded_authority() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = LifecycleRegistry(shard_count=1, snapshot_history_limit=1)
    session = SessionLifecycleIdentity(
        hostname="host-1",
        object_id="session-1",
        logon_id="0x10001",
        principal="alice",
        session_kind="interactive",
        started_at=started,
    )
    registry.register_session(session, action_id="session", transition_id="session:start")
    registry.record_dependent(
        session.ref,
        transition_id="session:dependent",
        canonical_time=started.replace(minute=1),
        action_id="dependent",
    )

    expected = registry.get_session("session-1")
    participant = LifecycleRegistryParticipant(registry)
    seal = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    restored_registry = LifecycleRegistry(shard_count=1, snapshot_history_limit=1)

    LifecycleRegistryParticipant(restored_registry).restore_checkpoint(seal.head.payload, ())

    assert restored_registry.get_session("session-1") == expected


def test_lifecycle_head_rebuilds_service_and_cross_host_transport_bindings() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = LifecycleRegistry(shard_count=4)
    session = SessionLifecycleIdentity(
        hostname="host-2",
        object_id="session-2",
        logon_id="0x20001",
        principal="bob",
        session_kind="ssh",
        started_at=started,
    )
    service = ServiceInstanceLifecycleIdentity(
        hostname="host-1",
        object_id="service-1",
        logical_service_id="sshd",
        boot_id="boot-1",
        instance_id="instance-1",
        started_at=started,
    )
    process = ProcessLifecycleIdentity(
        hostname="host-1",
        object_id="process-1",
        pid=1000,
        started_at=started,
        image="/usr/sbin/sshd",
        role="service",
    )
    transport = TransportLifecycleIdentity(
        hostname="host-1",
        object_id="transport-1",
        transport_id="transport-id-1",
        src_hostname="host-2",
        dst_hostname="host-1",
        network_tuple=NetworkTuple("10.0.0.2", 49152, "10.0.0.1", 22, "tcp"),
        opened_at=started,
        close_deadline=started.replace(minute=30),
        zeek_uid="Cexample",
        conn_id="conn-1",
    )
    registry.register_session(session, action_id="session", transition_id="session:start")
    registry.register_service_instance(
        LogicalServiceIdentity("host-1", "sshd", "sshd", "builtin"),
        service,
        action_id="service",
        transition_id="service:start",
    )
    registry.register_process(
        process,
        token=ProcessTokenIdentity(principal="root"),
        membership=LifecycleMembership("service", "service-1"),
        action_id="process",
        transition_id="process:start",
    )
    registry.register_transport(
        transport,
        action_id="transport",
        transition_id="transport:start",
    )
    service_binding = ServiceProcessBindingIdentity(
        binding_id="service-binding-1",
        service_object_id="service-1",
        process_object_id="process-1",
        bound_at=started.replace(second=1),
        role="worker",
        action_id="service-bind",
    )
    transport_binding = TransportSessionBindingIdentity(
        binding_id="transport-binding-1",
        transport_object_id="transport-1",
        session_object_id="session-2",
        bound_at=started.replace(second=2),
        role="session",
        action_id="transport-bind",
    )
    registry.bind_service_process(service_binding)
    registry.close_service_process_binding(
        service_binding.binding_id,
        expected_identity=service_binding,
        closed_at=started.replace(minute=10),
        action_id="service-unbind",
    )
    registry.bind_transport_session(transport_binding)
    expected_service_binding = registry.service_process_binding(service_binding.binding_id)
    expected_transport_binding = registry.transport_session_binding(transport_binding.binding_id)
    expected_transport = registry.get_transport("transport-1")

    participant = LifecycleRegistryParticipant(registry)
    seal = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    restored_registry = LifecycleRegistry(shard_count=4)
    LifecycleRegistryParticipant(restored_registry).restore_checkpoint(seal.head.payload, ())

    assert restored_registry.service_process_binding(service_binding.binding_id) == (
        expected_service_binding
    )
    assert restored_registry.transport_session_binding(transport_binding.binding_id) == (
        expected_transport_binding
    )
    assert restored_registry.get_transport("transport-1") == expected_transport


def test_lifecycle_head_restores_lease_values_indexes_and_commit_keys() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = LifecycleRegistry(shard_count=2)
    session = SessionLifecycleIdentity(
        hostname="host-1",
        object_id="session-1",
        logon_id="0x10001",
        principal="alice",
        session_kind="interactive",
        started_at=started,
    )
    shell = ProcessLifecycleIdentity(
        hostname="host-1",
        object_id="shell-1",
        pid=1001,
        started_at=started + timedelta(seconds=1),
        image="/bin/bash",
        role="shell",
    )
    singleton_process = ProcessLifecycleIdentity(
        hostname="host-1",
        object_id="singleton-process-1",
        pid=1002,
        started_at=started + timedelta(seconds=2),
        image="/usr/bin/python",
        role="application",
    )
    registry.register_session(session, action_id="session", transition_id="session:start")
    for identity in (shell, singleton_process):
        registry.register_process(
            identity,
            token=ProcessTokenIdentity(principal="alice", logon_id=session.logon_id),
            membership=LifecycleMembership(
                "session",
                session.object_id,
                session_object_id=session.object_id,
            ),
            action_id=f"{identity.object_id}:start",
            transition_id=f"{identity.object_id}:start",
        )
    registry.add_retention_lease(
        LifecycleRetentionLease(
            lease_id="retention-1",
            subject=shell.ref,
            retain_until=started + timedelta(hours=5),
            reason="checkpoint-test",
        )
    )
    foreground = registry.acquire_foreground_lease(
        LifecycleForegroundLease(
            lease_id="foreground-1",
            hostname=session.hostname,
            principal=session.principal,
            session_object_id=session.object_id,
            process_object_id=shell.object_id,
            acquired_at=started + timedelta(seconds=3),
            lease_until=started + timedelta(hours=1),
            action_id="foreground:acquire",
            concurrency_group_id="pipeline-1",
        )
    )
    foreground = registry.renew_foreground_lease(
        foreground.lease_id,
        expected_lease_until=foreground.lease_until,
        lease_until=started + timedelta(hours=2),
        canonical_time=started + timedelta(minutes=1),
        action_id="foreground:renew",
        transition_ordinal=7,
    )
    singleton = registry.acquire_singleton_lease(
        LifecycleSingletonLease(
            lease_id="singleton-1",
            hostname=session.hostname,
            principal=session.principal,
            session_object_id=session.object_id,
            logon_id=session.logon_id,
            canonical_image=singleton_process.image,
            process_object_id="",
            acquired_at=started + timedelta(seconds=4),
            lease_until=started + timedelta(hours=3),
            action_id="singleton:acquire",
        )
    )
    singleton = registry.bind_singleton_lease(
        singleton.lease_id,
        process_object_id=singleton_process.object_id,
        canonical_time=started + timedelta(minutes=2),
        action_id="singleton:bind",
        transition_ordinal=3,
    )
    singleton = registry.renew_singleton_lease(
        singleton.lease_id,
        expected_lease_until=singleton.lease_until,
        lease_until=started + timedelta(hours=4),
        canonical_time=started + timedelta(minutes=3),
        action_id="singleton:renew",
        transition_ordinal=9,
    )
    foreground_partition = registry._routes.get("foreground_lease", foreground.lease_id)
    singleton_partition = registry._routes.get("singleton_lease", singleton.lease_id)
    assert isinstance(foreground_partition, int)
    assert isinstance(singleton_partition, int)
    expected_foreground_entry = registry._partitions[foreground_partition]._foreground_leases.get(
        foreground.lease_id
    )
    expected_singleton_entry = registry._partitions[singleton_partition]._singleton_leases.get(
        singleton.lease_id
    )

    participant = LifecycleRegistryParticipant(registry)
    seal = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    restored = LifecycleRegistry(shard_count=2)
    LifecycleRegistryParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored.foreground_lease(foreground.lease_id) == foreground
    assert restored.singleton_lease(singleton.lease_id) == singleton
    restored_foreground_partition = restored._routes.get("foreground_lease", foreground.lease_id)
    restored_singleton_partition = restored._routes.get("singleton_lease", singleton.lease_id)
    assert isinstance(restored_foreground_partition, int)
    assert isinstance(restored_singleton_partition, int)
    assert (
        restored._partitions[restored_foreground_partition]._foreground_leases.get(
            foreground.lease_id
        )
        == expected_foreground_entry
    )
    assert (
        restored._partitions[restored_singleton_partition]._singleton_leases.get(singleton.lease_id)
        == expected_singleton_entry
    )
    census = restored.census()
    assert census.retention_leases == 1
    assert census.foreground_leases == 1
    assert census.singleton_leases == 1
    assert restored.release_retention_lease("retention-1")


def test_state_value_codec_round_trips_only_explicit_runtime_records() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    session = ActiveSession(
        logon_id="0x10001",
        username="alice",
        system="host-1",
        logon_type=2,
        start_time=started,
        source_ip="10.0.0.5",
    )

    assert decode_state_value(encode_state_value(session)) == session
    with pytest.raises(TypeError, match="unsupported"):
        encode_state_value(StateManager())
    with pytest.raises(CheckpointCorruptionError, match="unsupported"):
        decode_state_value(["record", "unknown-runtime-class", []])


def test_state_manager_head_seals_only_new_allocator_records_and_restores() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    manager = StateManager()
    participant = StateManagerParticipant(manager)
    manager.set_current_time(started)
    manager.register_hostname("host-1", "10.0.0.5")
    session = manager.register_session(
        "0x10001",
        "alice",
        "host-1",
        2,
        "10.0.0.10",
        started,
        session_id=2,
    )
    process = manager.register_process(
        "host-1",
        4000,
        0,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        "alice",
        "Medium",
        os_category="windows",
        start_time=started + timedelta(seconds=1),
        logon_id=session.logon_id,
    )
    assert manager.next_semantic_peer_ordinal("process", "peer-1") == 0
    assert (
        manager.next_linux_logind_session_id(
            "linux-1", random.Random(7), started + timedelta(seconds=2)
        )
        > 0
    )

    first = participant.prepare_checkpoint(0)
    assert len(first.segments) == 1
    first_head = first.head.payload
    first_segment = first.segments[0].payload
    first_document = loads(first_segment)
    assert isinstance(first_document, dict)
    assert len(first_document["records"]) == 3
    participant.checkpoint_committed(0)

    manager._mark_logon_id_used("0x10002")
    assert manager.next_semantic_peer_ordinal("process", "peer-1") == 1
    second = participant.prepare_checkpoint(1)
    assert second.head.payload == first_head
    assert len(second.segments) == 1
    second_document = loads(second.segments[0].payload)
    assert isinstance(second_document, dict)
    assert len(second_document["records"]) == 2
    participant.checkpoint_committed(1)

    restored = StateManager()
    restored_participant = StateManagerParticipant(restored)
    restored_participant.restore_checkpoint(
        second.head.payload,
        (first_segment, second.segments[0].payload),
    )

    assert restored.get_current_time() == manager.get_current_time()
    assert restored.list_dns_cache() == manager.list_dns_cache()
    assert restored.get_session(session.logon_id) == session
    assert restored.get_process("host-1", process.pid) == process
    assert restored._used_logon_ids == manager._used_logon_ids
    assert restored._logon_id_second_ordinals == manager._logon_id_second_ordinals
    assert restored._semantic_peer_ordinals == manager._semantic_peer_ordinals
    assert restored._linux_logind_session_used_ids == manager._linux_logind_session_used_ids
    assert restored.materialization_version == manager.materialization_version
    assert restored.next_semantic_peer_ordinal("process", "peer-1") == 2


def test_append_spool_seals_only_new_bytes_and_restores_fresh_files(tmp_path: Path) -> None:
    first_path = tmp_path / "active" / "first.log"
    second_path = tmp_path / "active" / "second.log"
    first_path.parent.mkdir()
    first_path.write_bytes(b"abcdef")
    second_path.write_bytes(b"123")
    participant = AppendOnlySpoolParticipant(
        owner="emitter-append",
        files={"first": first_path, "second": second_path},
        chunk_size=2,
    )

    first = participant.prepare_checkpoint(0)
    assert participant.last_bytes_read == 9
    participant.checkpoint_committed(0)
    with first_path.open("ab") as stream:
        stream.write(b"ghi")
    with second_path.open("ab") as stream:
        stream.write(b"45")
    second = participant.prepare_checkpoint(1)
    assert participant.last_bytes_read == 5
    participant.checkpoint_committed(1)

    restored_first = tmp_path / "restored" / "first.log"
    restored_second = tmp_path / "restored" / "second.log"
    restored = AppendOnlySpoolParticipant(
        owner="emitter-append",
        files={"first": restored_first, "second": restored_second},
        chunk_size=2,
    )
    restored.restore_checkpoint(
        second.head.payload,
        tuple(segment.payload for segment in (*first.segments, *second.segments)),
    )
    assert restored_first.read_bytes() == b"abcdefghi"
    assert restored_second.read_bytes() == b"12345"


def test_append_spool_aborted_delta_is_resealed_without_advancing(tmp_path: Path) -> None:
    path = tmp_path / "spool.log"
    path.write_bytes(b"first")
    participant = AppendOnlySpoolParticipant(owner="append", files={"main": path})
    prepared = participant.prepare_checkpoint(0)
    participant.checkpoint_aborted(0)
    retry = participant.prepare_checkpoint(0)

    assert retry == prepared
    assert participant.last_bytes_read == len(b"first")


def test_append_spool_rejects_replacement_and_corrupt_chain(tmp_path: Path) -> None:
    path = tmp_path / "spool.log"
    path.write_bytes(b"first")
    participant = AppendOnlySpoolParticipant(owner="append", files={"main": path})
    prepared = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    replacement = tmp_path / "replacement.log"
    replacement.write_bytes(b"first-more")
    os.replace(replacement, path)

    with pytest.raises(Exception, match="identity changed"):
        participant.prepare_checkpoint(1)

    restored_path = tmp_path / "restored.log"
    restored = AppendOnlySpoolParticipant(owner="append", files={"main": restored_path})
    corrupt = bytearray(prepared.segments[0].payload)
    corrupt[-1] ^= 1
    with pytest.raises(CheckpointCorruptionError, match="metadata changed"):
        restored.restore_checkpoint(prepared.head.payload, (bytes(corrupt),))


def test_immutable_spool_files_are_imported_once_and_restored(tmp_path: Path) -> None:
    source = tmp_path / "active"
    source.mkdir()
    files = {"run-0": source / "run-0.ndjson"}
    files["run-0"].write_bytes(b"b\na\n")
    participant = ImmutableSpoolFilesParticipant(
        owner="sort-runs",
        source_files=lambda: files,
        restore_path=lambda name: tmp_path / "restored" / f"{name}.ndjson",
    )

    first = participant.prepare_checkpoint(0)
    assert participant.last_bytes_read == 4
    participant.checkpoint_committed(0)
    files["run-1"] = source / "run-1.ndjson"
    files["run-1"].write_bytes(b"d\nc\n")
    second = participant.prepare_checkpoint(1)
    assert participant.last_bytes_read == 4
    assert len(second.segments) == 1
    participant.checkpoint_committed(1)

    restored = ImmutableSpoolFilesParticipant(
        owner="sort-runs",
        source_files=lambda: {},
        restore_path=lambda name: tmp_path / "restored" / f"{name}.ndjson",
    )
    restored.restore_checkpoint(
        second.head.payload,
        tuple(segment.payload for segment in (*first.segments, *second.segments)),
    )
    assert (tmp_path / "restored" / "run-0.ndjson").read_bytes() == b"b\na\n"
    assert (tmp_path / "restored" / "run-1.ndjson").read_bytes() == b"d\nc\n"


def test_sqlite_spool_seals_only_dirty_rows_and_rebuilds_fresh_database(
    tmp_path: Path,
) -> None:
    source = sqlite3.connect(tmp_path / "source.sqlite3")
    source.execute(
        "CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, phase TEXT)"
    )
    source.execute("CREATE INDEX events_phase ON events (phase)")
    source.execute("CREATE TABLE state (name TEXT PRIMARY KEY, value INTEGER NOT NULL)")
    source.executemany(
        "INSERT INTO events VALUES (?, ?, ?)",
        ((1, "one", "candidate"), (2, "two", "candidate")),
    )
    source.execute("INSERT INTO state VALUES ('count', 2)")
    source.commit()
    participant = SQLiteSpoolParticipant(
        owner="sqlite-spool",
        connection=lambda: source,
        tables=("events", "state"),
    )

    first = participant.prepare_checkpoint(0)
    assert participant.last_rows_read == 3
    participant.checkpoint_committed(0)
    source.execute("UPDATE events SET phase = 'final' WHERE sequence = 1")
    source.execute("DELETE FROM events WHERE sequence = 2")
    source.execute("INSERT INTO events VALUES (3, 'three', 'candidate')")
    source.execute("UPDATE state SET value = 3 WHERE name = 'count'")
    source.commit()
    second = participant.prepare_checkpoint(1)
    assert participant.last_rows_read == 4
    participant.checkpoint_committed(1)
    unchanged = participant.prepare_checkpoint(2)
    assert participant.last_rows_read == 0
    assert unchanged.segments == ()
    participant.checkpoint_committed(2)

    target = sqlite3.connect(tmp_path / "target.sqlite3")
    target.execute(
        "CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, phase TEXT)"
    )
    target.execute("CREATE INDEX events_phase ON events (phase)")
    target.execute("CREATE TABLE state (name TEXT PRIMARY KEY, value INTEGER NOT NULL)")
    target.execute("INSERT INTO events VALUES (99, 'discard', 'candidate')")
    target.execute("INSERT INTO state VALUES ('count', 99)")
    target.commit()
    restored = SQLiteSpoolParticipant(
        owner="sqlite-spool",
        connection=lambda: target,
        tables=("events", "state"),
        initialize_tracking=False,
    )
    restored.restore_checkpoint(
        unchanged.head.payload,
        tuple(segment.payload for segment in (*first.segments, *second.segments)),
    )
    assert target.execute("SELECT * FROM events ORDER BY sequence").fetchall() == [
        (1, "one", "final"),
        (3, "three", "candidate"),
    ]
    assert target.execute("SELECT * FROM state").fetchall() == [("count", 3)]
    assert target.execute("PRAGMA index_list(events)").fetchall()
    source.close()
    target.close()


def test_controller_commits_only_due_transactional_participants(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    progress: list[dict[str, float | int | str]] = []
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint=_FINGERPRINT,
        checkpoint_hours=6,
        resolved_scenario=b"schema_version: '2.0'\n",
        progress=progress.append,
    )
    participant = _FakeParticipant()

    with pytest.raises(ValueError, match="not scheduled"):
        controller.commit(cursor=_cursor(5), participants=(participant,))
    first = controller.commit(cursor=_cursor(6), participants=(participant,))
    second = controller.commit(cursor=_cursor(12), participants=(participant,))

    assert first.sequence == 0
    assert second.sequence == 1
    assert participant.committed_sequence == 1
    assert participant.prepared_sequence is None
    assert len(second.segments) == 2
    assert progress[-1]["new_segment_bytes"] > 0
    assert progress[-1]["reused_segment_bytes"] == first.segments[0].size

    recovered = store.recover(expected_fingerprint=_FINGERPRINT)
    fresh = _FakeParticipant()
    resumed = IncrementalCheckpointController.for_recovery(
        store=store,
        recovery=recovered,
        fingerprint=_FINGERPRINT,
        resolved_scenario=store.read_resolved_scenario(recovered),
    )
    resumed.restore_participants(recovery=recovered, participants=(fresh,))
    assert fresh.restored == (
        {"committed": 0, "pending": 1},
        ([0], [1]),
    )


def test_controller_aborts_every_prepared_participant_on_store_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint=_FINGERPRINT,
        checkpoint_hours=6,
        resolved_scenario=b"schema_version: '2.0'\n",
    )
    participant = _FakeParticipant()

    def fail_commit(**kwargs: object) -> CheckpointManifest:
        raise OSError("injected publication failure")

    monkeypatch.setattr(store, "commit", fail_commit)
    with pytest.raises(OSError, match="injected"):
        controller.commit(cursor=_cursor(6), participants=(participant,))
    assert participant.aborted == [0]
    assert participant.committed_sequence == -1
    assert participant.prepared_sequence is None


def test_store_shares_inherited_segments_without_reprocessing_them(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first_metrics = CheckpointStoreMetrics()
    first = _commit(
        store,
        sequence=0,
        hour=6,
        payload=b"first delta" * 100,
        metrics=first_metrics,
    )
    first_segment = first.segments[0]
    first_path = store.workspace / first_segment.relative_path
    first_stat = first_path.stat()

    second_metrics = CheckpointStoreMetrics()
    second = _commit(
        store,
        sequence=1,
        hour=12,
        inherited=first.segments,
        payload=b"second delta" * 100,
        references=(first_segment.sha256,),
        metrics=second_metrics,
    )

    assert len(second.segments) == 2
    assert second_metrics.reused_segment_bytes == first_segment.size
    assert second_metrics.bytes_read == 0
    assert second_metrics.bytes_hashed < sum(segment.size for segment in second.segments)
    assert [segment.owner_ordinal for segment in second.segments] == [0, 1]
    assert first_path.stat().st_ino == first_stat.st_ino
    assert first_path.stat().st_mtime_ns == first_stat.st_mtime_ns
    recovery = store.recover(expected_fingerprint=_FINGERPRINT)
    assert recovery.manifest.sequence == 1
    assert store.read_segment(recovery.manifest.segments[0]) == b"first delta" * 100
    assert store.read_segment(recovery.manifest.segments[1]) == b"second delta" * 100


def test_store_rotates_manifests_and_collects_unreferenced_segments(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"retired")
    retired_path = store.workspace / first.segments[0].relative_path
    second = _commit(
        store,
        sequence=1,
        hour=12,
        inherited=first.segments,
        payload=b"retained",
    )
    retained = tuple(
        segment for segment in second.segments if segment.sha256 != first.segments[0].sha256
    )
    _commit(store, sequence=2, hour=18, inherited=retained)
    assert retired_path.exists()
    _commit(store, sequence=3, hour=24, inherited=retained)
    assert not retired_path.exists()
    assert [path.name for path in store._recovery_directories()] == [
        "00000000000000000003",
        "00000000000000000002",
    ]


def test_store_falls_back_when_newest_head_is_corrupt(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"first")
    second = _commit(store, sequence=1, hour=12, inherited=first.segments, payload=b"second")
    newest_head = store.workspace / second.participant_heads[0].relative_path
    newest_head.write_bytes(b"tampered")

    recovery = store.recover(expected_fingerprint=_FINGERPRINT)

    assert recovery.used_fallback
    assert recovery.manifest.sequence == 0
    assert recovery.warning is not None
    assert "newest generation checkpoint was corrupt" in recovery.warning


def test_store_authenticates_manifest_through_recovery_index(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"first")
    second = _commit(store, sequence=1, hour=12, inherited=first.segments, payload=b"second")
    newest_manifest = store.workspace / "recovery" / f"{second.sequence:020d}" / "manifest.json"
    document = json.loads(newest_manifest.read_text(encoding="utf-8"))
    document["metadata"] = {"tampered": True}
    newest_manifest.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    recovery = store.recover(expected_fingerprint=_FINGERPRINT)

    assert recovery.used_fallback
    assert recovery.manifest.sequence == 0
    assert recovery.warning is not None
    assert "manifest failed index validation" in recovery.warning


def test_store_rejects_corrupt_authoritative_recovery_index(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit(store, sequence=0, hour=6, payload=b"first")
    store.index_path.write_text('{"recoveries": []}', encoding="utf-8")

    with pytest.raises(CheckpointCorruptionError, match="invalid entry set"):
        store.recover(expected_fingerprint=_FINGERPRINT)


def test_store_rejects_fingerprint_mismatch_without_falling_back(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    _commit(store, sequence=0, hour=6, payload=b"first")
    with pytest.raises(CheckpointCompatibilityError, match="fingerprint"):
        store.recover(expected_fingerprint="2" * 64)


def test_store_rejects_symlinked_content(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    manifest = _commit(store, sequence=0, hour=6, payload=b"first")
    segment_path = store.workspace / manifest.segments[0].relative_path
    replacement = tmp_path / "replacement"
    replacement.write_bytes(segment_path.read_bytes())
    segment_path.unlink()
    segment_path.symlink_to(replacement)
    with pytest.raises(CheckpointCorruptionError, match="symlink"):
        store.recover(expected_fingerprint=_FINGERPRINT)


def test_store_rejects_resealing_an_inherited_segment(tmp_path: Path) -> None:
    store = IncrementalCheckpointStore(tmp_path / "output")
    first = _commit(store, sequence=0, hour=6, payload=b"same")
    with pytest.raises(ValueError, match="reseal"):
        _commit(
            store,
            sequence=1,
            hour=12,
            inherited=first.segments,
            payload=b"same",
        )


def test_run_lock_rejects_live_owner_and_reclaims_dead_local_owner(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first = RunLock(workspace)
    first.acquire()
    with pytest.raises(CheckpointLockError, match="live process"):
        RunLock(workspace).acquire()
    first.release()

    workspace.mkdir(exist_ok=True)
    lock_path = workspace / "run.lock"
    lock_path.write_text(
        json.dumps({"hostname": socket.gethostname(), "pid": 2**31 - 1}),
        encoding="utf-8",
    )
    replacement = RunLock(workspace)
    replacement.acquire()
    assert json.loads(lock_path.read_text(encoding="utf-8"))["pid"] == os.getpid()
    replacement.release()


def test_manifest_rejects_unknown_segment_reference() -> None:
    with pytest.raises(ValidationError, match="unknown segments"):
        CheckpointManifest(
            sequence=0,
            run_id="run",
            run_fingerprint=_FINGERPRINT,
            checkpoint_hours=6,
            cursor=_cursor(6),
            resolved_scenario_sha256="2" * 64,
            resolved_scenario_relative_path="objects/resolved/22/input.yaml",
            participant_heads=(
                {
                    "owner": "engine",
                    "schema_version": "1",
                    "relative_path": "recovery/0/heads/engine.bin",
                    "size": 1,
                    "sha256": "3" * 64,
                    "referenced_segments": ("4" * 64,),
                },
            ),
        )
