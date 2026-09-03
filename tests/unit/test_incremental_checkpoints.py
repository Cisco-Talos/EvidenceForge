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

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
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
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpRetentionLease,
    RdpSessionAffinity,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.checkpoints.application_channel_head import (
    ApplicationChannelRegistryParticipant,
)
from evidenceforge.generation.checkpoints.cadence import CheckpointCadence
from evidenceforge.generation.checkpoints.cryptographic_material_head import (
    CryptographicMaterialParticipant,
)
from evidenceforge.generation.checkpoints.errors import (
    CheckpointCompatibilityError,
    CheckpointCorruptionError,
    CheckpointError,
    CheckpointLockError,
)
from evidenceforge.generation.checkpoints.http_channel_head import (
    HttpApplicationChannelParticipant,
)
from evidenceforge.generation.checkpoints.intent_ledger_head import (
    IntentExecutionLedgerParticipant,
)
from evidenceforge.generation.checkpoints.lifecycle_head import LifecycleRegistryParticipant
from evidenceforge.generation.checkpoints.models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointStoreMetrics,
)
from evidenceforge.generation.checkpoints.network_runtime_head import (
    NetworkTransactionRuntimeParticipant,
)
from evidenceforge.generation.checkpoints.owner_inventory import (
    APPLICATION_CHANNEL_REGISTRY_CHECKPOINT_FIELDS,
    APPLICATION_CHANNEL_SHARD_CHECKPOINT_FIELDS,
    CRYPTOGRAPHIC_MATERIAL_CHECKPOINT_FIELDS,
    HTTP_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    HTTP_PACKED_TRANSPORT_STORE_CHECKPOINT_FIELDS,
    HTTP_TRANSPORT_SHARD_CHECKPOINT_FIELDS,
    INTENT_EXECUTION_LEDGER_CHECKPOINT_FIELDS,
    LIFECYCLE_PARTITION_CHECKPOINT_FIELDS,
    LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS,
    NETWORK_TRANSACTION_RUNTIME_CHECKPOINT_FIELDS,
    PROXY_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    PROXY_PACKED_TUNNEL_STORE_CHECKPOINT_FIELDS,
    PROXY_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    SMB_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    SMB_SESSION_RECORD_CHECKPOINT_FIELDS,
    SMB_SESSION_STORE_CHECKPOINT_FIELDS,
    SMB_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS,
    SSH_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    SSH_OPERATION_ROUTE_CHECKPOINT_FIELDS,
    SSH_PACKED_OPERATION_STORE_CHECKPOINT_FIELDS,
    SSH_PACKED_SESSION_STORE_CHECKPOINT_FIELDS,
    SSH_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    STATE_MANAGER_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.participants import (
    OwnerStateField,
    ParticipantSeal,
)
from evidenceforge.generation.checkpoints.proxy_channel_head import (
    ExplicitProxyChannelParticipant,
)
from evidenceforge.generation.checkpoints.rdp_head import RdpSessionManagerParticipant
from evidenceforge.generation.checkpoints.rng import (
    GenerationRngParticipant,
    decode_random_state,
    encode_random_state,
)
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.checkpoints.smb_channel_head import (
    SmbApplicationChannelParticipant,
)
from evidenceforge.generation.checkpoints.source_timing_head import (
    SourceTimingPlannerParticipant,
)
from evidenceforge.generation.checkpoints.spools import (
    AppendOnlySpoolParticipant,
    ImmutableSpoolFilesParticipant,
)
from evidenceforge.generation.checkpoints.sqlite_spool import SQLiteSpoolParticipant
from evidenceforge.generation.checkpoints.ssh_channel_head import (
    SshApplicationChannelParticipant,
)
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
from evidenceforge.generation.checkpoints.timing_runtime_head import TimingRuntimeParticipant
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAffinity,
)
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.network_runtime import (
    NetworkRuntimePointFamily,
    NetworkTransactionRuntime,
    NetworkTransportLease,
    _network_transport_occurrence_stable_id,
    _transport_lease_digest_value,
    _TransportLeaseRecord,
)
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
)
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.generation.smb_channels import SmbApplicationChannelManager, SmbChannelAffinity
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.timing.clocks import SourceClockKey, SourceClockSpec
from evidenceforge.models.exceptions import StateError
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
    source_timing = SourceTimingPlanner()
    application_channels = ApplicationChannelRegistry(
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
    )
    intent_execution = IntentExecutionLedger(AuthoredIntentLedger("checkpoint-test", ()))
    network_runtime = NetworkTransactionRuntime(
        state_manager=manager,
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
    )

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
    assert_complete_owner_inventory(
        source_timing,
        SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS,
        owner_name="source-timing",
    )
    assert_complete_owner_inventory(
        application_channels,
        APPLICATION_CHANNEL_REGISTRY_CHECKPOINT_FIELDS,
        owner_name="application-channels",
    )
    assert_complete_owner_inventory(
        intent_execution,
        INTENT_EXECUTION_LEDGER_CHECKPOINT_FIELDS,
        owner_name="intent-execution-ledger",
    )
    assert_complete_owner_inventory(
        network_runtime,
        NETWORK_TRANSACTION_RUNTIME_CHECKPOINT_FIELDS,
        owner_name="network-runtime",
    )
    assert_complete_owner_inventory(
        network_runtime.cryptographic_material,
        CRYPTOGRAPHIC_MATERIAL_CHECKPOINT_FIELDS,
        owner_name="cryptographic-material",
    )
    http = HttpApplicationChannelManager(
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
        registry=application_channels,
    )
    assert_complete_owner_inventory(
        http,
        HTTP_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
        owner_name="http-channels",
    )
    proxy = ExplicitProxyChannelManager(
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
        registry=application_channels,
        shard_count=application_channels.shard_count,
    )
    assert_complete_owner_inventory(
        proxy,
        PROXY_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
        owner_name="proxy-channels",
    )
    ssh = SshApplicationChannelManager(
        application_registry=application_channels,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
    )
    assert_complete_owner_inventory(
        ssh,
        SSH_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
        owner_name="ssh-channels",
    )
    smb = SmbApplicationChannelManager(
        application_registry=application_channels,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 2, tzinfo=UTC),
    )
    assert_complete_owner_inventory(
        smb,
        SMB_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
        owner_name="smb-channels",
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

    smb_manager = StateManager()
    smb_manager._smb_connection_authority_by_conn_id["conn-1"] = object()  # type: ignore[assignment]
    with pytest.raises(CheckpointError, match="_smb_connection_authority_by_conn_id"):
        assert_transient_owner_state_empty(
            smb_manager,
            STATE_MANAGER_CHECKPOINT_FIELDS,
            owner_name="state-manager",
        )


def test_network_runtime_head_round_trips_points_transports_and_freshness() -> None:
    """Hydration should rebuild bounded network authority without heap snapshots."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    state = StateManager()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=started,
        window_end=started + timedelta(days=2),
    )
    runtime.set_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        ("client", "example.test"),
        {"ttl": 300, "answers": ["10.0.0.20"]},
        expires_at=started + timedelta(hours=8),
    )
    runtime.set_point(
        NetworkRuntimePointFamily.TLS_SERVER_NAME,
        "10.0.0.20",
        "example.test",
        expires_at=started + timedelta(hours=2),
    )
    runtime.delete_point(NetworkRuntimePointFamily.TLS_SERVER_NAME, "10.0.0.20")

    lease_opened_at = started + timedelta(minutes=10)
    lease_occurrence_id = _network_transport_occurrence_stable_id(
        "checkpoint-transport",
        src_ip="10.0.0.10",
        src_port=50_000,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        opened_at=lease_opened_at,
    )
    lease = NetworkTransportLease(
        intent_stable_id="checkpoint-transport",
        src_ip="10.0.0.10",
        src_port=50_000,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        opened_at=lease_opened_at,
        closed_at=started + timedelta(hours=3),
        occurrence_stable_id=lease_occurrence_id,
        automatic=False,
    )
    record = _TransportLeaseRecord(
        lease=lease,
        preparation_id=7,
        candidate_inspections=3,
        adaptive_reuse=True,
        committed=True,
    )
    freshness_deadline = started + timedelta(days=1, hours=3)
    with runtime._lock:
        runtime._insert_transport_record_locked(record)
        runtime._transport_lease_deadlines.replace(
            lease.occurrence_stable_id,
            (lease.closed_at, 1, lease.occurrence_stable_id),
        )
        runtime._transport_freshness[lease.tuple_key] = lease.closed_at
        runtime._transport_freshness_deadlines.replace(
            lease.tuple_key,
            (freshness_deadline, 1, lease.tuple_key),
        )
        runtime._live_transport_leases = 1
        runtime._next_preparation_id = 8
        runtime._next_transport_ordinal = 2
        runtime._transport_state_xor ^= runtime._state_component(
            "network-transport-lease-v1",
            _transport_lease_digest_value(lease),
        )
        runtime._transport_state_xor ^= runtime._state_component(
            "network-transport-freshness-v1",
            (lease.tuple_key, lease.closed_at),
        )

    seal = NetworkTransactionRuntimeParticipant(runtime).prepare_checkpoint(0)
    expected_digest = runtime.state_digest()
    restored = NetworkTransactionRuntime(
        state_manager=StateManager(),
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=started,
        window_end=started + timedelta(days=2),
    )
    NetworkTransactionRuntimeParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored.state_digest() == expected_digest
    assert restored.get_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        ("client", "example.test"),
    ) == {"ttl": 300, "answers": ["10.0.0.20"]}
    assert not restored.transport_tuple_interval_available(
        src_ip=lease.src_ip,
        src_port=lease.src_port,
        dst_ip=lease.dst_ip,
        dst_port=lease.dst_port,
        protocol=lease.protocol,
        opened_at=started + timedelta(minutes=30),
        closed_at=started + timedelta(hours=1),
    )
    assert restored.census().live_transport_leases == 1
    page = restored.advance_watermark_page(started + timedelta(hours=4))
    assert not page.has_more
    assert restored.census().live_transport_leases == 0
    assert restored.census().retained_transport_freshness == 1


def test_network_runtime_head_rejects_open_preparation() -> None:
    """A network preparation capability cannot cross a checkpoint barrier."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    runtime = NetworkTransactionRuntime(
        state_manager=StateManager(),
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    preparation = runtime.begin(
        owner_rng=random.Random(5),
        stable_id="checkpoint-open-preparation",
        linearization_time=started,
    )

    with pytest.raises(CheckpointError, match="_open_preparations"):
        NetworkTransactionRuntimeParticipant(runtime).prepare_checkpoint(0)

    preparation.cancel()


def test_network_runtime_head_rejects_modified_semantic_row() -> None:
    """The participant digest should reject a modified but structurally valid row."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    runtime = NetworkTransactionRuntime(
        state_manager=StateManager(),
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    runtime.set_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "example.test",
        300,
        expires_at=started + timedelta(hours=2),
    )
    seal = NetworkTransactionRuntimeParticipant(runtime).prepare_checkpoint(0)
    modified = loads(seal.head.payload)
    assert isinstance(modified, dict)
    points = modified["points"]
    assert isinstance(points, list)
    points[0][3] = 301
    restored = NetworkTransactionRuntime(
        state_manager=StateManager(),
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=started,
        window_end=started + timedelta(days=1),
    )

    with pytest.raises(CheckpointCorruptionError, match="state digest changed"):
        NetworkTransactionRuntimeParticipant(restored).restore_checkpoint(dumps(modified), ())


def test_cryptographic_material_uses_only_new_identity_segments() -> None:
    """Material checkpoints should rebuild values while sealing only new identities."""

    registry = CryptographicMaterialRegistry()
    participant = CryptographicMaterialParticipant(registry)
    authority = registry.resolve_authority(
        subject_name="CN=Checkpoint Root",
        issuer_name="CN=Checkpoint Root",
        key_type="ecdsa",
        key_size=256,
    )
    certificate = registry.resolve_certificate(
        backend_identity="checkpoint-backend",
        subject_name="CN=checkpoint.example.test",
        issuer_name="CN=Checkpoint Root",
        not_valid_before=1_700_000_000,
        not_valid_after=1_800_000_000,
        key_type="ecdsa",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns=("checkpoint.example.test",),
    )
    dkim = registry.resolve_dkim_key("example.test", "selector-a")

    first = participant.prepare_checkpoint(0)
    assert len(first.segments) == 1
    participant.checkpoint_committed(0)
    registry.public_key_spki("second-key", key_type="rsa", key_size=2048)
    second = participant.prepare_checkpoint(1)
    assert len(second.segments) == 1
    assert second.segments[0].record_count == 1
    participant.checkpoint_committed(1)

    restored = CryptographicMaterialRegistry()
    restored_participant = CryptographicMaterialParticipant(restored)
    restored_participant.restore_checkpoint(
        second.head.payload,
        (first.segments[0].payload, second.segments[0].payload),
    )

    assert restored.state_digest() == registry.state_digest()
    assert (
        restored.resolve_authority(
            subject_name="CN=Checkpoint Root",
            issuer_name="CN=Checkpoint Root",
            key_type="ecdsa",
            key_size=256,
        )
        == authority
    )
    assert (
        restored.resolve_certificate(
            backend_identity="checkpoint-backend",
            subject_name="CN=checkpoint.example.test",
            issuer_name="CN=Checkpoint Root",
            not_valid_before=1_700_000_000,
            not_valid_after=1_800_000_000,
            key_type="ecdsa",
            key_size=256,
            signature_algorithm="ecdsa-with-SHA256",
            san_dns=("checkpoint.example.test",),
        )
        == certificate
    )
    assert restored.resolve_dkim_key("example.test", "selector-a") == dkim
    unchanged = restored_participant.prepare_checkpoint(2)
    assert not unchanged.segments


def test_cryptographic_material_rejects_prepared_overlay() -> None:
    """A sealed TLS overlay cannot cross a checkpoint barrier."""

    registry = CryptographicMaterialRegistry()
    participant = CryptographicMaterialParticipant(registry)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("prepared-key", key_type="ecdsa", key_size=256)
    preparation.seal()

    with pytest.raises(CheckpointError, match="_tls_point_reservations"):
        participant.prepare_checkpoint(0)

    assert preparation.cancel()


def test_http_channel_head_round_trips_open_transport_and_reuses_it() -> None:
    """HTTP hydration should rebuild packed sidecar indexes against shared authority."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    ended = started + timedelta(days=1)
    registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    manager = HttpApplicationChannelManager(
        window_start=started,
        window_end=ended,
        registry=registry,
    )
    affinity = HttpChannelAffinity.from_request(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.20",
        dst_port=443,
        http_host="checkpoint.example.test",
        user_agent="Mozilla/5.0",
        transport_security="tls",
    )
    transport = manager.open_transport(
        affinity,
        transport_id="checkpoint-http-transport",
        zeek_uid="CHECKPOINT-UID",
        conn_id="checkpoint-conn",
        src_port=50_001,
        opened_at=started,
        closes_at=started + timedelta(minutes=30),
        initial_request_time=started + timedelta(seconds=1),
        orig_budget=1_000,
        resp_budget=10_000,
    )
    assert transport is not None
    application_seal = ApplicationChannelRegistryParticipant(registry).prepare_checkpoint(0)
    http_seal = HttpApplicationChannelParticipant(manager).prepare_checkpoint(0)
    assert not http_seal.segments

    restored_registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    ApplicationChannelRegistryParticipant(restored_registry).restore_checkpoint(
        application_seal.head.payload,
        (),
    )
    restored = HttpApplicationChannelManager(
        window_start=started,
        window_end=ended,
        registry=restored_registry,
    )
    HttpApplicationChannelParticipant(restored).restore_checkpoint(http_seal.head.payload, ())

    assert restored.get_transport(transport.channel_id) == transport
    reused = restored.reserve_reuse(
        affinity,
        requested_at=started + timedelta(seconds=10),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert reused is not None
    assert reused.channel_id == transport.channel_id
    shard = next(iter(restored._shards.values()))
    assert_complete_owner_inventory(
        shard,
        HTTP_TRANSPORT_SHARD_CHECKPOINT_FIELDS,
        owner_name="http-transport-shard",
    )
    assert_complete_owner_inventory(
        shard.transports,
        HTTP_PACKED_TRANSPORT_STORE_CHECKPOINT_FIELDS,
        owner_name="http-packed-transport-store",
    )


def test_http_channel_head_rejects_prepared_admission() -> None:
    """A coupled HTTP/application admission cannot cross the barrier."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager = HttpApplicationChannelManager(
        window_start=started,
        window_end=started + timedelta(days=1),
        registry=registry,
    )
    affinity = HttpChannelAffinity.from_request(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.20",
        dst_port=80,
        http_host="checkpoint.example.test",
    )
    token = manager.prepare_open_transport(
        affinity,
        transport_id="checkpoint-http-prepared",
        zeek_uid="CHECKPOINT-PREPARED",
        conn_id="checkpoint-prepared",
        src_port=50_002,
        opened_at=started,
        closes_at=started + timedelta(minutes=5),
        initial_request_time=started + timedelta(seconds=1),
        orig_budget=1_000,
        resp_budget=10_000,
    )
    assert token is not None

    with pytest.raises(CheckpointError, match="_prepared_admissions"):
        HttpApplicationChannelParticipant(manager).prepare_checkpoint(0)

    assert manager.cancel_prepared_admission(token)


def test_proxy_channel_head_round_trips_open_tunnel_and_reuses_it() -> None:
    """Proxy hydration should rebuild channel, affinity, origin, and expiry routes."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    ended = started + timedelta(days=1)
    registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    manager = ExplicitProxyChannelManager(
        window_start=started,
        window_end=ended,
        registry=registry,
        shard_count=registry.shard_count,
    )
    affinity = ExplicitProxyChannelAffinity(
        client_ip="10.0.0.10",
        proxy_ip="10.0.3.10",
        proxy_port=8080,
        origin_host="checkpoint.example.test",
        origin_ip="203.0.113.20",
        origin_port=443,
        user_agent="Mozilla/5.0",
        auth_identity="EXAMPLE\\Alice",
        policy_id="checkpoint-policy",
    )
    opened = manager.open_tunnel(
        affinity,
        client_transport_id="checkpoint-client-transport",
        origin_transport_id="checkpoint-origin-transport",
        client_zeek_uid="CHECKPOINT-CLIENT",
        origin_zeek_uid="CHECKPOINT-ORIGIN",
        tunnel_group_id="checkpoint-tunnel-group",
        client_source_port=50_010,
        origin_source_port=40_010,
        opened_at=started,
        closes_at=started + timedelta(minutes=30),
        setup_started_at=started + timedelta(milliseconds=10),
        setup_completed_at=started + timedelta(milliseconds=30),
        setup_request_wire_bytes=120,
        setup_response_wire_bytes=240,
        planned_request_count=2,
        aggregate_request_wire_bytes=1_000,
        aggregate_response_wire_bytes=5_000,
    )
    assert opened is not None
    application_seal = ApplicationChannelRegistryParticipant(registry).prepare_checkpoint(0)
    proxy_seal = ExplicitProxyChannelParticipant(manager).prepare_checkpoint(0)

    restored_registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    ApplicationChannelRegistryParticipant(restored_registry).restore_checkpoint(
        application_seal.head.payload,
        (),
    )
    restored = ExplicitProxyChannelManager(
        window_start=started,
        window_end=ended,
        registry=restored_registry,
        shard_count=restored_registry.shard_count,
    )
    ExplicitProxyChannelParticipant(restored).restore_checkpoint(proxy_seal.head.payload, ())

    assert restored.get_tunnel(opened.tunnel.channel_id) == opened.tunnel
    reused = restored.reserve_request(
        affinity,
        requested_at=started + timedelta(seconds=1),
        completed_at=started + timedelta(seconds=2),
        request_wire_bytes=100,
        response_wire_bytes=500,
    )
    assert reused is not None
    assert reused.tunnel.channel_id == opened.tunnel.channel_id
    shard = next(iter(restored._shards.values()))
    assert_complete_owner_inventory(
        shard,
        PROXY_SIDECAR_SHARD_CHECKPOINT_FIELDS,
        owner_name="proxy-sidecar-shard",
    )
    assert_complete_owner_inventory(
        shard.tunnels,
        PROXY_PACKED_TUNNEL_STORE_CHECKPOINT_FIELDS,
        owner_name="proxy-packed-tunnel-store",
    )


def test_proxy_channel_head_rejects_prepared_admission() -> None:
    """A coupled proxy/application admission cannot cross the barrier."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager = ExplicitProxyChannelManager(
        window_start=started,
        window_end=started + timedelta(days=1),
        registry=registry,
        shard_count=registry.shard_count,
    )
    affinity = ExplicitProxyChannelAffinity(
        client_ip="10.0.0.10",
        proxy_ip="10.0.3.10",
        proxy_port=8080,
        origin_host="checkpoint.example.test",
        origin_ip="203.0.113.20",
        origin_port=443,
        user_agent="Mozilla/5.0",
        auth_identity="",
        policy_id="checkpoint-policy",
    )
    token = manager.prepare_open_tunnel(
        affinity,
        client_transport_id="checkpoint-prepared-client",
        origin_transport_id="checkpoint-prepared-origin",
        client_zeek_uid="CHECKPOINT-PREPARED-CLIENT",
        origin_zeek_uid="CHECKPOINT-PREPARED-ORIGIN",
        tunnel_group_id="checkpoint-prepared-group",
        client_source_port=50_011,
        origin_source_port=40_011,
        opened_at=started,
        closes_at=started + timedelta(minutes=5),
        setup_started_at=started + timedelta(milliseconds=10),
        setup_completed_at=started + timedelta(milliseconds=30),
        setup_request_wire_bytes=120,
        setup_response_wire_bytes=240,
        planned_request_count=1,
        aggregate_request_wire_bytes=1_000,
        aggregate_response_wire_bytes=5_000,
    )
    assert token is not None

    with pytest.raises(CheckpointError, match="_prepared_admissions"):
        ExplicitProxyChannelParticipant(manager).prepare_checkpoint(0)

    assert manager.cancel_prepared_admission(token)


def test_ssh_channel_head_round_trips_open_session_and_active_operation() -> None:
    """SSH hydration should rebuild packed sessions, children, routes, and expiry."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    ended = started + timedelta(days=1)
    registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    manager = SshApplicationChannelManager(
        application_registry=registry,
        window_start=started,
        window_end=ended,
    )
    closes_at = started + timedelta(minutes=30)
    affinity = SshChannelAffinity(
        client_identity="client.example.test",
        client_session_object_id="checkpoint-client-session",
        server_identity="server.example.test",
        server_session_object_id="checkpoint-server-session",
        principal="checkpoint-user",
        auth_method="publickey",
    )
    source_process = SshProcessHold(
        hostname=affinity.client_identity,
        pid=40_001,
        process_object_id="checkpoint-ssh-client-process",
        session_object_id=affinity.client_session_object_id,
        principal="checkpoint-local-user",
        started_at=started,
        required_until=closes_at,
    )
    receiver_process = SshProcessHold(
        hostname=affinity.server_identity,
        pid=40_002,
        process_object_id="checkpoint-sshd-process",
        session_object_id=affinity.server_session_object_id,
        principal=affinity.principal,
        started_at=started,
        required_until=closes_at,
    )
    transport = SshTransportPlan(
        transport_id="checkpoint-ssh-transport",
        zeek_uid="CHECKPOINT-SSH",
        conn_id="checkpoint-ssh-connection",
        source_ip="10.0.0.10",
        server_ip="10.0.0.20",
        source_port=50_022,
        server_port=22,
        opened_at=started + timedelta(seconds=1),
        closes_at=closes_at,
        receiver_process=receiver_process,
        source_process=source_process,
    )
    binding = SshSessionBinding(
        hostname=affinity.server_identity,
        logon_id="0x00000042",
        session_object_id=affinity.server_session_object_id,
        lifecycle_group_id="checkpoint-ssh-lifecycle",
        principal=affinity.principal,
        ready_at=started + timedelta(seconds=2),
    )
    session = manager.open_session(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=10),
        initiator_budget=10_000,
        responder_budget=20_000,
        operation_budget=4,
    )
    operation = manager.reserve_operation(
        session,
        kind=SshOperationKind.EXEC,
        semantic_operation_id="checkpoint-command",
        started_at=started + timedelta(seconds=3),
        ended_at=started + timedelta(seconds=4),
        initiator_bytes=100,
        responder_bytes=200,
    )
    application_seal = ApplicationChannelRegistryParticipant(registry).prepare_checkpoint(0)
    ssh_seal = SshApplicationChannelParticipant(manager).prepare_checkpoint(0)

    restored_registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    ApplicationChannelRegistryParticipant(restored_registry).restore_checkpoint(
        application_seal.head.payload,
        (),
    )
    restored = SshApplicationChannelManager(
        application_registry=restored_registry,
        window_start=started,
        window_end=ended,
    )
    SshApplicationChannelParticipant(restored).restore_checkpoint(ssh_seal.head.payload, ())

    assert restored.session_view(session.channel_id) == session
    assert restored.operation_lease(operation.operation_id) == operation
    assert restored.finalize_operation(operation.operation_id)
    assert (
        restored.close_session(
            session.channel_id,
            closed_at=started + timedelta(seconds=5),
            reason="checkpoint-test",
        )
        is not None
    )
    shard = next(iter(manager._shards.values()))
    assert_complete_owner_inventory(
        shard,
        SSH_SIDECAR_SHARD_CHECKPOINT_FIELDS,
        owner_name="ssh-sidecar-shard",
    )
    assert_complete_owner_inventory(
        shard.sessions,
        SSH_PACKED_SESSION_STORE_CHECKPOINT_FIELDS,
        owner_name="ssh-packed-session-store",
    )
    assert_complete_owner_inventory(
        shard.operations,
        SSH_PACKED_OPERATION_STORE_CHECKPOINT_FIELDS,
        owner_name="ssh-packed-operation-store",
    )
    route = next(item for item in manager._operation_routes if item is not None)
    assert_complete_owner_inventory(
        route,
        SSH_OPERATION_ROUTE_CHECKPOINT_FIELDS,
        owner_name="ssh-operation-route",
    )


def test_ssh_channel_head_rejects_prepared_admission_state() -> None:
    """Prepared SSH capability state cannot cross the checkpoint barrier."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager = SshApplicationChannelManager(
        application_registry=registry,
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager._prepared_admissions[1] = object()  # type: ignore[assignment]

    with pytest.raises(CheckpointError, match="_prepared_admissions"):
        SshApplicationChannelParticipant(manager).prepare_checkpoint(0)


def test_smb_channel_head_round_trips_reusable_session_and_sensor_view() -> None:
    """SMB hydration should rebuild open session/tree state and exact sensor views."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    ended = started + timedelta(days=1)
    closes_at = started + timedelta(hours=1)
    registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    manager = SmbApplicationChannelManager(
        application_registry=registry,
        window_start=started,
        window_end=ended,
    )
    affinity = SmbChannelAffinity(
        client_identity="CLIENT01",
        client_ip="10.0.0.10",
        client_session="0x1001",
        server_identity="FILE01",
        server_ip="10.0.0.20",
        principal="EXAMPLE\\analyst",
        auth_protocol="Kerberos",
        account_scope="EXAMPLE",
        dialect="3.1.1",
        signing_policy="required",
        encryption_policy="off",
        server_policy="windows:file-server",
        share_policy="disk:standard",
        client_access="windows_native",
    )
    traffic = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=100, packets=1, ip_bytes=140),
        resp=DirectionalTrafficLedger(payload_bytes=200, packets=1, ip_bytes=240),
    )
    plan = NetworkTransactionPlan(
        stable_id="checkpoint-smb-transport",
        hostname="file01.example.test",
        outcome="success",
        phase_times=(("attempt", started), ("close", closes_at)),
        started_at=started,
        closed_at=closes_at,
        src_ip="10.0.0.10",
        src_port=50_445,
        dst_ip="10.0.0.20",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid="CHECKPOINT-SMB",
        conn_id="checkpoint-smb-connection",
        duration=timedelta(hours=1).total_seconds(),
        conn_state="SF",
        history="ShADadfF",
        traffic=traffic,
    )
    observation = NetworkSensorObservation(
        sensor_identity="checkpoint-sensor",
        path_role="internal",
        capture_profile="full",
        tuple_view=NetworkTuple("10.0.0.10", 50_445, "10.0.0.20", 445, "tcp"),
        connection_uid="CHECKPOINT-SMB",
        connection_ids=((plan.stable_id, plan.conn_id),),
        file_ids=(),
        local_orig=True,
        local_resp=True,
        observed_start_time=started,
        observed_close_time=closes_at,
        traffic=traffic,
        visible_formats=frozenset({"zeek"}),
        history="ShADadfF",
    )
    lease = manager.open_session(
        affinity,
        transport_plan=plan,
        sensor_observations=(observation,),
        ground_truth_transport_uid=plan.zeek_uid,
        logon_id="0xA1",
        auth_session_ref="checkpoint-smb-auth",
        principal="EXAMPLE\\analyst",
        auth_protocol="kerberos",
        account_scope="EXAMPLE",
        effective_uid=None,
        effective_gid=None,
        client_access="windows_native",
        server_hostname="FILE01",
        client_ip="10.0.0.10",
        lifecycle_group_id=plan.stable_id,
        share_ref="FILE01.Documents",
        semantic_operation_id="checkpoint-operation-1",
        operation_started_at=started + timedelta(milliseconds=100),
        operation_ended_at=started + timedelta(seconds=1),
        operation_initiator_bytes=100,
        operation_responder_bytes=200,
        idle_timeout=timedelta(minutes=15),
        initiator_budget=10_000,
        responder_budget=100_000,
        operation_budget=10,
        operation_completes_immediately=True,
    )
    expected = manager.session_view(lease.channel_id)
    application_seal = ApplicationChannelRegistryParticipant(registry).prepare_checkpoint(0)
    smb_seal = SmbApplicationChannelParticipant(manager).prepare_checkpoint(0)

    restored_registry = ApplicationChannelRegistry(window_start=started, window_end=ended)
    ApplicationChannelRegistryParticipant(restored_registry).restore_checkpoint(
        application_seal.head.payload,
        (),
    )
    restored = SmbApplicationChannelManager(
        application_registry=restored_registry,
        window_start=started,
        window_end=ended,
    )
    SmbApplicationChannelParticipant(restored).restore_checkpoint(smb_seal.head.payload, ())

    assert restored.session_view(lease.channel_id) == expected
    reuse = restored.reserve_reuse(
        affinity,
        share_ref="file01.documents",
        semantic_operation_id="checkpoint-operation-2",
        requested_at=started + timedelta(seconds=2),
        required_until=started + timedelta(seconds=3),
        initiator_bytes=110,
        responder_bytes=220,
    ).lease
    assert reuse is not None
    assert reuse.reused_session
    assert restored.finalize_operation(reuse)
    shard = next(iter(restored._shards.values()))
    assert_complete_owner_inventory(
        shard,
        SMB_SIDECAR_SHARD_CHECKPOINT_FIELDS,
        owner_name="smb-sidecar-shard",
    )
    assert_complete_owner_inventory(
        shard.sessions,
        SMB_SESSION_STORE_CHECKPOINT_FIELDS,
        owner_name="smb-session-store",
    )
    record = next(iter(shard.sessions.values()))
    assert_complete_owner_inventory(
        record,
        SMB_SESSION_RECORD_CHECKPOINT_FIELDS,
        owner_name="smb-session-record",
    )


def test_smb_channel_head_rejects_prepared_admission_state() -> None:
    """Prepared SMB capability state cannot cross the checkpoint barrier."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager = SmbApplicationChannelManager(
        application_registry=registry,
        window_start=started,
        window_end=started + timedelta(days=1),
    )
    manager._prepared_admissions[1] = object()  # type: ignore[assignment]

    with pytest.raises(CheckpointError, match="_prepared_admissions"):
        SmbApplicationChannelParticipant(manager).prepare_checkpoint(0)


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


def test_source_timing_head_round_trips_every_bounded_index_family() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    planner = SourceTimingPlanner()
    expected: dict[str, tuple[object, object]] = {}
    for ordinal, family in enumerate(planner.index_family_specs):
        loaded = planner.load_probe_entry(family.name, ordinal, started)
        cache = dict(planner._bounded_indexes())[family.name]
        value = cache.raw_get(loaded.key)
        assert value is not None
        expected[family.name] = (loaded.key, value)

    participant = SourceTimingPlannerParticipant(planner)
    seal = participant.prepare_checkpoint(0)
    assert not seal.segments

    restored = SourceTimingPlanner()
    SourceTimingPlannerParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored._watermark == planner._watermark
    for family, cache in restored._bounded_indexes():
        key, value = expected[family]
        assert cache.raw_get(key) == value


def test_source_timing_barrier_rejects_open_preparation_authority() -> None:
    planner = SourceTimingPlanner()
    planner._active_preparation_claims = 1

    with pytest.raises(CheckpointError, match="_active_preparation_claims"):
        SourceTimingPlannerParticipant(planner).prepare_checkpoint(0)


def _application_identity(
    channel_id: str,
    transport_id: str,
    started: datetime,
) -> ApplicationChannelIdentity:
    return ApplicationChannelIdentity(
        channel_id=channel_id,
        protocol="http",
        owner_id="host-1",
        affinity_digest=f"affinity-{channel_id}",
        binding=ApplicationTransportBinding(
            transport_id=transport_id,
            opened_at=started,
            closes_at=started + timedelta(hours=1),
        ),
        opened_at=started,
        idle_timeout=timedelta(minutes=10),
        hard_deadline=started + timedelta(hours=1),
        budget=ApplicationChannelBudget(
            initiator_bytes=1000,
            responder_bytes=2000,
            operations=10,
        ),
    )


def test_application_channel_head_restores_open_closed_active_and_used_state() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(hours=2),
        shard_count=4,
    )
    first_identity = _application_identity("channel-1", "transport-1", started)
    second_identity = _application_identity("channel-2", "transport-2", started)
    registry.open_channel(first_identity)
    registry.open_channel(second_identity)
    completed = ApplicationOperationReservation(
        operation_id="operation-completed",
        channel_id="channel-1",
        ordinal=0,
        started_at=started + timedelta(seconds=1),
        ended_at=started + timedelta(seconds=2),
        initiator_bytes=10,
        responder_bytes=20,
    )
    active = ApplicationOperationReservation(
        operation_id="operation-active",
        channel_id="channel-2",
        ordinal=0,
        started_at=started + timedelta(seconds=3),
        ended_at=started + timedelta(minutes=1),
        initiator_bytes=30,
        responder_bytes=40,
    )
    registry.reserve_completed_operation(completed)
    registry.reserve_operation(active)
    registry.close_channel(
        "channel-1",
        closed_at=started + timedelta(seconds=4),
        reason="complete",
    )
    registry.watermark(started + timedelta(seconds=5))
    expected_first = registry.get("channel-1")
    expected_second = registry.get("channel-2")

    participant = ApplicationChannelRegistryParticipant(registry)
    seal = participant.prepare_checkpoint(0)
    restored = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(hours=2),
        shard_count=2,
    )
    ApplicationChannelRegistryParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored.get("channel-1") == expected_first
    assert restored.get("channel-2") == expected_second
    assert restored.census().active_operations == 1
    assert restored.census().used_operation_ids == 2
    assert restored.finalize_operation("operation-active")
    with pytest.raises(StateError, match="already used"):
        restored.reserve_completed_operation(completed)
    for shard in restored._shards.values():
        assert_complete_owner_inventory(
            shard,
            APPLICATION_CHANNEL_SHARD_CHECKPOINT_FIELDS,
            owner_name="application-channel-shard",
        )


def test_application_channel_barrier_rejects_retained_capabilities() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    registry = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(hours=1),
    )
    registry._recoverable_admission_slots.add(1)

    with pytest.raises(CheckpointError, match="_recoverable_admission_slots"):
        ApplicationChannelRegistryParticipant(registry).prepare_checkpoint(0)


def test_intent_execution_head_round_trips_bounded_aggregates_and_hot_identity() -> None:
    authored = AuthoredIntentLedger("checkpoint-test", ())
    ledger = IntentExecutionLedger(authored, hot_identity_capacity=16)
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    occurrence = SemanticOccurrenceKey(
        action_id="action-1",
        role=OccurrenceRole.PRIMARY,
        instance_key="instance-1",
    )
    ledger.mark_planned("unexpected-intent")
    ledger.record_occurrence("unexpected-intent", occurrence, timestamp)
    ledger.record_occurrence("unexpected-intent", occurrence, timestamp + timedelta(seconds=1))
    ledger.record_observation(
        "unexpected-intent",
        "windows_security",
        "visible",
        timestamp + timedelta(seconds=2),
    )

    seal = IntentExecutionLedgerParticipant(ledger).prepare_checkpoint(0)
    assert not seal.segments
    restored = IntentExecutionLedger(authored, hot_identity_capacity=16)
    IntentExecutionLedgerParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored.snapshot() == ledger.snapshot()
    assert restored.diagnostics() == ledger.diagnostics()
    ledger.record_occurrence("unexpected-intent", occurrence, timestamp + timedelta(hours=1))
    restored.record_occurrence("unexpected-intent", occurrence, timestamp + timedelta(hours=1))
    assert restored.snapshot() == ledger.snapshot()


def test_intent_execution_barrier_rejects_prepared_batch_authority() -> None:
    ledger = IntentExecutionLedger(AuthoredIntentLedger("checkpoint-test", ()))
    ledger._batch_claimed_reservations = 1

    with pytest.raises(CheckpointError, match="_batch_claimed_reservations"):
        IntentExecutionLedgerParticipant(ledger).prepare_checkpoint(0)


def test_rdp_head_restores_sessions_operations_leases_and_application_bindings() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    ended = started + timedelta(hours=2)
    application = ApplicationChannelRegistry(window_start=started, window_end=ended)
    manager = RdpReconnectStateManager(
        application_registry=application,
        window_start=started,
        window_end=ended,
    )
    identity = RdpLogicalSessionIdentity(
        logical_session_id="rdp-logical-1",
        affinity=RdpSessionAffinity(
            source_host="client.example.test",
            source_address="10.0.0.1",
            target_host="server.example.test",
            target_address="10.0.0.2",
            principal="EXAMPLE\\user",
            logon_id="0x100",
            session_id=1,
        ),
        started_at=started,
        idle_timeout=timedelta(minutes=20),
        reconnect_timeout=timedelta(minutes=10),
        hard_deadline=ended,
        budget=ApplicationChannelBudget(10_000, 20_000, 10),
    )
    transport = RdpTransportPlan(
        channel_id="rdp-channel-1",
        binding=ApplicationTransportBinding(
            transport_id="rdp-transport-1",
            opened_at=started,
            closes_at=ended,
        ),
        connected_at=started,
        budget=ApplicationChannelBudget(5_000, 10_000, 5),
    )
    manager.open_session(identity, transport)
    operation = manager.reserve_operation(
        identity.logical_session_id,
        started_at=started + timedelta(seconds=1),
        ended_at=started + timedelta(minutes=1),
        initiator_bytes=100,
        responder_bytes=200,
    )
    lease = RdpRetentionLease(
        lease_id="lease-1",
        logical_session_id=identity.logical_session_id,
        acquired_at=started + timedelta(seconds=2),
        retain_until=started + timedelta(minutes=30),
        reason="checkpoint test",
    )
    manager.add_retention_lease(lease)
    expected = manager.get(identity.logical_session_id)

    application_seal = ApplicationChannelRegistryParticipant(application).prepare_checkpoint(0)
    rdp_seal = RdpSessionManagerParticipant(manager).prepare_checkpoint(0)
    restored_application = ApplicationChannelRegistry(window_start=started, window_end=ended)
    ApplicationChannelRegistryParticipant(restored_application).restore_checkpoint(
        application_seal.head.payload,
        (),
    )
    restored = RdpReconnectStateManager(
        application_registry=restored_application,
        window_start=started,
        window_end=ended,
    )
    RdpSessionManagerParticipant(restored).restore_checkpoint(rdp_seal.head.payload, ())

    assert restored.get(identity.logical_session_id) == expected
    assert restored.census().active_operations == 1
    assert restored.census().active_leases == 1
    assert restored.finalize_operation(
        identity.logical_session_id, operation.reservation.operation_id
    )
    assert restored.release_retention_lease(
        identity.logical_session_id,
        lease.lease_id,
        released_at=started + timedelta(minutes=2),
    )


def test_rdp_barrier_rejects_active_mutation_claim() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    application = ApplicationChannelRegistry(
        window_start=started,
        window_end=started + timedelta(hours=1),
    )
    manager = RdpReconnectStateManager(
        application_registry=application,
        window_start=started,
        window_end=started + timedelta(hours=1),
    )
    manager._mutating_logical_session_ids["rdp-logical-1"] = 1

    with pytest.raises(CheckpointError, match="_mutating_logical_session_ids"):
        RdpSessionManagerParticipant(manager).prepare_checkpoint(0)


def test_timing_runtime_head_restores_exact_audit_and_rebuilds_clock_cache() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    runtime = TimingRuntime(reference_time=started, max_audit_relationship_keys=8)
    key = SourceClockKey(kind="sensor", identity="zeek-1", profile="default")
    spec = SourceClockSpec()
    expected_adjustment = runtime.clocks.adjustment(
        started + timedelta(hours=1), key=key, spec=spec
    )
    runtime.audit.record_repair("network.connection.order")
    runtime.audit.record_saturation("network.connection.window")
    runtime.audit.record_fallback("network.connection.fallback")

    seal = TimingRuntimeParticipant(runtime).prepare_checkpoint(0)
    restored = TimingRuntime(reference_time=started, max_audit_relationship_keys=8)
    TimingRuntimeParticipant(restored).restore_checkpoint(seal.head.payload, ())

    assert restored.audit.snapshot() == runtime.audit.snapshot()
    assert restored.clocks.cache_size == 0
    assert (
        restored.clocks.adjustment(started + timedelta(hours=1), key=key, spec=spec)
        == expected_adjustment
    )
    runtime.clocks.adjustment(started + timedelta(hours=1), key=key, spec=spec)
    assert restored.audit.snapshot() == runtime.audit.snapshot()


def test_timing_runtime_barrier_rejects_owner_claim() -> None:
    runtime = TimingRuntime(reference_time=datetime(2026, 1, 1, tzinfo=UTC))
    runtime._owner_lane = object()

    with pytest.raises(CheckpointError, match="_owner_lane"):
        TimingRuntimeParticipant(runtime).prepare_checkpoint(0)


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
