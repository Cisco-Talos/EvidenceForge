# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contract tests for bounded SSH application child channels."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest

import evidenceforge.generation.ssh_channels as ssh_channels
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshSessionView,
    SshTransportPlan,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 1, tzinfo=UTC)
_END = _START + timedelta(days=31)


def _manager(
    *,
    start: datetime = _START,
    end: datetime = _END,
) -> tuple[SshApplicationChannelManager, ApplicationChannelRegistry]:
    application = ApplicationChannelRegistry(window_start=start, window_end=end)
    return (
        SshApplicationChannelManager(
            application_registry=application,
            window_start=start,
            window_end=end,
        ),
        application,
    )


def _session_values(
    index: int,
    *,
    opened_at: datetime = _START + timedelta(minutes=1),
    duration: timedelta = timedelta(minutes=30),
) -> tuple[SshChannelAffinity, SshTransportPlan, SshSessionBinding]:
    closes_at = opened_at + duration
    client = f"client-{index}"
    server = f"server-{index}"
    client_session = f"client-session-{index}"
    server_session = f"server-session-{index}"
    affinity = SshChannelAffinity(
        client_identity=client,
        client_session_object_id=client_session,
        server_identity=server,
        server_session_object_id=server_session,
        principal=f"user-{index}",
        auth_method="publickey",
    )
    source = SshProcessHold(
        hostname=client,
        pid=10_000 + index,
        process_object_id=f"source-process-{index}",
        session_object_id=client_session,
        principal=f"local-{index}",
        started_at=opened_at - timedelta(seconds=2),
        required_until=closes_at,
    )
    receiver = SshProcessHold(
        hostname=server,
        pid=20_000 + index,
        process_object_id=f"receiver-process-{index}",
        session_object_id=server_session,
        principal=f"user-{index}",
        started_at=opened_at - timedelta(seconds=1),
        required_until=closes_at,
    )
    transport = SshTransportPlan(
        transport_id=f"transport-{index}",
        zeek_uid=f"Cssh{index:016d}",
        conn_id=f"conn-{index}",
        source_ip=f"10.10.{index // 250}.{index % 250 + 1}",
        server_ip=f"10.20.{index // 250}.{index % 250 + 1}",
        source_port=40_000 + index % 20_000,
        server_port=22,
        opened_at=opened_at,
        closes_at=closes_at,
        source_process=source,
        receiver_process=receiver,
    )
    binding = SshSessionBinding(
        hostname=server,
        logon_id=f"0x{index + 1:08x}",
        session_object_id=server_session,
        lifecycle_group_id=f"ssh-lifecycle-{index}",
        principal=f"user-{index}",
        ready_at=opened_at + timedelta(seconds=1),
    )
    return affinity, transport, binding


def _open(
    manager: SshApplicationChannelManager,
    index: int,
    *,
    opened_at: datetime = _START + timedelta(minutes=1),
    duration: timedelta = timedelta(minutes=30),
    idle_timeout: timedelta | None = None,
    initiator_budget: int = 1_000_000,
    responder_budget: int = 1_000_000,
    operation_budget: int = 32,
) -> SshSessionView:
    affinity, transport, binding = _session_values(
        index,
        opened_at=opened_at,
        duration=duration,
    )
    return manager.open_session(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=idle_timeout or duration,
        initiator_budget=initiator_budget,
        responder_budget=responder_budget,
        operation_budget=operation_budget,
    )


def _reserve(
    manager: SshApplicationChannelManager,
    session: SshSessionView,
    *,
    semantic_id: str = "operation-0",
    kind: SshOperationKind = SshOperationKind.SHELL,
    offset: timedelta = timedelta(seconds=2),
    duration: timedelta = timedelta(seconds=1),
    initiator_bytes: int = 100,
    responder_bytes: int = 200,
    parent_operation_id: str = "",
):
    started_at = session.binding.ready_at + offset
    return manager.reserve_operation(
        session,
        kind=kind,
        semantic_operation_id=semantic_id,
        started_at=started_at,
        ended_at=started_at + duration,
        initiator_bytes=initiator_bytes,
        responder_bytes=responder_bytes,
        parent_operation_id=parent_operation_id,
    )


def test_ssh_session_binds_exact_transport_lifecycle_and_process_holds() -> None:
    manager, application = _manager()
    session = _open(manager, 1)

    assert manager.session_view(session.channel_id) == session
    assert manager.find_by_transport(session.transport.transport_id) == session
    assert manager.find_reusable_session(session.affinity, at=session.binding.ready_at) == session
    snapshot = application.get(session.channel_id)
    assert snapshot is not None
    assert snapshot.identity.protocol == "ssh"
    assert snapshot.identity.binding.transport_id == session.transport.transport_id
    assert session.binding.session_object_id == session.affinity.server_session_object_id
    assert session.transport.receiver_process.session_object_id == session.binding.session_object_id
    assert session.transport.source_process is not None
    assert (
        session.transport.source_process.session_object_id
        == session.affinity.client_session_object_id
    )
    assert manager.census().sidecar_lookup_candidates_inspected <= 6


def test_ssh_hot_exact_cache_skips_primary_route_and_rejects_retired_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, application = _manager()
    session = _open(manager, 3)

    assert manager.session_view(session.channel_id) == session
    cold_candidates = manager.census().sidecar_lookup_candidates_inspected
    original_route = application.owner_partition_for_channel

    def reject_primary_route(_channel_id: str) -> int | None:
        raise AssertionError("warmed SSH exact lookup revisited the common primary route")

    monkeypatch.setattr(application, "owner_partition_for_channel", reject_primary_route)
    assert manager.session_view(session.channel_id) == session
    census = manager.census()
    assert census.sidecar_lookup_candidates_inspected == cold_candidates + 1
    assert census.decoded_cache_entries >= 1
    assert census.decoded_cache_capacity >= 16_384
    assert census.decoded_cache_estimated_bytes > 0

    closed = manager.close_session(
        session.channel_id,
        closed_at=session.binding.ready_at + timedelta(seconds=2),
        reason="client_close",
    )
    assert closed is not None
    monkeypatch.setattr(application, "owner_partition_for_channel", original_route)
    assert manager.session_view(session.channel_id) is None


def test_ssh_packed_session_preserves_arbitrary_wide_descriptors_exactly() -> None:
    manager, _application = _manager()
    affinity, transport, binding = _session_values(2)
    client_identity = "external-client.example.test"
    client_session = "opaque-client-session/" + ("x" * 280)
    source = replace(
        transport.source_process,
        hostname=client_identity,
        process_object_id="opaque-source-process/" + ("y" * 280),
        session_object_id=client_session,
    )
    affinity = replace(
        affinity,
        client_identity=client_identity,
        client_session_object_id=client_session,
        auth_method="vendor-auth/opaque-v9",
    )
    transport = replace(
        transport,
        transport_id="opaque-transport/" + ("z" * 280),
        source_ip="2001:db8::25",
        source_process=source,
    )

    session = manager.open_session(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=10),
        initiator_budget=1_000,
        responder_budget=2_000,
        operation_budget=2,
    )

    assert manager.session_view(session.channel_id) == session
    packed = ssh_channels._pack_session(session)
    assert packed[0] & ssh_channels._SESSION_WIDE_LENGTHS
    assert len(packed) > 456
    assert ssh_channels._unpack_session(packed) == session


@pytest.mark.parametrize("kind", list(SshOperationKind))
def test_ssh_child_families_have_stable_ids_and_no_completed_history(
    kind: SshOperationKind,
) -> None:
    manager, application = _manager()
    session = _open(manager, list(SshOperationKind).index(kind) + 10)
    lease = _reserve(manager, session, semantic_id=f"{kind.value}-0", kind=kind)

    assert lease.kind is kind
    assert lease.child_channel_id.startswith("ssh-child-channel-")
    assert lease.operation_id.startswith("ssh-operation-")
    assert manager.operation_lease(lease.operation_id) == lease
    assert manager.finalize_operation(lease.operation_id)
    assert not manager.finalize_operation(lease.operation_id)
    assert manager.operation_lease(lease.operation_id) is None
    census = manager.census()
    assert census.active_operations == 0
    assert census.operation_backing_entries == 0
    snapshot = application.get(session.channel_id)
    assert snapshot is not None
    assert snapshot.completed_operations == 1
    assert snapshot.active_operations == 0


def test_ssh_synchronous_first_child_uses_atomic_completed_path() -> None:
    manager, application = _manager()
    affinity, transport, binding = _session_values(18)
    started_at = binding.ready_at + timedelta(seconds=1)
    session, lease = manager.open_session_with_completed_operation(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=30),
        initiator_budget=1_000,
        responder_budget=1_000,
        operation_budget=2,
        kind=SshOperationKind.EXEC,
        semantic_operation_id="exec-18",
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=1),
        initiator_bytes=32,
        responder_bytes=64,
    )

    assert manager.session_view(session.channel_id) == session
    assert manager.operation_lease(lease.operation_id) is None
    assert not manager.finalize_operation(lease.operation_id)
    census = manager.census()
    assert census.active_operations == 0
    assert census.operation_backing_entries == 0
    assert application.census().used_operation_ids == 1
    snapshot = application.get(session.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == snapshot.completed_operations == 1
    assert snapshot.active_operations == 0


def test_ssh_parent_child_containment_and_finalization_order() -> None:
    manager, _application = _manager()
    session = _open(manager, 20)
    shell = _reserve(
        manager,
        session,
        semantic_id="shell",
        kind=SshOperationKind.SHELL,
        duration=timedelta(seconds=10),
    )
    child = _reserve(
        manager,
        session,
        semantic_id="exec-whoami",
        kind=SshOperationKind.EXEC,
        offset=timedelta(seconds=3),
        duration=timedelta(seconds=1),
        parent_operation_id=shell.operation_id,
    )

    with pytest.raises(StateError, match="active child operations"):
        manager.finalize_operation(shell.operation_id)
    assert manager.operation_lease(shell.operation_id) == shell
    assert manager.finalize_operation(child.operation_id)
    assert manager.finalize_operation(shell.operation_id)
    assert manager.census().active_operations == 0


def test_ssh_rejects_identity_process_budget_and_window_conflicts_atomically() -> None:
    manager, application = _manager()
    affinity, transport, binding = _session_values(30)
    contradictory = replace(binding, session_object_id="different-session")
    with pytest.raises(StateError, match="session object"):
        manager.open_session(
            affinity,
            transport=transport,
            binding=contradictory,
            idle_timeout=timedelta(minutes=5),
            initiator_budget=10,
            responder_budget=10,
            operation_budget=1,
        )
    assert manager.census().open_sessions == 0

    session = _open(
        manager,
        30,
        initiator_budget=10,
        responder_budget=10,
        operation_budget=1,
    )
    before = manager.census()
    with pytest.raises(StateError, match="initiator byte budget"):
        _reserve(manager, session, initiator_bytes=11, responder_bytes=0)
    after = manager.census()
    assert after.active_operations == before.active_operations == 0
    assert after.operation_backing_entries == before.operation_backing_entries == 0
    snapshot = application.get(session.channel_id)
    assert snapshot is not None and snapshot.reserved_operations == 0

    outside = session.transport.closes_at + timedelta(microseconds=1)
    with pytest.raises(StateError, match="outside the SSH window|outside its lifecycle"):
        manager.reserve_operation(
            session,
            kind=SshOperationKind.SCP,
            semantic_operation_id="late",
            started_at=outside,
            ended_at=outside,
        )


def test_ssh_process_hold_must_cover_transport_and_child() -> None:
    affinity, transport, binding = _session_values(40)
    with pytest.raises(ValueError, match="ends before TCP close"):
        replace(
            transport,
            receiver_process=replace(
                transport.receiver_process,
                required_until=transport.closes_at - timedelta(microseconds=1),
            ),
        )

    manager, _application = _manager()
    session = manager.open_session(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=30),
        initiator_budget=100,
        responder_budget=100,
        operation_budget=2,
    )
    forged = replace(
        session,
        transport=replace(
            session.transport,
            source_process=replace(
                session.transport.source_process,
                process_object_id="other-source-process",
            ),
        ),
    )
    with pytest.raises(StateError, match="identity or transport binding is stale"):
        _reserve(manager, forged)


def test_ssh_idle_hard_and_watermark_fences_with_bounded_closure_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, application = _manager()
    session = _open(
        manager,
        50,
        duration=timedelta(seconds=30),
        idle_timeout=timedelta(seconds=5),
    )
    lease = _reserve(
        manager,
        session,
        offset=timedelta(seconds=2),
        duration=timedelta(seconds=1),
    )
    assert manager.finalize_operation(lease.operation_id)
    snapshot = application.get(session.channel_id)
    assert snapshot is not None
    assert snapshot.idle_deadline == lease.ended_at + timedelta(seconds=5)

    def reject_snapshot_reconstruction(
        _registry: ApplicationChannelRegistry,
        _channel_id: str,
    ) -> None:
        raise AssertionError("SSH due-close path reconstructed a shared channel snapshot")

    monkeypatch.setattr(ApplicationChannelRegistry, "get", reject_snapshot_reconstruction)

    before = manager.watermark(snapshot.idle_deadline - timedelta(microseconds=1))
    assert before.closures == ()
    result = manager.watermark(snapshot.idle_deadline)
    assert len(result.closures) == 1
    closure = result.closures[0]
    assert closure.channel_id == session.channel_id
    assert closure.session_object_id == session.binding.session_object_id
    assert closure.source_process == session.transport.source_process
    assert closure.receiver_process == session.transport.receiver_process
    assert manager.session_view(session.channel_id) is None
    shared = application.census()
    assert shared.retained_closed_channels == 1
    assert shared.watermark == _START

    with pytest.raises(StateError, match="before the current watermark"):
        _open(manager, 51, opened_at=_START + timedelta(seconds=1))


def test_ssh_watermark_pages_close_outside_locks_before_shared_watermark() -> None:
    manager, application = _manager()
    sessions = [
        _open(
            manager,
            60 + index,
            opened_at=_START + timedelta(seconds=1),
            duration=timedelta(seconds=10),
            idle_timeout=timedelta(seconds=2),
        )
        for index in range(5)
    ]
    cutoff = _START + timedelta(seconds=4)
    first = manager.watermark(cutoff, limit=2)
    assert len(first.closures) == 2
    assert first.has_more
    second = manager.watermark(cutoff, limit=2)
    assert len(second.closures) == 2
    assert second.has_more
    third = manager.watermark(cutoff, limit=2)
    assert len(third.closures) == 1
    assert not third.has_more
    assert {item.channel_id for item in (*first.closures, *second.closures, *third.closures)} == {
        item.channel_id for item in sessions
    }
    assert application.census().retained_closed_channels == 5
    application.watermark(cutoff)
    assert application.census().retained_channels == 5
    application.watermark(cutoff + timedelta(seconds=31))
    assert application.census().retained_channels == 0


def test_ssh_watermark_rejects_active_child_without_losing_state() -> None:
    manager, _application = _manager()
    session = _open(
        manager,
        70,
        opened_at=_START + timedelta(seconds=1),
        duration=timedelta(seconds=10),
        idle_timeout=timedelta(seconds=3),
    )
    lease = _reserve(manager, session, duration=timedelta(seconds=1))
    before = manager.census()
    with pytest.raises(StateError, match="active child operations"):
        manager.watermark(session.transport.closes_at)
    after = manager.census()
    assert after.open_sessions == before.open_sessions == 1
    assert after.active_operations == before.active_operations == 1
    assert manager.operation_lease(lease.operation_id) == lease
    assert manager.finalize_operation(lease.operation_id)


def _deterministic_digest(workers: int, count: int = 96) -> str:
    manager, application = _manager()

    def publish(index: int) -> tuple[str, str, str]:
        session = _open(manager, 1_000 + index)
        lease = _reserve(
            manager,
            session,
            semantic_id=f"exec-{index}",
            kind=SshOperationKind.EXEC,
        )
        assert manager.finalize_operation(lease.operation_id)
        return session.channel_id, lease.child_channel_id, lease.operation_id

    if workers == 1:
        rows = [publish(index) for index in range(count)]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(publish, range(count)))
    census = manager.census()
    material = {
        "rows": sorted(rows),
        "sessions": census.open_sessions,
        "operations": census.active_operations,
        "used": application.census().used_operation_ids,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def test_ssh_one_four_eight_worker_identity_is_deterministic() -> None:
    assert _deterministic_digest(1) == _deterministic_digest(4) == _deterministic_digest(8)


def test_ssh_disjoint_owner_mutations_make_overlapping_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _application = _manager()
    first = 2_000
    first_affinity, _transport, _binding = _session_values(first)
    first_partition = manager.owner_partition_id(first_affinity)
    second = next(
        index
        for index in range(first + 1, first + 1_000)
        if manager.owner_partition_id(_session_values(index)[0]) != first_partition
    )
    rendezvous = Barrier(2)
    original_insert = ssh_channels._PackedSshSessionStore.insert

    def overlapping_insert(
        store: ssh_channels._PackedSshSessionStore,
        view: SshSessionView,
        **kwargs: object,
    ) -> int:
        rendezvous.wait(timeout=3)
        return original_insert(store, view, **kwargs)

    monkeypatch.setattr(ssh_channels._PackedSshSessionStore, "insert", overlapping_insert)
    with ThreadPoolExecutor(max_workers=2) as pool:
        sessions = tuple(pool.map(lambda index: _open(manager, index), (first, second)))

    assert len({session.channel_id for session in sessions}) == 2
    assert manager.census().open_sessions == 2


@pytest.mark.slow
def test_ssh_hash_seed_determinism_in_fresh_processes() -> None:
    root = Path(__file__).resolve().parents[2]
    code = """
import hashlib
import json
from datetime import UTC, datetime, timedelta
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.ssh_channels import *
start = datetime(2026, 8, 1, tzinfo=UTC)
end = start + timedelta(days=1)
app = ApplicationChannelRegistry(window_start=start, window_end=end)
manager = SshApplicationChannelManager(application_registry=app, window_start=start, window_end=end)
rows = []
for index in range(12):
    opened = start + timedelta(seconds=index + 1)
    closed = opened + timedelta(minutes=5)
    affinity = SshChannelAffinity(f'client-{index}', f'client-session-{index}', f'server-{index}', f'server-session-{index}', f'user-{index}', 'publickey')
    source = SshProcessHold(f'client-{index}', 1000 + index, f'source-{index}', f'client-session-{index}', f'local-{index}', opened - timedelta(seconds=1), closed)
    receiver = SshProcessHold(f'server-{index}', 2000 + index, f'receiver-{index}', f'server-session-{index}', f'user-{index}', opened - timedelta(seconds=1), closed)
    transport = SshTransportPlan(f'transport-{index}', f'C{index}', f'conn-{index}', f'10.0.0.{index + 1}', f'10.1.0.{index + 1}', 40000 + index, 22, opened, closed, receiver, source)
    binding = SshSessionBinding(f'server-{index}', f'0x{index:x}', f'server-session-{index}', f'group-{index}', f'user-{index}', opened + timedelta(seconds=1))
    session = manager.open_session(affinity, transport=transport, binding=binding, idle_timeout=timedelta(minutes=5), initiator_budget=1000, responder_budget=1000, operation_budget=2)
    lease = manager.reserve_operation(session, kind=SshOperationKind.EXEC, semantic_operation_id=f'op-{index}', started_at=binding.ready_at + timedelta(seconds=1), ended_at=binding.ready_at + timedelta(seconds=2), initiator_bytes=10, responder_bytes=20)
    manager.finalize_operation(lease.operation_id)
    rows.append((session.channel_id, lease.child_channel_id, lease.operation_id))
print(hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest())
"""
    digests: list[str] = []
    for seed in ("1", "8675309"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        digests.append(completed.stdout.strip())
    assert len(set(digests)) == 1


@pytest.mark.parametrize(
    "hours",
    [
        24,
        pytest.param(24 * 7, marks=pytest.mark.slow),
        pytest.param(24 * 30, marks=pytest.mark.soak),
    ],
)
def test_ssh_retention_plateaus_across_24h_7d_30d(hours: int) -> None:
    start = _START
    end = start + timedelta(hours=hours + 2)
    manager, application = _manager(start=start, end=end)
    maximum_live = 0
    for hour in range(hours):
        opened = start + timedelta(hours=hour, seconds=1)
        for ordinal in range(2):
            session = _open(
                manager,
                hour * 2 + ordinal,
                opened_at=opened + timedelta(seconds=ordinal),
                duration=timedelta(minutes=5),
                idle_timeout=timedelta(minutes=5),
            )
            lease = _reserve(manager, session, semantic_id=f"hour-{hour}-{ordinal}")
            manager.finalize_operation(lease.operation_id)
        cutoff = start + timedelta(hours=hour + 1)
        while True:
            result = manager.watermark(cutoff, limit=8)
            if not result.has_more:
                break
        application.watermark(cutoff)
        maximum_live = max(maximum_live, manager.census().high_water_mark)
    census = manager.census()
    assert census.open_sessions == 0
    assert census.active_operations == 0
    assert census.session_backing_entries == 0
    assert census.operation_backing_entries == 0
    assert census.expiry_entries == 0
    assert maximum_live <= 4
