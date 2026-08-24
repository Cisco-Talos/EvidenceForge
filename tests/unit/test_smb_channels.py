# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for bounded reusable SMB application channels."""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

import evidenceforge.generation.smb_channels as smb_channels_module
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionToken,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAffinity,
    SmbCompletedHandlePlan,
    SmbCompletedOperationPlan,
    SmbOperationLease,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 16, 12, tzinfo=UTC)
_END = _START + timedelta(days=40)


def _manager() -> SmbApplicationChannelManager:
    application_registry = ApplicationChannelRegistry(window_start=_START, window_end=_END)
    return SmbApplicationChannelManager(
        application_registry=application_registry,
        window_start=_START,
        window_end=_END,
    )


def _affinity(
    *,
    client_identity: str = "CLIENT01",
    client_ip: str = "10.0.0.10",
    client_session: str = "0x1001",
    server_identity: str = "FILE01",
    server_ip: str = "10.0.0.20",
    principal: str = "EXAMPLE\\analyst",
    auth_protocol: str = "Kerberos",
    account_scope: str = "EXAMPLE",
    dialect: str = "3.1.1",
    signing_policy: str = "required",
    encryption_policy: str = "off",
    server_policy: str = "windows:file-server",
    share_policy: str = "disk:standard",
    client_access: str = "windows_native",
) -> SmbChannelAffinity:
    return SmbChannelAffinity(
        client_identity=client_identity,
        client_ip=client_ip,
        client_session=client_session,
        server_identity=server_identity,
        server_ip=server_ip,
        principal=principal,
        auth_protocol=auth_protocol,
        account_scope=account_scope,
        dialect=dialect,
        signing_policy=signing_policy,
        encryption_policy=encryption_policy,
        server_policy=server_policy,
        share_policy=share_policy,
        client_access=client_access,
    )


def _plan(
    suffix: str = "1",
    *,
    opened_at: datetime = _START,
    duration: timedelta = timedelta(hours=1),
) -> NetworkTransactionPlan:
    closes_at = opened_at + duration
    return NetworkTransactionPlan(
        stable_id=f"smb-transport-{suffix}",
        hostname="file01.example.test",
        outcome="success",
        phase_times=(("attempt", opened_at), ("close", closes_at)),
        started_at=opened_at,
        closed_at=closes_at,
        src_ip="10.0.0.10",
        src_port=50_000 + int(suffix),
        dst_ip="10.0.0.20",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"CUID{suffix}",
        conn_id=f"conn-{suffix}",
        duration=duration.total_seconds(),
        conn_state="SF",
        history="ShADadfF",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=100, packets=1, ip_bytes=140),
            resp=DirectionalTrafficLedger(payload_bytes=200, packets=1, ip_bytes=240),
        ),
    )


def _open(
    manager: SmbApplicationChannelManager,
    affinity: SmbChannelAffinity | None = None,
    *,
    suffix: str = "1",
    share_ref: str = "FILE01.Documents",
    opened_at: datetime = _START,
    duration: timedelta = timedelta(hours=1),
    operation_offset: timedelta = timedelta(milliseconds=100),
    operation_duration: timedelta = timedelta(seconds=1),
    idle_timeout: timedelta = timedelta(minutes=15),
    initiator_budget: int = 10_000,
    responder_budget: int = 100_000,
    operation_budget: int = 100,
    operation_completes_immediately: bool = False,
) -> SmbOperationLease:
    operation_start = opened_at + operation_offset
    return manager.open_session(
        affinity or _affinity(),
        transport_plan=_plan(suffix, opened_at=opened_at, duration=duration),
        sensor_observations=(),
        ground_truth_transport_uid=f"OBSERVED{suffix}",
        logon_id=f"0xA{suffix}",
        auth_session_ref=f"auth-{suffix}",
        principal="EXAMPLE\\analyst",
        auth_protocol="kerberos",
        account_scope="EXAMPLE",
        effective_uid=None,
        effective_gid=None,
        client_access="windows_native",
        server_hostname="FILE01",
        client_ip="10.0.0.10",
        lifecycle_group_id=f"smb-transport-{suffix}",
        share_ref=share_ref,
        semantic_operation_id=f"operation-{suffix}",
        operation_started_at=operation_start,
        operation_ended_at=operation_start + operation_duration,
        operation_initiator_bytes=100,
        operation_responder_bytes=200,
        idle_timeout=idle_timeout,
        initiator_budget=initiator_budget,
        responder_budget=responder_budget,
        operation_budget=operation_budget,
        operation_completes_immediately=operation_completes_immediately,
    )


def test_affinity_normalizes_case_but_keeps_every_semantic_dimension_exact() -> None:
    first = _affinity()
    equivalent = _affinity(
        client_identity="client01",
        server_identity="file01",
        principal="example\\ANALYST",
        auth_protocol="kerberos",
    )

    assert first == equivalent
    assert first.digest == equivalent.digest
    assert first.owner_id == "smb-client:client01:0x1001"
    assert first.digest != _affinity(client_session="0x1002").digest
    assert first.digest != _affinity(principal="EXAMPLE\\other").digest
    assert first.digest != _affinity(dialect="3.0.2").digest
    assert first.digest != _affinity(signing_policy="enabled").digest
    assert first.digest != _affinity(encryption_policy="required").digest
    assert first.digest != _affinity(server_policy="samba:file-server").digest
    assert first.digest != _affinity(share_policy="disk:encrypted").digest
    assert first.digest != _affinity(client_access="cifs_mount").digest


def test_internal_canonical_affinity_ingress_is_byte_identical() -> None:
    strict = _affinity(
        client_identity="client01",
        server_identity="file01",
        principal="example\\analyst",
        auth_protocol="kerberos",
        account_scope="example",
    )
    canonical = SmbChannelAffinity._from_canonical(
        client_identity="client01",
        client_ip="10.0.0.10",
        client_session="0x1001",
        server_identity="file01",
        server_ip="10.0.0.20",
        principal="example\\analyst",
        auth_protocol="kerberos",
        account_scope="example",
        dialect="3.1.1",
        signing_policy="required",
        encryption_policy="off",
        server_policy="windows:file-server",
        share_policy="disk:standard",
        client_access="windows_native",
    )

    assert canonical == strict
    assert canonical.owner_id == strict.owner_id
    assert canonical.digest == strict.digest
    assert canonical._digest_bytes == strict._digest_bytes


def test_same_share_reuses_transport_session_tree_and_frozen_identity() -> None:
    manager = _manager()
    first = _open(manager)
    assert manager.finalize_operation(first)

    second = manager.reserve_reuse(
        _affinity(),
        share_ref="file01.documents",
        semantic_operation_id="operation-2",
        requested_at=_START + timedelta(seconds=2),
        required_until=_START + timedelta(seconds=3),
        initiator_bytes=110,
        responder_bytes=220,
    ).lease

    assert second is not None
    assert second.reused_session
    assert not second.created_tree
    assert second.channel_id == first.channel_id
    assert second.session_id == first.session_id
    assert second.tree_id == first.tree_id
    assert second.transport_plan == first.transport_plan
    assert second.ground_truth_transport_uid == "OBSERVED1"
    assert second.ordinal == 1


def test_exact_channel_reuse_never_crosses_an_overlapping_same_affinity_session() -> None:
    """An authenticated anchor cannot attach its next file to a sibling channel."""

    manager = _manager()
    affinity = _affinity()
    first = _open(manager, affinity, suffix="1")
    sibling = _open(manager, affinity, suffix="2")
    assert manager.finalize_operation(first)
    assert manager.finalize_operation(sibling)

    result = manager.reserve_channel_reuse(
        first,
        affinity,
        share_ref="file01.documents",
        semantic_operation_id="first-channel-second-file",
        requested_at=_START + timedelta(seconds=2),
        required_until=_START + timedelta(seconds=3),
        initiator_bytes=110,
        responder_bytes=220,
    )

    lease = result.lease
    assert lease is not None
    assert not result.closures
    assert lease.channel_id == first.channel_id
    assert lease.channel_id != sibling.channel_id
    assert lease.transport_plan == first.transport_plan
    assert lease.transport_plan.stable_id == first.transport_plan.stable_id
    assert manager.finalize_operation(lease)
    first_snapshot = manager.application_registry.get(first.channel_id)
    sibling_snapshot = manager.application_registry.get(sibling.channel_id)
    assert first_snapshot is not None and first_snapshot.completed_operations == 2
    assert sibling_snapshot is not None and sibling_snapshot.completed_operations == 1

    assert manager.close_session(
        first.channel_id,
        closed_at=_START + timedelta(seconds=4),
        reason="test complete",
    )
    assert manager.close_session(
        sibling.channel_id,
        closed_at=_START + timedelta(seconds=4),
        reason="test complete",
    )
    assert manager.census().open_sessions == 0


def test_terminal_two_operation_batch_is_atomic_exact_and_sidecar_neutral() -> None:
    """One root commits all ordered members closed with exact bytes and no live SMB state."""

    manager = _manager()
    plan = _plan()
    first_start = _START + timedelta(milliseconds=100)
    first_end = first_start + timedelta(milliseconds=400)
    second_start = first_end + timedelta(microseconds=1)
    second_end = second_start + timedelta(milliseconds=500)
    operations = (
        SmbCompletedOperationPlan(
            semantic_operation_id="first",
            started_at=first_start,
            ended_at=first_end,
            initiator_bytes=40,
            responder_bytes=80,
            handles=(
                SmbCompletedHandlePlan(
                    file_id="content-1",
                    content_version=1,
                    access="read",
                    opened_at=first_start,
                    closed_at=first_end,
                ),
            ),
        ),
        SmbCompletedOperationPlan(
            semantic_operation_id="second",
            started_at=second_start,
            ended_at=second_end,
            initiator_bytes=60,
            responder_bytes=120,
            handles=(
                SmbCompletedHandlePlan(
                    file_id="content-2",
                    content_version=1,
                    access="read",
                    opened_at=second_start,
                    closed_at=second_end,
                ),
            ),
        ),
    )
    token = manager.prepare_fresh_session_with_completed_operations_and_close(
        _affinity(),
        transport_plan=plan,
        sensor_observations=(),
        ground_truth_transport_uid="OBSERVED1",
        logon_id="0xA1",
        auth_session_ref="auth-1",
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
        tree_connected_at=_START + timedelta(milliseconds=50),
        operations=operations,
        idle_timeout=timedelta(minutes=15),
        closed_at=second_end + timedelta(milliseconds=10),
    )

    with manager.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    assert manager.authenticates_admission_receipt(result.receipt)
    assert result.receipt.operation_ids == tuple(
        operation.operation_id for operation in result.result.operations
    )
    assert (
        manager.application_registry.recover_committed_admission(token.application_token)
        is result.application
    )
    assert manager.application_registry.acknowledge_committed_admission(
        token.application_token,
        result.application,
    )
    assert result.result.operations[1].started_at > result.result.operations[0].ended_at
    snapshot = result.application.snapshot
    assert snapshot.reserved_operations == snapshot.completed_operations == 2
    assert snapshot.reserved_initiator_bytes == 100
    assert snapshot.reserved_responder_bytes == 200
    assert snapshot.active_operations == 0
    assert snapshot.closed_at == result.result.closure.closed_at
    census = manager.census()
    assert census.open_sessions == census.open_trees == census.open_handles == 0
    assert census.prepared_admissions == census.claimed_admissions == 0
    assert census.application.open_channels == 0
    assert census.application.used_operation_ids == 2


def test_terminal_batch_accepts_64_and_rejects_65_without_residue() -> None:
    """The exact runtime cardinality boundary accepts 64 and neutrally rejects 65."""

    manager = _manager()
    plan = _plan()
    operations = tuple(
        SmbCompletedOperationPlan(
            semantic_operation_id=f"member-{index}",
            started_at=_START + timedelta(milliseconds=100 + index * 2),
            ended_at=_START + timedelta(milliseconds=101 + index * 2),
            initiator_bytes=1 if index < 63 else 37,
            responder_bytes=2 if index < 63 else 74,
        )
        for index in range(64)
    )
    token = manager.prepare_fresh_session_with_completed_operations_and_close(
        _affinity(),
        transport_plan=plan,
        sensor_observations=(),
        ground_truth_transport_uid="OBSERVED1",
        logon_id="0xA1",
        auth_session_ref="auth-1",
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
        tree_connected_at=_START + timedelta(milliseconds=50),
        operations=operations,
        idle_timeout=timedelta(minutes=15),
        closed_at=_START + timedelta(milliseconds=250),
    )
    with manager.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()
    assert len(result.result.operations) == 64
    assert result.application.snapshot.reserved_operations == 64
    assert result.application.snapshot.completed_operations == 64
    assert result.application.snapshot.reserved_initiator_bytes == 100
    assert result.application.snapshot.reserved_responder_bytes == 200
    assert (
        manager.application_registry.recover_committed_admission(token.application_token)
        is result.application
    )
    assert manager.application_registry.acknowledge_committed_admission(
        token.application_token,
        result.application,
    )

    rejecting_manager = _manager()
    before = rejecting_manager.census()
    member = SmbCompletedOperationPlan(
        semantic_operation_id="member",
        started_at=_START + timedelta(seconds=1),
        ended_at=_START + timedelta(seconds=2),
        initiator_bytes=0,
        responder_bytes=0,
    )
    with pytest.raises(ValueError, match="1..64"):
        rejecting_manager.prepare_fresh_session_with_completed_operations_and_close(
            _affinity(),
            transport_plan=_plan(),
            sensor_observations=(),
            ground_truth_transport_uid="OBSERVED1",
            logon_id="0xA1",
            auth_session_ref="auth-1",
            principal="EXAMPLE\\analyst",
            auth_protocol="kerberos",
            account_scope="EXAMPLE",
            effective_uid=None,
            effective_gid=None,
            client_access="windows_native",
            server_hostname="FILE01",
            client_ip="10.0.0.10",
            lifecycle_group_id="smb-transport-1",
            share_ref="FILE01.Documents",
            tree_connected_at=_START + timedelta(milliseconds=50),
            operations=(member,) * 65,
            idle_timeout=timedelta(minutes=15),
            closed_at=_START + timedelta(seconds=3),
        )
    assert rejecting_manager.census() == before
    accepted = manager.census()
    assert accepted.open_sessions == accepted.open_trees == accepted.open_handles == 0
    assert accepted.prepared_admissions == accepted.claimed_admissions == 0
    assert accepted.application.open_channels == 0
    assert accepted.application.recoverable_admission_receipts == 0


def test_terminal_batch_cancel_releases_manager_and_common_reservations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost common release return is retryable through the retained SMB owner."""

    manager = _manager()
    plan = _plan()
    started_at = _START + timedelta(milliseconds=100)
    ended_at = started_at + timedelta(milliseconds=500)
    token = manager.prepare_fresh_session_with_completed_operations_and_close(
        _affinity(),
        transport_plan=plan,
        sensor_observations=(),
        ground_truth_transport_uid="OBSERVED1",
        logon_id="0xA1",
        auth_session_ref="auth-1",
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
        tree_connected_at=_START + timedelta(milliseconds=50),
        operations=(
            SmbCompletedOperationPlan(
                semantic_operation_id="cancelled",
                started_at=started_at,
                ended_at=ended_at,
                initiator_bytes=100,
                responder_bytes=200,
            ),
        ),
        idle_timeout=timedelta(minutes=15),
        closed_at=ended_at + timedelta(milliseconds=10),
    )

    faulted = False

    common_cancel = manager.application_registry.cancel_prepared_admission

    def lose_common_release_return(application_token: ApplicationChannelAdmissionToken) -> bool:
        nonlocal faulted
        released = common_cancel(application_token)
        if not faulted:
            faulted = True
            raise RuntimeError("injected common release tail")
        return released

    monkeypatch.setattr(
        manager.application_registry,
        "cancel_prepared_admission",
        lose_common_release_return,
    )
    with pytest.raises(RuntimeError, match="injected common release tail"):
        manager.cancel_prepared_admission(token)
    held = manager.census()
    assert faulted
    assert held.prepared_admissions == 1
    assert held.application.prepared_admissions == 0
    assert held.application.releasing_admissions == 0

    monkeypatch.setattr(
        manager.application_registry,
        "cancel_prepared_admission",
        common_cancel,
    )
    assert manager.cancel_prepared_admission(token)
    census = manager.census()
    assert census.prepared_admissions == census.claimed_admissions == 0
    assert census.open_sessions == census.open_trees == census.open_handles == 0
    assert census.application.open_channels == 0
    assert census.application.prepared_admissions == 0
    assert census.application.claimed_admissions == 0
    assert census.application.reserved_channel_ids == 0
    assert census.application.reserved_transport_ids == 0
    assert census.application.reserved_operation_ids == 0


def test_terminal_batch_commit_adopts_one_common_lost_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A primitive common commit lost return converges to one terminal SMB result."""

    manager = _manager()
    plan = _plan()
    started_at = _START + timedelta(milliseconds=100)
    ended_at = started_at + timedelta(milliseconds=500)
    token = manager.prepare_fresh_session_with_completed_operations_and_close(
        _affinity(),
        transport_plan=plan,
        sensor_observations=(),
        ground_truth_transport_uid="OBSERVED1",
        logon_id="0xA1",
        auth_session_ref="auth-1",
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
        tree_connected_at=_START + timedelta(milliseconds=50),
        operations=(
            SmbCompletedOperationPlan(
                semantic_operation_id="lost-return",
                started_at=started_at,
                ended_at=ended_at,
                initiator_bytes=100,
                responder_bytes=200,
            ),
        ),
        idle_timeout=timedelta(minutes=15),
        closed_at=ended_at + timedelta(milliseconds=10),
    )
    faulted = False

    def lose_first_open_row_return(stage: str) -> None:
        nonlocal faulted
        if stage == "open-row" and not faulted:
            faulted = True
            raise OSError("injected terminal batch lost return")

    monkeypatch.setattr(manager._registry, "_prepared_commit_fault", lose_first_open_row_return)
    with manager.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert manager.authenticates_admission_receipt(result.receipt)
    assert result.result.operations[0].operation_id == result.receipt.operation_ids[0]
    assert (
        manager.application_registry.recover_committed_admission(token.application_token)
        is result.application
    )
    assert manager.application_registry.acknowledge_committed_admission(
        token.application_token,
        result.application,
    )
    census = manager.census()
    assert census.prepared_admissions == census.claimed_admissions == 0
    assert census.open_sessions == census.open_trees == census.open_handles == 0
    assert census.application.open_channels == 0
    assert census.application.used_operation_ids == 1


def test_immediate_first_operation_matches_active_then_finalize_and_close() -> None:
    """Known completion skips active state but preserves exact retained identity and closure."""

    active_manager = _manager()
    immediate_manager = _manager()
    active = _open(active_manager)
    immediate = _open(immediate_manager, operation_completes_immediately=True)

    assert not active.operation_completed
    assert immediate.operation_completed
    assert replace(immediate, operation_completed=False) == active
    active_before = active_manager.application_registry.census()
    immediate_before = immediate_manager.application_registry.census()
    assert active_before.active_operations == 1
    assert immediate_before.active_operations == 0
    assert active_before.used_operation_ids == immediate_before.used_operation_ids == 1

    assert active_manager.finalize_operation(active)
    assert not immediate_manager.finalize_operation(immediate)
    assert active_manager.application_registry.get(active.channel_id) == (
        immediate_manager.application_registry.get(immediate.channel_id)
    )
    active_after = active_manager.census()
    immediate_after = immediate_manager.census()
    assert active_after.open_sessions == immediate_after.open_sessions == 1
    assert active_after.open_trees == immediate_after.open_trees == 1
    assert active_after.open_handles == immediate_after.open_handles == 0
    assert active_after.application.active_operations == 0
    assert immediate_after.application.active_operations == 0
    assert active_after.application.used_operation_ids == 1
    assert immediate_after.application.used_operation_ids == 1

    with pytest.raises(StateError, match="completed during admission"):
        immediate_manager.open_handle(
            immediate,
            file_id="content-immediate",
            content_version=1,
            access="read",
            opened_at=immediate.started_at,
        )

    cutoff = _START + timedelta(minutes=16)
    active_close = active_manager.watermark(cutoff)
    immediate_close = immediate_manager.watermark(cutoff)
    assert tuple(active_close.closures) == tuple(immediate_close.closures)
    assert active_close.census.open_sessions == immediate_close.census.open_sessions == 0
    assert active_close.census.application.open_channels == 0
    assert immediate_close.census.application.open_channels == 0


def test_cross_share_reuses_session_but_opens_one_new_tree() -> None:
    manager = _manager()
    first = _open(manager)
    assert manager.finalize_operation(first)

    second = manager.reserve_reuse(
        _affinity(),
        share_ref="FILE01.Engineering",
        semantic_operation_id="operation-2",
        requested_at=_START + timedelta(seconds=2),
        required_until=_START + timedelta(seconds=3),
        initiator_bytes=100,
        responder_bytes=200,
    ).lease

    assert second is not None
    assert second.channel_id == first.channel_id
    assert second.session_id == first.session_id
    assert second.tree_id != first.tree_id
    assert second.created_tree
    assert manager.census().open_trees == 2


@pytest.mark.parametrize(
    "different",
    [
        _affinity(client_ip="10.0.0.11"),
        _affinity(client_session="0x1002"),
        _affinity(server_ip="10.0.0.21"),
        _affinity(principal="EXAMPLE\\other"),
        _affinity(dialect="3.0.2"),
        _affinity(signing_policy="enabled"),
        _affinity(encryption_policy="required"),
        _affinity(server_policy="samba:file-server"),
        _affinity(share_policy="disk:encrypted"),
    ],
)
def test_incompatible_affinity_never_reuses(different: SmbChannelAffinity) -> None:
    manager = _manager()
    first = _open(manager)
    assert manager.finalize_operation(first)

    result = manager.reserve_reuse(
        different,
        share_ref="FILE01.Documents",
        semantic_operation_id="operation-2",
        requested_at=_START + timedelta(seconds=2),
        required_until=_START + timedelta(seconds=3),
        initiator_bytes=100,
        responder_bytes=200,
    )

    assert result.lease is None
    assert not result.closures
    assert manager.census().open_sessions == 1


def test_handle_versions_produce_source_native_fuid_and_close_idempotently() -> None:
    manager = _manager()
    lease = _open(manager)
    first = manager.open_handle(
        lease,
        file_id="canonical-content-1",
        content_version=1,
        access="read",
        opened_at=lease.started_at,
        role="primary",
    )
    second = manager.open_handle(
        lease,
        file_id="canonical-content-1",
        content_version=2,
        access="read",
        opened_at=lease.started_at,
        role="next-version",
    )

    assert first.handle_id != second.handle_id
    assert manager.file_transfer_fuid(first, "read") != manager.file_transfer_fuid(second, "read")
    with pytest.raises(StateError, match="active handles"):
        manager.finalize_operation(lease)
    assert manager.close_handle(first, lease, closed_at=lease.ended_at)
    assert not manager.close_handle(first, lease, closed_at=lease.ended_at)
    assert manager.close_handle(second, lease, closed_at=lease.ended_at)
    assert manager.finalize_operation(lease)
    assert not manager.finalize_operation(lease)


def test_deny_write_handle_fences_only_the_exact_channel_file_bucket() -> None:
    manager = _manager()
    lease = _open(manager)
    conflict = manager.open_handle(
        lease,
        file_id="file-1",
        content_version=1,
        access="read",
        opened_at=lease.started_at,
        deny_write=True,
        role="conflict",
    )

    assert manager.has_write_conflict(lease, "file-1")
    assert not manager.has_write_conflict(lease, "file-2")
    with pytest.raises(StateError, match="denies write"):
        manager.open_handle(
            lease,
            file_id="file-1",
            content_version=1,
            access="write",
            opened_at=lease.started_at,
        )
    assert manager.close_handle(conflict, lease, closed_at=lease.ended_at)


def test_exact_end_boundary_is_allowed_and_one_microsecond_overflow_is_atomic() -> None:
    manager = _manager()
    first = _open(manager, idle_timeout=timedelta(hours=2))
    assert manager.finalize_operation(first)
    closes_at = first.transport_plan.closed_at
    assert closes_at is not None

    boundary = manager.reserve_reuse(
        _affinity(),
        share_ref="FILE01.Documents",
        semantic_operation_id="boundary",
        requested_at=closes_at - timedelta(seconds=1),
        required_until=closes_at,
        initiator_bytes=100,
        responder_bytes=200,
    ).lease
    assert boundary is not None
    assert manager.finalize_operation(boundary)
    before = manager.channel_snapshot(first.channel_id)

    overflow = manager.reserve_reuse(
        _affinity(),
        share_ref="FILE01.Documents",
        semantic_operation_id="overflow",
        requested_at=closes_at - timedelta(seconds=1),
        required_until=closes_at + timedelta(microseconds=1),
        initiator_bytes=100,
        responder_bytes=200,
    )

    assert overflow.lease is None
    assert len(overflow.closures) == 1
    after = manager.channel_snapshot(first.channel_id)
    assert before is not None and after is not None
    assert after.reserved_operations == before.reserved_operations
    assert after.reserved_initiator_bytes == before.reserved_initiator_bytes
    assert after.reserved_responder_bytes == before.reserved_responder_bytes


def test_capacity_overflow_retires_exact_channel_without_consuming_budget() -> None:
    manager = _manager()
    first = _open(
        manager,
        initiator_budget=199,
        responder_budget=399,
        operation_budget=2,
    )
    assert manager.finalize_operation(first)
    before = manager.channel_snapshot(first.channel_id)

    result = manager.reserve_reuse(
        _affinity(),
        share_ref="FILE01.Documents",
        semantic_operation_id="too-large",
        requested_at=_START + timedelta(seconds=2),
        required_until=_START + timedelta(seconds=3),
        initiator_bytes=100,
        responder_bytes=200,
    )

    assert result.lease is None
    assert result.closures[0].reason == "capacity"
    after = manager.channel_snapshot(first.channel_id)
    assert before is not None and after is not None
    assert not after.is_open
    assert after.reserved_operations == before.reserved_operations
    assert after.reserved_initiator_bytes == before.reserved_initiator_bytes
    assert after.reserved_responder_bytes == before.reserved_responder_bytes


def test_one_of_one_thousand_affinity_lookup_inspects_only_exact_candidates() -> None:
    manager = _manager()
    target: SmbOperationLease | None = None
    for index in range(1_000):
        affinity = _affinity(
            client_identity=f"client-{index}",
            client_session=f"session-{index}",
        )
        lease = _open(
            manager,
            affinity,
            suffix=str(index + 1),
            opened_at=_START + timedelta(microseconds=index),
        )
        assert manager.finalize_operation(lease)
        if index == 777:
            target = lease
    assert target is not None
    before = manager.census().lookup_candidates_inspected

    reused = manager.reserve_reuse(
        _affinity(client_identity="client-777", client_session="session-777"),
        share_ref="FILE01.Documents",
        semantic_operation_id="target-reuse",
        requested_at=_START + timedelta(seconds=10),
        required_until=_START + timedelta(seconds=11),
        initiator_bytes=1,
        responder_bytes=1,
    ).lease

    assert reused is not None
    assert reused.channel_id == target.channel_id
    # The aggregate includes one SMB affinity/session candidate at each
    # sidecar layer and one exact common-channel candidate.
    assert manager.census().lookup_candidates_inspected - before == 3


def test_warmed_exact_lookup_does_not_revisit_large_primary_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    lease = _open(manager)
    expected = manager.session_view(lease.channel_id)
    assert expected is not None

    def fail_large_primary_lookup(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("warmed exact lookup revisited the packed primary store")

    monkeypatch.setattr(
        smb_channels_module.CompactIndexedStore,
        "get",
        fail_large_primary_lookup,
    )

    assert manager.session_view(lease.channel_id) is expected


def test_sidecar_exact_candidate_counter_counts_cache_and_store_hits_not_misses() -> None:
    manager = _manager()
    lease = _open(manager)
    channel_key = manager._channel_key(lease.channel_id)
    assert channel_key is not None
    assert manager.session_view(lease.channel_id) is not None
    shard = manager._cached_exact_shard(channel_key)
    assert shard is not None

    before_cache = manager.census().sidecar_lookup_candidates_inspected
    assert manager.session_view(lease.channel_id) is not None
    after_cache = manager.census().sidecar_lookup_candidates_inspected
    assert after_cache - before_cache == 1

    with shard.lock:
        shard.snapshot_cache.clear()
    before_store = manager.census().sidecar_lookup_candidates_inspected
    assert manager.session_view(lease.channel_id) is not None
    after_store = manager.census().sidecar_lookup_candidates_inspected
    assert after_store - before_store == 1

    assert manager.session_view("smb-channel-00000000000000000000000000000000") is None
    assert manager.census().sidecar_lookup_candidates_inspected == after_store


def test_thirty_day_watermarks_plateau_open_sidecars_and_reclaim_expired_state() -> None:
    manager = _manager()
    peak_open = 0
    for day in range(30):
        opened_at = _START + timedelta(days=day)
        for index in range(4):
            suffix = str(day * 4 + index + 1)
            affinity = _affinity(
                client_identity=f"client-{index}",
                client_session=f"session-{day}-{index}",
            )
            lease = _open(
                manager,
                affinity,
                suffix=suffix,
                opened_at=opened_at + timedelta(seconds=index),
                duration=timedelta(minutes=20),
            )
            assert manager.finalize_operation(lease)
        result = manager.watermark(opened_at + timedelta(hours=1))
        manager.application_registry.watermark(opened_at + timedelta(hours=1))
        peak_open = max(peak_open, result.census.open_sessions)

    final_cutoff = _START + timedelta(days=31)
    final = manager.watermark(final_cutoff)
    manager.application_registry.watermark(final_cutoff)
    final = manager.watermark(final_cutoff)
    assert peak_open == 0
    assert final.census.open_sessions == 0
    assert final.census.open_trees == 0
    assert final.census.open_handles == 0
    assert final.census.application.retained_channels == 0
    assert final.census.session_backing_entries == 0


def test_transport_hard_deadline_expires_before_longer_idle_deadline() -> None:
    manager = _manager()
    lease = _open(
        manager,
        duration=timedelta(minutes=1),
        idle_timeout=timedelta(minutes=15),
    )
    assert manager.finalize_operation(lease)

    result = manager.watermark(_START + timedelta(minutes=2))

    assert len(result.closures) == 1
    assert result.closures[0].channel_id == lease.channel_id
    assert result.closures[0].closed_at == lease.transport_plan.closed_at
    assert result.census.open_sessions == 0


def test_watermark_decodes_compact_closures_only_when_consumed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    lease = _open(manager, duration=timedelta(minutes=1))
    assert manager.finalize_operation(lease)
    calls = 0
    original = smb_channels_module._unpack_closure_metadata_payloads

    def counted_unpack(*args: bytes) -> tuple[str, str, str, str, datetime, datetime | None]:
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(
        smb_channels_module,
        "_unpack_closure_metadata_payloads",
        counted_unpack,
    )

    result = manager.watermark(_START + timedelta(minutes=2))

    assert len(result.closures) == 1
    assert calls == 0
    assert result.closures[0].channel_id == lease.channel_id
    assert calls == 1


def test_identifiers_are_hash_seed_independent() -> None:
    code = """
from evidenceforge.generation.smb_channels import SmbChannelAffinity
a = SmbChannelAffinity('CLIENT01','10.0.0.10','0x1001','FILE01','10.0.0.20',
                       'EXAMPLE\\\\analyst','kerberos','EXAMPLE','3.1.1','required',
                       'off','windows:file-server','disk:standard','windows_native')
print(a.owner_id, a.digest)
"""
    outputs = []
    for seed in ("1", "987654"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", code],
                env=env,
                text=True,
            ).strip()
        )
    assert outputs[0] == outputs[1]


def test_disjoint_channel_identities_are_worker_schedule_independent() -> None:
    """Stable semantic IDs must not depend on disjoint owner scheduling."""

    def run(worker_count: int) -> tuple[tuple[str, ...], ...]:
        manager = _manager()

        def execute(index: int) -> tuple[str, ...]:
            suffix = str(index + 1)
            lease = _open(
                manager,
                _affinity(
                    client_identity=f"client-{index}",
                    client_session=f"session-{index}",
                ),
                suffix=suffix,
                opened_at=_START + timedelta(microseconds=index),
            )
            handle = manager.open_handle(
                lease,
                file_id=f"file-{index}",
                content_version=1,
                access="read",
                opened_at=lease.started_at + timedelta(milliseconds=1),
            )
            fuid = manager.file_transfer_fuid(handle, "read")
            assert manager.close_handle(
                handle,
                lease,
                closed_at=lease.ended_at,
            )
            assert manager.finalize_operation(lease)
            return (
                lease.channel_id,
                lease.session_id,
                lease.tree_id,
                lease.operation_id,
                handle.handle_id,
                fuid,
            )

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            return tuple(executor.map(execute, range(96)))

    assert run(1) == run(4) == run(8)
