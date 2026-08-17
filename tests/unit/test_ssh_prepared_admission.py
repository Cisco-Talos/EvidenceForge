# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for staged SSH/common application admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAdmissionToken,
    SshChannelAffinity,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
    ssh_channel_sidecar_result_digest,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 1, 9, tzinfo=UTC)
_END = _START + timedelta(days=1)


def _manager() -> tuple[SshApplicationChannelManager, ApplicationChannelRegistry]:
    application = ApplicationChannelRegistry(window_start=_START, window_end=_END)
    return (
        SshApplicationChannelManager(
            application_registry=application,
            window_start=_START,
            window_end=_END,
        ),
        application,
    )


def _values(index: int = 1) -> tuple[SshChannelAffinity, SshTransportPlan, SshSessionBinding]:
    opened_at = _START + timedelta(minutes=index)
    closes_at = opened_at + timedelta(minutes=30)
    client_session = f"client-session-{index}"
    server_session = f"server-session-{index}"
    affinity = SshChannelAffinity(
        client_identity=f"client-{index}",
        client_session_object_id=client_session,
        server_identity=f"server-{index}",
        server_session_object_id=server_session,
        principal=f"user-{index}",
        auth_method="publickey",
    )
    transport = SshTransportPlan(
        transport_id=f"transport-{index}",
        zeek_uid=f"Cssh{index:016d}",
        conn_id=f"conn-{index}",
        source_ip=f"10.10.0.{index}",
        server_ip=f"10.20.0.{index}",
        source_port=40_000 + index,
        server_port=22,
        opened_at=opened_at,
        closes_at=closes_at,
        source_process=SshProcessHold(
            hostname=f"client-{index}",
            pid=10_000 + index,
            process_object_id=f"source-process-{index}",
            session_object_id=client_session,
            principal=f"local-{index}",
            started_at=opened_at - timedelta(seconds=2),
            required_until=closes_at,
        ),
        receiver_process=SshProcessHold(
            hostname=f"server-{index}",
            pid=20_000 + index,
            process_object_id=f"receiver-process-{index}",
            session_object_id=server_session,
            principal=f"user-{index}",
            started_at=opened_at - timedelta(seconds=1),
            required_until=closes_at,
        ),
    )
    binding = SshSessionBinding(
        hostname=f"server-{index}",
        logon_id=f"0x{index:08x}",
        session_object_id=server_session,
        lifecycle_group_id=f"ssh-lifecycle-{index}",
        principal=f"user-{index}",
        ready_at=opened_at + timedelta(seconds=1),
    )
    return affinity, transport, binding


def _prepare(
    manager: SshApplicationChannelManager,
    index: int = 1,
) -> SshChannelAdmissionToken:
    affinity, transport, binding = _values(index)
    started_at = binding.ready_at + timedelta(seconds=1)
    return manager.prepare_open_session_with_completed_operation(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=30),
        initiator_budget=1_000,
        responder_budget=2_000,
        operation_budget=2,
        kind=SshOperationKind.EXEC,
        semantic_operation_id=f"exec-{index}",
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=1),
        initiator_bytes=32,
        responder_bytes=64,
    )


def test_prepared_ssh_open_is_invisible_and_cancel_releases_both_capabilities() -> None:
    manager, application = _manager()
    token = _prepare(manager)

    assert manager.authenticates_admission_token(token)
    assert application.authenticates_admission_token(token.application_token)
    assert manager.session_view(token.session.channel_id) is None
    assert application.get(token.session.channel_id) is None
    assert manager.census().open_sessions == 0
    assert application.census().retained_channels == 0

    assert manager.cancel_prepared_admission(token)
    assert not manager.authenticates_admission_token(token)
    assert not application.authenticates_admission_token(token.application_token)
    assert not manager.cancel_prepared_admission(token)


def test_prepared_ssh_commit_issues_one_authenticated_nested_receipt() -> None:
    manager, application = _manager()
    token = _prepare(manager)

    with manager.prepared_admission(token) as prepared:
        admission = prepared.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    assert admission.session == token.session
    assert admission.operation == token.operation
    assert admission.receipt.manager_kind == "ssh"
    assert admission.receipt.manager_id == manager.manager_id
    assert admission.receipt.publication_token == token.publication_token
    assert admission.receipt.application_receipt == admission.application.receipt
    assert admission.receipt.channel_id == token.session.channel_id
    assert admission.receipt.ssh_session_id == token.session.ssh_session_id
    assert admission.receipt.operation_id == token.operation.operation_id
    assert admission.receipt.transport_ids == (token.session.transport.transport_id,)
    assert admission.receipt.sidecar_result_digest == ssh_channel_sidecar_result_digest(
        token.session, token.operation
    )
    assert manager.authenticates_admission_receipt(admission.receipt)
    assert application.authenticates_admission_receipt(admission.receipt.application_receipt)
    assert manager.session_view(token.session.channel_id) == token.session
    assert application.get(token.session.channel_id) == admission.application.snapshot
    assert not manager.authenticates_admission_token(token)

    foreign, _foreign_application = _manager()
    assert not foreign.authenticates_admission_receipt(admission.receipt)
    assert not manager.authenticates_admission_receipt(
        replace(admission.receipt, sidecar_result_digest="0" * 64)
    )


def test_prepared_ssh_claim_body_holds_no_manager_lock_and_abort_is_neutral() -> None:
    manager, application = _manager()
    token = _prepare(manager)

    with manager.prepared_admission(token):
        assert manager.session_view(token.session.channel_id) is None
        assert application.get(token.session.channel_id) is None
        assert not manager.cancel_prepared_admission(token)

    assert manager.session_view(token.session.channel_id) is None
    assert application.get(token.session.channel_id) is None
    assert not manager.authenticates_admission_token(token)
    assert application.census().prepared_admissions == 0


def test_prepared_ssh_claim_fences_watermark_and_unclaimed_token_can_stale() -> None:
    manager, application = _manager()
    claimed = _prepare(manager)
    with manager.prepared_admission(claimed):
        with pytest.raises(StateError, match="claimed admission"):
            manager.watermark(claimed.linearization_time + timedelta(microseconds=1))
    assert application.census().prepared_admissions == 0

    stale = _prepare(manager, 2)
    manager.watermark(stale.linearization_time + timedelta(microseconds=1))
    with pytest.raises(StateError, match="behind the canonical watermark"):
        with manager.prepared_admission(stale):
            pass
    assert not manager.authenticates_admission_token(stale)
    assert application.census().prepared_admissions == 0


def test_prepared_ssh_in_place_tamper_rejects_and_releases_original_reservations() -> None:
    manager, application = _manager()
    token = _prepare(manager)
    object.__setattr__(token, "session", replace(token.session, ssh_session_id="tampered"))

    assert not manager.authenticates_admission_token(token)
    with pytest.raises(StateError, match="integrity"):
        manager.cancel_prepared_admission(token)
    assert application.census().prepared_admissions == 0
    replacement = _prepare(manager)
    assert manager.cancel_prepared_admission(replacement)


def test_immediate_ssh_completed_open_is_the_prepared_compatibility_wrapper() -> None:
    manager, application = _manager()
    affinity, transport, binding = _values(2)
    started_at = binding.ready_at + timedelta(seconds=1)

    session, operation = manager.open_session_with_completed_operation(
        affinity,
        transport=transport,
        binding=binding,
        idle_timeout=timedelta(minutes=30),
        initiator_budget=1_000,
        responder_budget=2_000,
        operation_budget=2,
        kind=SshOperationKind.EXEC,
        semantic_operation_id="exec-2",
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=1),
        initiator_bytes=32,
        responder_bytes=64,
    )

    assert manager.session_view(session.channel_id) == session
    assert manager.operation_lease(operation.operation_id) is None
    snapshot = application.get(session.channel_id)
    assert snapshot is not None
    assert snapshot.completed_operations == snapshot.reserved_operations == 1
    assert application.census().prepared_admissions == 0
