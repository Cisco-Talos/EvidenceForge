# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for authenticated staged RDP transport admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationTransportBinding,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpSessionState,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionToken,
    rdp_session_sidecar_result_digest,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)
_END = _START + timedelta(days=1)


def _manager() -> tuple[RdpReconnectStateManager, ApplicationChannelRegistry]:
    application = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        closed_grace=timedelta(minutes=5),
    )
    return (
        RdpReconnectStateManager(
            application_registry=application,
            window_start=_START,
            window_end=_END,
        ),
        application,
    )


def _identity(index: int, *, operation_budget: int = 4) -> RdpLogicalSessionIdentity:
    return RdpLogicalSessionIdentity(
        logical_session_id=f"rdp-logical-{index}",
        affinity=RdpSessionAffinity(
            source_host=f"client-{index}.example.test",
            source_address=f"10.1.0.{index}",
            target_host="rds-01.example.test",
            target_address="10.2.0.10",
            principal=f"EXAMPLE\\user{index}",
            logon_id=f"0x{0x1000 + index:X}",
            session_id=index,
        ),
        started_at=_START,
        idle_timeout=timedelta(minutes=20),
        reconnect_timeout=timedelta(minutes=10),
        hard_deadline=_START + timedelta(hours=2),
        budget=ApplicationChannelBudget(10_000, 20_000, operation_budget),
    )


def _transport(
    index: int,
    generation: int,
    *,
    connected_at: datetime,
    operation_budget: int = 4,
) -> RdpTransportPlan:
    return RdpTransportPlan(
        channel_id=f"rdp-channel-{index}-{generation}",
        binding=ApplicationTransportBinding(
            transport_id=f"rdp-transport-{index}-{generation}",
            opened_at=connected_at - timedelta(milliseconds=100),
            closes_at=connected_at + timedelta(minutes=30),
        ),
        connected_at=connected_at,
        budget=ApplicationChannelBudget(5_000, 10_000, operation_budget),
    )


def test_prepare_and_cancel_publish_no_canonical_common_or_sidecar_state() -> None:
    """Preparation is invisible and cancellation releases both reservations."""

    manager, application = _manager()
    identity = _identity(1)
    transport = _transport(1, 0, connected_at=_START)
    manager_before = manager.census()
    application_before = application.census()

    token = manager.prepare_open_session(identity, transport)

    assert manager.authenticates_admission_token(token)
    assert manager.get(identity.logical_session_id) is None
    assert application.get(transport.channel_id) is None
    manager_after = manager.census()
    assert (
        manager_after.retained_sessions,
        manager_after.connected_sessions,
        manager_after.disconnected_sessions,
        manager_after.logged_out_sessions,
        manager_after.sidecar_shard_count,
        manager_after.affinity_partition_count,
    ) == (
        manager_before.retained_sessions,
        manager_before.connected_sessions,
        manager_before.disconnected_sessions,
        manager_before.logged_out_sessions,
        manager_before.sidecar_shard_count,
        manager_before.affinity_partition_count,
    )
    application_after = application.census()
    assert (
        application_after.retained_channels,
        application_after.open_channels,
        application_after.active_operations,
        application_after.used_operation_ids,
    ) == (
        application_before.retained_channels,
        application_before.open_channels,
        application_before.active_operations,
        application_before.used_operation_ids,
    )
    assert application_after.prepared_admissions == 1
    assert manager.cancel_prepared_admission(token)
    assert not manager.cancel_prepared_admission(token)
    assert not manager.authenticates_admission_token(token)
    assert manager.get(identity.logical_session_id) is None
    assert application.get(transport.channel_id) is None

    replacement = manager.prepare_open_session(identity, transport)
    assert manager.cancel_prepared_admission(replacement)


def test_claim_body_is_lock_free_and_commit_receipt_authenticates_exact_result() -> None:
    """A claimed admission permits disjoint work and commits one signed result."""

    manager, application = _manager()
    identity = _identity(2)
    transport = _transport(2, 0, connected_at=_START)
    token = manager.prepare_open_session(identity, transport)

    with manager.prepared_admission(token) as prepared:
        disjoint = manager.open_session(
            _identity(3),
            _transport(3, 0, connected_at=_START),
        )
        admission = prepared.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    assert disjoint.logical_session_id == "rdp-logical-3"
    assert admission.session == manager.get(identity.logical_session_id)
    assert admission.application.snapshot == application.get(transport.channel_id)
    assert admission.receipt.transport_ids == (transport.binding.transport_id,)
    assert admission.receipt.sidecar_result_digest == rdp_session_sidecar_result_digest(
        admission.session
    )
    assert manager.authenticates_admission_receipt(admission.receipt)
    assert application.authenticates_admission_receipt(admission.receipt.application_receipt)
    assert not manager.authenticates_admission_token(token)


def test_uncommitted_claim_aborts_without_common_or_sidecar_publication() -> None:
    """Leaving a claim without commit consumes no canonical identities or capacity."""

    manager, application = _manager()
    identity = _identity(4)
    transport = _transport(4, 0, connected_at=_START)
    token = manager.prepare_open_session(identity, transport)

    with manager.prepared_admission(token):
        assert manager.get(identity.logical_session_id) is None
        assert application.get(transport.channel_id) is None

    assert not manager.authenticates_admission_token(token)
    assert manager.get(identity.logical_session_id) is None
    assert application.get(transport.channel_id) is None
    retry = manager.prepare_open_session(identity, transport)
    assert manager.cancel_prepared_admission(retry)


def test_forged_token_cannot_cancel_original_and_tampered_receipt_is_rejected() -> None:
    """Public substitution cannot redirect cancellation or receipt membership."""

    manager, _application = _manager()
    identity = _identity(5)
    transport = _transport(5, 0, connected_at=_START)
    token = manager.prepare_open_session(identity, transport)
    forged = replace(token, transport_ids=("rdp-transport-forged",))

    assert not manager.cancel_prepared_admission(forged)
    assert manager.authenticates_admission_token(token)
    with manager.prepared_admission(token) as prepared:
        admission = prepared.commit_no_fail()

    tampered = replace(admission.receipt, sidecar_result_digest="0" * 64)
    assert not manager.authenticates_admission_receipt(tampered)
    assert manager.authenticates_admission_receipt(admission.receipt)


def test_same_object_token_tamper_cancels_only_its_trusted_nested_reservation() -> None:
    """Integrity failure releases manager-owned keys without trusting edited fields."""

    manager, application = _manager()
    identity = _identity(8)
    transport = _transport(8, 0, connected_at=_START)
    token = manager.prepare_open_session(identity, transport)
    object.__setattr__(token, "transport_ids", ("rdp-transport-forged",))

    with pytest.raises(StateError, match="integrity validation failed"):
        manager.cancel_prepared_admission(token)

    assert application.get(transport.channel_id) is None
    assert not manager.authenticates_admission_token(token)
    replacement = manager.prepare_open_session(identity, transport)
    assert manager.cancel_prepared_admission(replacement)


def test_reconnect_receipt_binds_prior_and_current_transport_generations() -> None:
    """Reconnect preparation freezes history and publishes only after coupled commit."""

    manager, application = _manager()
    identity = _identity(6)
    first = _transport(6, 0, connected_at=_START)
    manager.open_session(identity, first)
    prior = manager.disconnect(
        identity.logical_session_id,
        channel_id=first.channel_id,
        disconnected_at=_START + timedelta(minutes=2),
    )
    second = _transport(6, 1, connected_at=_START + timedelta(minutes=3))

    token = manager.prepare_reconnect(
        identity.logical_session_id,
        affinity=identity.affinity,
        transport=second,
        expected_generation=1,
    )

    assert isinstance(token, RdpSessionAdmissionToken)
    assert token.transport_ids == (
        first.binding.transport_id,
        second.binding.transport_id,
    )
    assert manager.get(identity.logical_session_id) == prior
    assert application.get(second.channel_id) is None
    with manager.prepared_admission(token) as prepared:
        admission = prepared.commit_no_fail()

    assert admission.session.state is RdpSessionState.CONNECTED
    assert admission.session.generation.ordinal == 1
    assert admission.receipt.transport_ids == token.transport_ids
    assert admission.receipt.application_receipt.snapshot.identity.binding == second.binding
    assert manager.authenticates_admission_receipt(admission.receipt)


def test_private_transport_operation_does_not_consume_public_rdp_capacity() -> None:
    """The common staging sentinel leaves the authored RDP operation budget intact."""

    manager, application = _manager()
    identity = _identity(7, operation_budget=1)
    transport = _transport(7, 0, connected_at=_START, operation_budget=1)
    manager.open_session(identity, transport)

    operation = manager.reserve_operation(
        identity.logical_session_id,
        started_at=_START + timedelta(seconds=1),
        ended_at=_START + timedelta(seconds=2),
    )
    assert operation.session.reserved_operations == 1
    assert operation.reservation.operation_id.startswith("rdp-operation-")
    common = application.get(transport.channel_id)
    assert common is not None
    assert common.identity.budget.operations == 2
    assert common.reserved_operations == 2
    with pytest.raises(StateError, match="logical operation budget"):
        manager.reserve_operation(
            identity.logical_session_id,
            started_at=_START + timedelta(seconds=3),
            ended_at=_START + timedelta(seconds=4),
        )
