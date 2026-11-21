# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""A small first RDP connection must admit supported later traffic generations."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.identity import SessionIdentity
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.actions.network_connection import DeferredRdpApplicationIntent
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _transaction(index: int, orig: int, resp: int) -> NetworkTransactionPlan:
    start = _START + timedelta(minutes=index)
    close = start + timedelta(seconds=30)
    return NetworkTransactionPlan(
        stable_id=f"physical-rdp-{index}",
        hostname="RDS",
        outcome="success",
        phase_times=(("transport_start", start), ("transport_close", close)),
        started_at=start,
        closed_at=close,
        src_ip="10.0.0.10",
        src_port=50000 + index,
        dst_ip="10.0.0.20",
        dst_port=3389,
        protocol="tcp",
        service="rdp",
        zeek_uid=f"Crdp{index}",
        conn_id=f"conn-{index}",
        duration=30.0,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(orig, 2000, orig + 80000),
            resp=DirectionalTrafficLedger(resp, 2000, resp + 80000),
        ),
    )


def test_small_first_transport_supports_maxima_and_keeps_logical_operation_limit() -> None:
    end = _START + timedelta(hours=2)
    application = ApplicationChannelRegistry(window_start=_START, window_end=end)
    manager = RdpReconnectStateManager(
        application_registry=application, window_start=_START, window_end=end
    )
    identity = SessionIdentity(
        hostname="RDS",
        object_id="session-rdp",
        logon_id="0x1234",
        session_id=1,
        principal="alice",
        session_kind="rdp",
        started_at=_START,
        lifecycle_group_id="rdp-lifecycle",
    )
    prior = None
    for generation in range(8):
        transaction = _transaction(
            generation, 50000 if generation == 0 else 500000, 100000 if generation == 0 else 2000000
        )
        intent = DeferredRdpApplicationIntent(
            manager=manager,
            source_host="CLIENT",
            target_host="RDS",
            principal="alice",
            hard_deadline=end,
            prior_session=prior,
            expected_generation=generation,
        )
        token, *_ = intent.prepare(identity, transaction)
        with manager.prepared_admission(token) as prepared:
            current = prepared.commit_no_fail().session
        admission = manager.reserve_operation(
            identity.object_id,
            started_at=transaction.started_at + timedelta(seconds=1),
            ended_at=transaction.started_at + timedelta(seconds=2),
            initiator_bytes=transaction.orig_bytes,
            responder_bytes=transaction.resp_bytes,
        )
        current = admission.session
        assert manager.finalize_operation(identity.object_id, admission.reservation.operation_id)
        assert current.reserved_initiator_bytes == 50000 + generation * 500000
        assert current.reserved_responder_bytes == 100000 + generation * 2000000
        assert current.reserved_operations == generation + 1
        prior = manager.disconnect(
            identity.object_id,
            channel_id=current.generation.channel_id,
            disconnected_at=transaction.closed_at,
        )
    assert prior is not None and prior.identity.budget.operations == 8
    ninth = DeferredRdpApplicationIntent(
        manager=manager,
        source_host="CLIENT",
        target_host="RDS",
        principal="alice",
        hard_deadline=end,
        prior_session=prior,
        expected_generation=8,
    )
    ninth_transport = _transaction(8, 50000, 100000)
    token, *_ = ninth.prepare(identity, ninth_transport)
    with manager.prepared_admission(token) as prepared:
        prepared.commit_no_fail()
    with pytest.raises(StateError, match="logical operation budget"):
        manager.reserve_operation(
            identity.object_id,
            started_at=ninth_transport.started_at + timedelta(seconds=1),
            ended_at=ninth_transport.started_at + timedelta(seconds=2),
        )
