# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for duration-stable explicit-proxy channels."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionToken,
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
    ExplicitProxyRequestReuse,
    ExplicitProxyTerminalRequest,
    ExplicitProxyTunnelOpen,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 16, 12, tzinfo=UTC)
_END = _START + timedelta(days=31)


def _manager(**kwargs: object) -> ExplicitProxyChannelManager:
    return ExplicitProxyChannelManager(
        window_start=_START,
        window_end=_END,
        allow_private_registry=True,
        **kwargs,
    )


def _affinity(**changes: object) -> ExplicitProxyChannelAffinity:
    values: dict[str, object] = {
        "client_ip": "10.0.0.10",
        "proxy_ip": "10.0.3.10",
        "proxy_port": 8080,
        "origin_host": "Portal.Example.Test.",
        "origin_ip": "203.0.113.20",
        "origin_port": 443,
        "user_agent": "Mozilla/5.0  Example",
        "auth_identity": "EXAMPLE\\Alice",
        "policy_id": "TLS-Bump-Standard",
    }
    values.update(changes)
    return ExplicitProxyChannelAffinity(**values)  # type: ignore[arg-type]


def test_proxy_manager_requires_explicit_private_or_exact_shared_registry() -> None:
    """Production injection is mandatory and shard/window ownership must align."""

    with pytest.raises(ValueError, match="requires the shared"):
        ExplicitProxyChannelManager(window_start=_START, window_end=_END)

    shared = ApplicationChannelRegistry(window_start=_START, window_end=_END, shard_count=8)
    manager = ExplicitProxyChannelManager(
        window_start=_START,
        window_end=_END,
        registry=shared,
        shard_count=8,
    )
    assert manager.application_registry is shared

    with pytest.raises(ValueError, match="shard_count must match"):
        ExplicitProxyChannelManager(
            window_start=_START,
            window_end=_END,
            registry=shared,
            shard_count=4,
        )


def _open(
    manager: ExplicitProxyChannelManager,
    affinity: ExplicitProxyChannelAffinity | None = None,
    *,
    suffix: str = "1",
    opened_at: datetime = _START,
    duration: timedelta = timedelta(seconds=30),
    setup_offset: timedelta = timedelta(milliseconds=10),
    setup_duration: timedelta = timedelta(milliseconds=20),
    setup_request_bytes: int = 120,
    setup_response_bytes: int = 240,
    request_count: int = 1,
    aggregate_request_bytes: int = 1_000,
    aggregate_response_bytes: int = 5_000,
    outcome: str = "success",
):
    return manager.open_tunnel(
        affinity or _affinity(),
        client_transport_id=f"client-transport-{suffix}",
        origin_transport_id=f"origin-transport-{suffix}",
        client_zeek_uid=f"Cproxy{suffix}",
        origin_zeek_uid=f"Corigin{suffix}",
        tunnel_group_id=f"proxy-group-{suffix}",
        client_source_port=50_000 + int(suffix),
        origin_source_port=40_000 + int(suffix),
        opened_at=opened_at,
        closes_at=opened_at + duration,
        setup_started_at=opened_at + setup_offset,
        setup_completed_at=opened_at + setup_offset + setup_duration,
        setup_request_wire_bytes=setup_request_bytes,
        setup_response_wire_bytes=setup_response_bytes,
        planned_request_count=request_count,
        aggregate_request_wire_bytes=aggregate_request_bytes,
        aggregate_response_wire_bytes=aggregate_response_bytes,
        setup_outcome=outcome,  # type: ignore[arg-type]
    )


def _prepare_open(
    manager: ExplicitProxyChannelManager,
    affinity: ExplicitProxyChannelAffinity | None = None,
    *,
    suffix: str = "1",
    opened_at: datetime = _START,
    duration: timedelta = timedelta(seconds=30),
    request_count: int = 1,
    aggregate_request_bytes: int = 1_000,
    aggregate_response_bytes: int = 5_000,
) -> ExplicitProxyAdmissionToken | None:
    return manager.prepare_open_tunnel(
        affinity or _affinity(),
        client_transport_id=f"client-transport-{suffix}",
        origin_transport_id=f"origin-transport-{suffix}",
        client_zeek_uid=f"Cproxy{suffix}",
        origin_zeek_uid=f"Corigin{suffix}",
        tunnel_group_id=f"proxy-group-{suffix}",
        client_source_port=50_000 + int(suffix),
        origin_source_port=40_000 + int(suffix),
        opened_at=opened_at,
        closes_at=opened_at + duration,
        setup_started_at=opened_at + timedelta(milliseconds=10),
        setup_completed_at=opened_at + timedelta(milliseconds=30),
        setup_request_wire_bytes=120,
        setup_response_wire_bytes=240,
        planned_request_count=request_count,
        aggregate_request_wire_bytes=aggregate_request_bytes,
        aggregate_response_wire_bytes=aggregate_response_bytes,
    )


def test_prepared_open_abort_and_cancel_publish_no_canonical_state() -> None:
    """Preparation and aborted claims retain reservations, never channel rows."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    prepared = manager.census()
    assert prepared.open_tunnel_views == 0
    assert prepared.prepared_admissions == 1
    assert prepared.claimed_admissions == 0
    assert prepared.reserved_channel_ids == 1
    assert prepared.reserved_affinities == 1
    assert prepared.reserved_origin_transport_ids == 1
    assert prepared.estimated_prepared_bytes > 0
    assert prepared.application.retained_channels == 0
    assert prepared.application.prepared_admissions == 1

    with manager.prepared_admission(token):
        claimed = manager.census()
        assert claimed.claimed_admissions == 1
        assert claimed.application.claimed_admissions == 1
        assert not manager.cancel_prepared_admission(token)
        assert manager.get_tunnel(token.result.tunnel.channel_id) is None

    cancelled = manager.census()
    assert cancelled.open_tunnel_views == 0
    assert cancelled.prepared_admissions == 0
    assert cancelled.claimed_admissions == 0
    assert cancelled.application.retained_channels == 0
    assert cancelled.application.prepared_admissions == 0
    assert not manager.cancel_prepared_admission(token)

    second = _prepare_open(manager, suffix="2")
    assert second is not None
    assert manager.cancel_prepared_admission(second)
    assert not manager.cancel_prepared_admission(second)
    assert manager.census().application.prepared_admissions == 0


def test_prepared_open_and_request_commit_exact_frozen_results() -> None:
    """Commit publishes the exact common row and packed proxy sidecar once."""

    manager = _manager()
    open_token = _prepare_open(manager)
    assert open_token is not None
    with manager.prepared_admission(open_token) as transaction:
        committed_open = transaction.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            transaction.commit_no_fail()
    assert manager.authenticates_admission_receipt(committed_open.receipt)
    opened = committed_open.result
    assert isinstance(opened, ExplicitProxyTunnelOpen)
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel

    request_token = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=25),
        request_wire_bytes=1_000,
        response_wire_bytes=5_000,
    )
    assert request_token is not None
    before = manager.channel_snapshot(opened.tunnel.channel_id)
    assert before is not None and before.reserved_operations == 1
    with manager.prepared_admission(request_token) as transaction:
        committed_request = transaction.commit_no_fail()
    assert manager.authenticates_admission_receipt(committed_request.receipt)
    request = committed_request.result
    assert isinstance(request, ExplicitProxyRequestReuse)
    assert request.tunnel == opened.tunnel
    assert committed_request.receipt.operation_id == request.operation_id
    assert committed_request.receipt.current_transport_id == request.tunnel.client_transport_id
    assert committed_request.receipt.prerequisite_transport_ids == ()
    request_swapped = replace(
        committed_request.receipt,
        current_transport_id=request.tunnel.origin_transport_id,
        prerequisite_transport_ids=(request.tunnel.client_transport_id,),
    )
    request_missing = replace(committed_request.receipt, current_transport_id="")
    request_foreign = replace(
        committed_request.receipt,
        current_transport_id="foreign-client-transport",
    )
    assert not manager.authenticates_admission_receipt(request_swapped)
    assert not manager.authenticates_admission_receipt(request_missing)
    assert not manager.authenticates_admission_receipt(request_foreign)
    after = manager.channel_snapshot(opened.tunnel.channel_id)
    assert after is not None and after.reserved_operations == 2


def test_prepared_terminal_request_is_atomic_cancelable_and_receipted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal preparation keeps the tunnel open until one atomic common/proxy commit."""

    manager = _manager()
    opened = _open(manager, request_count=2)
    assert opened is not None
    before = manager.channel_snapshot(opened.tunnel.channel_id)
    assert before is not None and before.is_open

    cancelled = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=25),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome="denied",
    )
    assert cancelled is not None
    assert isinstance(cancelled.result, ExplicitProxyTerminalRequest)
    prepared = manager.census()
    assert prepared.prepared_admissions == 1
    assert prepared.application.prepared_admissions == 1
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel
    assert manager.cancel_prepared_admission(cancelled)
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before

    aborted = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=25),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome="denied",
    )
    assert aborted is not None
    with manager.prepared_admission(aborted):
        assert manager.channel_snapshot(opened.tunnel.channel_id) == before
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before

    token = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=25),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome="denied",
    )
    assert token is not None

    def fail_public_close(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("terminal proxy commit called the non-atomic public close API")

    monkeypatch.setattr(ApplicationChannelRegistry, "close_channel_by_token", fail_public_close)
    with manager.prepared_admission(token) as transaction:
        committed = transaction.commit_no_fail()

    terminal = committed.result
    assert isinstance(terminal, ExplicitProxyTerminalRequest)
    assert terminal.outcome == "denied"
    assert terminal.close_reason == "terminal denied"
    assert manager.authenticates_admission_receipt(committed.receipt)
    assert committed.receipt.current_transport_id == terminal.tunnel.client_transport_id
    assert committed.receipt.prerequisite_transport_ids == ()
    assert committed.receipt.sidecar_result == terminal
    assert committed.receipt.application_receipt.snapshot.closed_at == terminal.close_at
    assert committed.receipt.application_receipt.snapshot.close_reason == terminal.close_reason
    assert manager.get_tunnel(terminal.tunnel.channel_id) is None
    closed = manager.channel_snapshot(terminal.tunnel.channel_id)
    assert closed is not None
    assert closed.reserved_operations == 2
    assert closed.completed_operations == 2
    assert closed.closed_at == terminal.close_at
    assert closed.close_reason == terminal.close_reason
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0
    changed_outcome = replace(
        committed.receipt,
        sidecar_result=replace(terminal, outcome="gateway_failure"),
    )
    changed_reason = replace(
        committed.receipt,
        sidecar_result=replace(terminal, close_reason="retargeted close"),
    )
    changed_time = replace(
        committed.receipt,
        sidecar_result=replace(terminal, close_at=terminal.close_at + timedelta(microseconds=1)),
    )
    assert not manager.authenticates_admission_receipt(changed_outcome)
    assert not manager.authenticates_admission_receipt(changed_reason)
    assert not manager.authenticates_admission_receipt(changed_time)


def test_prepared_terminal_request_tamper_foreign_stale_and_overflow_preserve_tunnel() -> None:
    """Every failed terminal capability path retains the exact live tunnel unchanged."""

    manager = _manager()
    foreign = _manager()
    opened = _open(manager)
    assert opened is not None
    before = manager.channel_snapshot(opened.tunnel.channel_id)
    assert before is not None
    token = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome="denied",
    )
    assert token is not None
    with pytest.raises(StateError, match="another manager"):
        with foreign.prepared_admission(token):
            pytest.fail("foreign manager unexpectedly claimed a terminal request")
    assert manager.cancel_prepared_admission(token)
    with pytest.raises(StateError, match="stale or already consumed"):
        with manager.prepared_admission(token):
            pytest.fail("cancelled terminal request unexpectedly entered a claim")
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before

    tampered = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome="denied",
    )
    assert tampered is not None
    object.__setattr__(tampered.application_token, "channel_close_reason", "retargeted close")
    with pytest.raises(StateError, match="integrity validation failed"):
        with manager.prepared_admission(tampered):
            pytest.fail("tampered terminal request unexpectedly entered a claim")
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel


def test_request_snapshot_is_signed_nonmutating_and_fences_generation_drift() -> None:
    """Deferred request snapshots authenticate exact affinity, state, and ABA generation."""

    manager = _manager()
    foreign = _manager()
    opened = _open(manager, request_count=2)
    assert opened is not None
    before = manager.channel_snapshot(opened.tunnel.channel_id)
    snapshot = manager.snapshot_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
    )
    assert snapshot is not None
    assert snapshot.tunnel == opened.tunnel
    assert snapshot.application_snapshot == before
    assert manager.authenticates_request_snapshot(snapshot)
    assert not foreign.authenticates_request_snapshot(snapshot)
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0

    changed_time = replace(snapshot, requested_at=snapshot.requested_at + timedelta(microseconds=1))
    changed_generation = replace(
        snapshot,
        generation_token=replace(
            snapshot.generation_token,
            generation=snapshot.generation_token.generation + 1,
        ),
    )
    assert not manager.authenticates_request_snapshot(changed_time)
    assert not manager.authenticates_request_snapshot(changed_generation)
    with pytest.raises(StateError, match="authentic current-tunnel snapshot"):
        manager.prepare_request(
            _affinity(),
            requested_at=snapshot.requested_at,
            completed_at=snapshot.requested_at + timedelta(milliseconds=25),
            request_wire_bytes=100,
            response_wire_bytes=200,
            expected_snapshot=changed_generation,
        )
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before

    registry = manager.application_registry
    routed = registry._channel_route(opened.tunnel.channel_id)
    assert routed is not None
    _route, shard_id, channel_handle = routed
    shard = registry._owner_shard(shard_id, create=False)
    assert shard is not None
    with shard.lock:
        retained = shard.channels.delete(channel_handle)
        assert shard.channels.insert(retained) == channel_handle
    assert manager.authenticates_request_snapshot(snapshot)
    with pytest.raises(StateError, match="snapshot is stale"):
        manager.prepare_request(
            _affinity(),
            requested_at=snapshot.requested_at,
            completed_at=snapshot.requested_at + timedelta(milliseconds=25),
            request_wire_bytes=100,
            response_wire_bytes=200,
            expected_snapshot=snapshot,
        )
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel

    overflow = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=1_001,
        response_wire_bytes=0,
        outcome="denied",
    )
    assert overflow is None
    assert manager.channel_snapshot(opened.tunnel.channel_id) == before
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel


def test_prepared_claim_body_holds_no_proxy_or_common_lock() -> None:
    """An unrelated reader makes progress while an admission body is claimed."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    channel_id = token.result.tunnel.channel_id
    with manager.prepared_admission(token):
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(manager.get_tunnel, channel_id).result(timeout=1) is None


def test_prepared_commit_receipt_rejects_wrong_manager_and_nested_tamper() -> None:
    """The proxy HMAC binds its exact result and authenticated common receipt."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    with manager.prepared_admission(token) as transaction:
        committed = transaction.commit_no_fail()
    assert manager.authenticates_admission_receipt(committed.receipt)
    assert committed.receipt.manager_kind == "explicit_proxy"
    assert committed.receipt.manager_instance_id == manager.manager_instance_id
    assert committed.receipt.publication_token == token.publication_token
    assert (
        committed.receipt.application_receipt.publication_token
        == token.application_token.publication_token
    )
    assert (
        committed.receipt.common_receipt_token
        == committed.receipt.application_receipt.receipt_token
    )
    assert (
        committed.receipt.application_receipt_token
        == committed.receipt.application_receipt.receipt_token
    )
    assert committed.receipt.channel_id == committed.result.tunnel.channel_id
    assert committed.receipt.operation_id == committed.result.setup_operation_id
    assert committed.receipt.current_transport_id == committed.result.tunnel.origin_transport_id
    assert committed.receipt.prerequisite_transport_ids == (
        committed.result.tunnel.client_transport_id,
    )
    assert committed.receipt.physical_transport_ids == (
        committed.result.tunnel.client_transport_id,
        committed.result.tunnel.origin_transport_id,
    )
    assert committed.receipt.origin_affinity_digest == committed.result.tunnel.affinity_digest
    assert len(committed.receipt.result_digest) == 64
    assert committed.receipt.sidecar_result == committed.result
    assert committed.receipt.sidecar_result_digest == committed.receipt.result_digest
    assert not _manager().authenticates_admission_receipt(committed.receipt)

    changed_manager = replace(committed.receipt, manager_id="retargeted-manager")
    assert not manager.authenticates_admission_receipt(changed_manager)
    swapped_legs = replace(
        committed.receipt,
        current_transport_id=committed.result.tunnel.client_transport_id,
        prerequisite_transport_ids=(committed.result.tunnel.origin_transport_id,),
    )
    assert not manager.authenticates_admission_receipt(swapped_legs)
    missing_prerequisite = replace(committed.receipt, prerequisite_transport_ids=())
    assert not manager.authenticates_admission_receipt(missing_prerequisite)
    foreign_origin = replace(committed.receipt, current_transport_id="foreign-origin-transport")
    assert not manager.authenticates_admission_receipt(foreign_origin)

    changed_result = replace(
        committed.receipt,
        sidecar_result=replace(committed.result, remaining_request_count=999),
    )
    assert not manager.authenticates_admission_receipt(changed_result)
    changed_common = replace(
        committed.receipt.application_receipt,
        operation_id="retargeted-operation",
    )
    changed_nested = replace(committed.receipt, application_receipt=changed_common)
    assert not manager.authenticates_admission_receipt(changed_nested)


def test_prepared_token_wrong_manager_and_tamper_fail_closed() -> None:
    """Manager identity plus nested common/proxy seals reject retargeted tokens."""

    manager = _manager()
    other = _manager()
    token = _prepare_open(manager)
    assert token is not None
    with pytest.raises(StateError, match="another manager"):
        with other.prepared_admission(token):
            pass

    changed_proxy = replace(token, _owner_id="retargeted-owner")
    with pytest.raises(StateError, match="stale or already consumed"):
        with manager.prepared_admission(changed_proxy):
            pass

    object.__setattr__(token.application_token, "_integrity_token", "0" * 64)
    with pytest.raises(StateError, match="integrity validation failed"):
        with manager.prepared_admission(token):
            pass
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0

    proxy_tamper = _prepare_open(manager, suffix="2")
    assert proxy_tamper is not None
    object.__setattr__(proxy_tamper, "_owner_id", "retargeted-owner")
    with pytest.raises(StateError, match="token was modified"):
        with manager.prepared_admission(proxy_tamper):
            pass
    assert manager.census().prepared_admissions == 0
    assert manager.census().application.prepared_admissions == 0

    manager_token_tamper = _prepare_open(manager, suffix="3")
    assert manager_token_tamper is not None
    object.__setattr__(manager_token_tamper, "_manager_token", id(other))
    with pytest.raises(StateError, match="token was modified"):
        with manager.prepared_admission(manager_token_tamper):
            pass
    final = manager.census()
    assert final.prepared_admissions == 0
    assert final.application.prepared_admissions == 0


def test_prepared_admission_watermark_fences_claims_and_stales_unclaimed() -> None:
    """A claim blocks its frontier while a watermark invalidates older unclaimed work."""

    manager = _manager()
    claimed = _prepare_open(manager)
    assert claimed is not None
    with manager.prepared_admission(claimed):
        with pytest.raises(StateError, match="cannot advance past a claimed admission"):
            manager.watermark(_START + timedelta(seconds=1))

    stale = _prepare_open(manager, suffix="2", opened_at=_START + timedelta(seconds=2))
    assert stale is not None
    manager.watermark(_START + timedelta(seconds=3))
    with pytest.raises(StateError, match="behind the canonical watermark"):
        with manager.prepared_admission(stale):
            pass
    assert not manager.cancel_prepared_admission(stale)
    assert manager.census().application.prepared_admissions == 0


def test_prepared_replacement_and_overflow_abort_preserve_existing_tunnel() -> None:
    """Neither replacement preparation nor overflow retires live canonical state."""

    manager = _manager()
    opened = _open(manager)
    assert opened is not None

    replacement = _prepare_open(
        manager,
        suffix="2",
        opened_at=_START + timedelta(seconds=1),
    )
    assert replacement is not None
    with manager.prepared_admission(replacement):
        prior = manager.channel_snapshot(opened.tunnel.channel_id)
        assert prior is not None and prior.is_open
        assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel
        with pytest.raises(StateError, match="has a prepared admission"):
            manager.close_tunnel(
                opened.tunnel.channel_id,
                closed_at=_START + timedelta(seconds=1),
                reason="racing close",
            )
    prior = manager.channel_snapshot(opened.tunnel.channel_id)
    assert prior is not None and prior.is_open

    overflow = manager.prepare_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=2),
        completed_at=_START + timedelta(seconds=2),
        request_wire_bytes=1_001,
        response_wire_bytes=0,
    )
    assert overflow is None
    prior = manager.channel_snapshot(opened.tunnel.channel_id)
    assert prior is not None and prior.is_open
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel

    committed = _prepare_open(
        manager,
        suffix="3",
        opened_at=_START + timedelta(seconds=3),
    )
    assert committed is not None
    with manager.prepared_admission(committed) as transaction:
        replacement_commit = transaction.commit_no_fail()
    replacement_result = replacement_commit.result
    assert isinstance(replacement_result, ExplicitProxyTunnelOpen)
    prior = manager.channel_snapshot(opened.tunnel.channel_id)
    assert prior is not None and prior.close_reason == "replaced"
    assert manager.get_tunnel(opened.tunnel.channel_id) is None
    assert manager.get_tunnel(replacement_result.tunnel.channel_id) == replacement_result.tunnel


def test_replacement_open_during_prior_setup_closes_at_completed_setup_frontier() -> None:
    """Parallel proxy setup replaces only after the prior setup's last activity."""

    manager = _manager()
    prior = _open(
        manager,
        setup_offset=timedelta(seconds=1),
        setup_duration=timedelta(seconds=2),
    )
    assert prior is not None
    prior_snapshot = manager.channel_snapshot(prior.tunnel.channel_id)
    assert prior_snapshot is not None
    assert prior_snapshot.last_activity_at == _START + timedelta(seconds=3)

    replacement = _prepare_open(
        manager,
        suffix="2",
        opened_at=_START + timedelta(seconds=2, milliseconds=500),
    )
    assert replacement is not None
    with manager.prepared_admission(replacement) as transaction:
        committed = transaction.commit_no_fail()

    replacement_result = committed.result
    assert isinstance(replacement_result, ExplicitProxyTunnelOpen)
    closed_prior = manager.channel_snapshot(prior.tunnel.channel_id)
    assert closed_prior is not None
    assert closed_prior.closed_at == prior_snapshot.last_activity_at
    assert closed_prior.close_reason == "replaced"
    assert manager.get_tunnel(prior.tunnel.channel_id) is None
    assert manager.get_tunnel(replacement_result.tunnel.channel_id) == replacement_result.tunnel


def test_setup_only_tunnel_summarizes_setup_without_open_reuse_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful CONNECT setup may have zero request children."""

    manager = _manager()

    def fail_public_close(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("setup-only proxy commit called the non-atomic public close API")

    monkeypatch.setattr(ApplicationChannelRegistry, "close_channel_by_token", fail_public_close)
    token = _prepare_open(
        manager,
        request_count=0,
        aggregate_request_bytes=0,
        aggregate_response_bytes=0,
    )
    assert token is not None
    with manager.prepared_admission(token) as prepared:
        committed = prepared.commit_no_fail()
    assert manager.authenticates_admission_receipt(committed.receipt)
    opened = committed.result

    assert isinstance(opened, ExplicitProxyTunnelOpen)
    assert opened.remaining_request_count == 0
    assert manager.get_tunnel(opened.tunnel.channel_id) is None
    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.closed_at == _START + timedelta(milliseconds=30)
    assert snapshot.close_reason == "setup-only"
    assert snapshot.reserved_operations == 1
    assert snapshot.completed_operations == 1
    assert snapshot.reserved_initiator_bytes == 120
    assert snapshot.reserved_responder_bytes == 240
    census = manager.census()
    assert census.open_tunnel_views == 0
    assert census.prepared_admissions == 0
    assert census.application.open_channels == 0
    assert census.application.prepared_admissions == 0


def test_one_child_reuses_exact_identity_and_does_not_double_count_upload() -> None:
    """Proxy wire totals include upload bodies once, not body plus wire total."""

    manager = _manager()
    opened = _open(
        manager,
        request_count=1,
        aggregate_request_bytes=1_200,
        aggregate_response_bytes=4_000,
    )
    assert opened is not None

    reused = manager.reserve_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=250),
        request_wire_bytes=1_200,
        response_wire_bytes=4_000,
        upload_body_bytes=1_000,
        expected_channel_id=opened.tunnel.channel_id,
        expected_client_transport_id="client-transport-1",
        expected_origin_transport_id="origin-transport-1",
        expected_client_source_port=50_001,
    )

    assert reused is not None
    assert reused.tunnel == opened.tunnel
    assert reused.tunnel.client_zeek_uid == "Cproxy1"
    assert reused.tunnel.origin_zeek_uid == "Corigin1"
    assert reused.tunnel.client_source_port == 50_001
    assert reused.tunnel.proxy_listener_port == 8080
    assert reused.tunnel.origin_source_port == 40_001
    assert reused.tunnel.origin_destination_port == 443
    assert reused.ordinal == 1
    assert reused.remaining_request_count == 0
    assert reused.remaining_request_wire_bytes == 0
    assert reused.remaining_response_wire_bytes == 0

    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.identity.binding.transport_id == "client-transport-1"
    assert snapshot.reserved_initiator_bytes == 120 + 1_200
    assert snapshot.reserved_responder_bytes == 240 + 4_000
    assert snapshot.reserved_operations == 2
    assert snapshot.completed_operations == 2
    assert snapshot.is_open
    assert snapshot.close_reason == ""
    assert manager.census().open_tunnel_views == 1


def test_packed_tunnel_round_trips_overflow_text_and_large_byte_budgets() -> None:
    """Rare overflow rows preserve exact public identity without eager decoded state."""

    manager = _manager()
    opened = manager.open_tunnel(
        _affinity(),
        client_transport_id="client-" + "x" * 400,
        origin_transport_id="origin-" + "y" * 400,
        client_zeek_uid="Cproxy-unicode-é",
        origin_zeek_uid="Corigin-unicode-λ",
        tunnel_group_id="proxy-group-overflow",
        client_source_port=50_001,
        origin_source_port=40_001,
        opened_at=_START,
        closes_at=_START + timedelta(minutes=30),
        setup_started_at=_START + timedelta(milliseconds=10),
        setup_completed_at=_START + timedelta(milliseconds=20),
        setup_request_wire_bytes=0,
        setup_response_wire_bytes=0,
        planned_request_count=1,
        aggregate_request_wire_bytes=2**40,
        aggregate_response_wire_bytes=2**41,
    )

    assert opened is not None
    before = manager.census()
    assert before.decoded_cache_entries == 0
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel
    after = manager.census()
    assert after.decoded_cache_entries == 1
    assert after.decoded_cache_entries <= after.decoded_cache_capacity
    assert after.decoded_cache_estimated_bytes > 0


def test_multiple_children_preserve_identity_and_remaining_aggregate_budgets() -> None:
    """One CONNECT setup can own N ordered request children on one transport."""

    manager = _manager()
    request_sizes = ((210, 1_000), (320, 2_000), (470, 2_000))
    opened = _open(
        manager,
        request_count=len(request_sizes),
        aggregate_request_bytes=sum(item[0] for item in request_sizes),
        aggregate_response_bytes=sum(item[1] for item in request_sizes),
    )
    assert opened is not None

    results = []
    for index, (request_bytes, response_bytes) in enumerate(request_sizes, start=1):
        result = manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=index),
            completed_at=_START + timedelta(seconds=index, milliseconds=100),
            request_wire_bytes=request_bytes,
            response_wire_bytes=response_bytes,
        )
        assert result is not None
        results.append(result)

    assert [result.ordinal for result in results] == [1, 2, 3]
    assert [result.remaining_request_count for result in results] == [2, 1, 0]
    assert [result.remaining_request_wire_bytes for result in results] == [790, 470, 0]
    assert [result.remaining_response_wire_bytes for result in results] == [4_000, 2_000, 0]
    assert {result.tunnel.channel_id for result in results} == {opened.tunnel.channel_id}
    assert {result.tunnel.client_transport_id for result in results} == {"client-transport-1"}
    assert {result.tunnel.origin_transport_id for result in results} == {"origin-transport-1"}


@pytest.mark.parametrize(
    "different",
    [
        _affinity(client_ip="10.0.0.11"),
        _affinity(proxy_ip="10.0.3.11"),
        _affinity(proxy_port=3128),
        _affinity(origin_host="other.example.test"),
        _affinity(origin_ip="203.0.113.21"),
        _affinity(origin_port=8443),
        _affinity(user_agent="curl/8.0"),
        _affinity(auth_identity="example\\bob"),
        _affinity(auth_identity="example\\alice"),
        _affinity(policy_id="pass-through"),
        _affinity(policy_id="tls-bump-standard"),
    ],
)
def test_every_affinity_dimension_is_an_exact_reuse_fence(
    different: ExplicitProxyChannelAffinity,
) -> None:
    """No client, proxy, origin, UA, authentication, or policy broad search occurs."""

    manager = _manager()
    assert _open(manager) is not None

    assert (
        manager.reserve_request(
            different,
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=0,
            response_wire_bytes=0,
        )
        is None
    )
    census = manager.census()
    assert census.open_tunnel_views == 1
    assert census.application.lookup_candidates_inspected == 0
    assert census.sidecar_estimated_bytes > census.sidecar_estimated_index_bytes


def test_affinity_normalization_and_stable_ids_ignore_population_order() -> None:
    """Semantic IDs are stable across case normalization and unrelated insertion."""

    normalized = _affinity(
        origin_host="portal.example.test",
        user_agent="mozilla/5.0 example",
    )
    assert normalized.digest == _affinity().digest

    first_manager = _manager()
    first = _open(first_manager, normalized)
    assert first is not None
    first_child = first_manager.reserve_request(
        normalized,
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=1_000,
        response_wire_bytes=5_000,
    )

    second_manager = _manager()
    unrelated = _affinity(client_ip="10.0.0.99", origin_host="other.example.test")
    assert _open(second_manager, unrelated, suffix="9") is not None
    second = _open(second_manager, normalized)
    assert second is not None
    second_child = second_manager.reserve_request(
        normalized,
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=1_000,
        response_wire_bytes=5_000,
    )

    assert first_child is not None and second_child is not None
    assert first.tunnel.channel_id == second.tunnel.channel_id
    assert first.setup_operation_id == second.setup_operation_id
    assert first_child.operation_id == second_child.operation_id


@pytest.mark.parametrize(
    ("request_bytes", "response_bytes"),
    [(1_001, 0), (0, 5_001)],
)
def test_directional_capacity_miss_preserves_exact_tunnel(
    request_bytes: int,
    response_bytes: int,
) -> None:
    """A capacity miss requests replacement without retiring the old transport."""

    manager = _manager()
    opened = _open(manager)
    assert opened is not None

    assert (
        manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=request_bytes,
            response_wire_bytes=response_bytes,
        )
        is None
    )
    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.is_open
    assert snapshot.close_reason == ""
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel


def test_remaining_request_count_is_a_hard_operation_capacity() -> None:
    """Zero remaining requests cannot be bypassed with a zero-byte child."""

    manager = _manager()
    opened = _open(
        manager,
        request_count=1,
        aggregate_request_bytes=0,
        aggregate_response_bytes=0,
    )
    assert opened is not None
    final_planned = manager.reserve_request(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=0,
        response_wire_bytes=0,
    )
    assert final_planned is not None
    assert final_planned.remaining_request_count == 0

    assert (
        manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=2),
            completed_at=_START + timedelta(seconds=2),
            request_wire_bytes=0,
            response_wire_bytes=0,
        )
        is None
    )
    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.is_open
    assert snapshot.close_reason == ""
    assert manager.get_tunnel(opened.tunnel.channel_id) == opened.tunnel


def test_idle_timeout_and_close_guard_are_exclusive_fences() -> None:
    """Neither an idle-expired tunnel nor its close guard admits another child."""

    timeout_manager = _manager(idle_timeout=timedelta(seconds=2))
    timed = _open(timeout_manager)
    assert timed is not None
    timed_snapshot = timeout_manager.channel_snapshot(timed.tunnel.channel_id)
    assert timed_snapshot is not None
    assert (
        timeout_manager.reserve_request(
            _affinity(),
            requested_at=timed_snapshot.idle_deadline,
            completed_at=timed_snapshot.idle_deadline,
            request_wire_bytes=0,
            response_wire_bytes=0,
        )
        is None
    )
    timed_snapshot = timeout_manager.channel_snapshot(timed.tunnel.channel_id)
    assert timed_snapshot is not None
    assert timed_snapshot.closed_at == _START + timedelta(seconds=2, milliseconds=30)

    guard_manager = _manager(close_guard=timedelta(seconds=2))
    guarded = _open(guard_manager, duration=timedelta(seconds=10))
    assert guarded is not None
    assert guarded.tunnel.reuse_deadline == _START + timedelta(seconds=8)
    assert (
        guard_manager.reserve_request(
            _affinity(),
            requested_at=guarded.tunnel.reuse_deadline,
            completed_at=guarded.tunnel.reuse_deadline,
            request_wire_bytes=0,
            response_wire_bytes=0,
        )
        is None
    )
    guarded_snapshot = guard_manager.channel_snapshot(guarded.tunnel.channel_id)
    assert guarded_snapshot is not None
    assert guarded_snapshot.closed_at == guarded.tunnel.reuse_deadline
    assert guarded_snapshot.close_reason == "reuse deadline"

    crossing_manager = _manager(close_guard=timedelta(seconds=2))
    crossing = _open(crossing_manager, duration=timedelta(seconds=10))
    assert crossing is not None
    assert (
        crossing_manager.reserve_request(
            _affinity(),
            requested_at=crossing.tunnel.reuse_deadline - timedelta(milliseconds=1),
            completed_at=crossing.tunnel.reuse_deadline + timedelta(milliseconds=1),
            request_wire_bytes=0,
            response_wire_bytes=0,
        )
        is None
    )


def test_setup_and_child_error_outcomes_never_leave_reusable_state() -> None:
    """Failed setup is not admitted and a terminal child retires its exact tunnel."""

    setup_error_manager = _manager()
    assert _open(setup_error_manager, outcome="authentication_required") is None
    setup_census = setup_error_manager.census()
    assert setup_census.open_tunnel_views == 0
    assert setup_census.application.retained_channels == 0

    child_error_manager = _manager()
    opened = _open(child_error_manager)
    assert opened is not None
    assert (
        child_error_manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=100,
            response_wire_bytes=200,
            outcome="denied",
        )
        is None
    )
    snapshot = child_error_manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == 2
    assert snapshot.completed_operations == 2
    assert snapshot.close_reason == "terminal denied"
    assert child_error_manager.census().open_tunnel_views == 0


def test_transport_and_expected_identity_fences_fail_closed() -> None:
    """Transport IDs cannot overlap and stale caller identities cannot reserve."""

    manager = _manager()
    opened = _open(manager)
    assert opened is not None
    other = _affinity(client_ip="10.0.0.11")
    with pytest.raises(StateError, match="client transport already belongs"):
        manager.open_tunnel(
            other,
            client_transport_id="client-transport-1",
            origin_transport_id="origin-transport-2",
            client_zeek_uid="Cproxy2",
            origin_zeek_uid="Corigin2",
            tunnel_group_id="proxy-group-2",
            client_source_port=50_002,
            origin_source_port=40_002,
            opened_at=_START + timedelta(seconds=1),
            closes_at=_START + timedelta(seconds=30),
            setup_started_at=_START + timedelta(seconds=1, milliseconds=10),
            setup_completed_at=_START + timedelta(seconds=1, milliseconds=30),
            setup_request_wire_bytes=120,
            setup_response_wire_bytes=240,
            planned_request_count=1,
            aggregate_request_wire_bytes=1_000,
            aggregate_response_wire_bytes=5_000,
        )

    with pytest.raises(StateError, match="origin transport identity mismatch"):
        manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=100,
            response_wire_bytes=200,
            expected_origin_transport_id="wrong-origin",
        )
    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == 1

    another_manager = _manager()
    assert _open(another_manager) is not None
    same_owner_other = _affinity(
        origin_host="other.example.test",
        origin_ip="203.0.113.21",
    )
    with pytest.raises(StateError, match="origin transport already belongs"):
        another_manager.open_tunnel(
            same_owner_other,
            client_transport_id="client-transport-2",
            origin_transport_id="origin-transport-1",
            client_zeek_uid="Cproxy2",
            origin_zeek_uid="Corigin2",
            tunnel_group_id="proxy-group-2",
            client_source_port=50_002,
            origin_source_port=40_002,
            opened_at=_START + timedelta(seconds=1),
            closes_at=_START + timedelta(seconds=30),
            setup_started_at=_START + timedelta(seconds=1, milliseconds=10),
            setup_completed_at=_START + timedelta(seconds=1, milliseconds=30),
            setup_request_wire_bytes=120,
            setup_response_wire_bytes=240,
            planned_request_count=1,
            aggregate_request_wire_bytes=1_000,
            aggregate_response_wire_bytes=5_000,
        )


def test_client_transport_binding_remains_reserved_through_close_grace() -> None:
    """Removing a proxy sidecar cannot prematurely release its physical transport."""

    manager = _manager(closed_grace=timedelta(seconds=5))
    opened = _open(manager)
    assert opened is not None
    assert manager.close_tunnel(
        opened.tunnel.channel_id,
        closed_at=_START + timedelta(seconds=2),
        reason="normal",
    )

    replacement = _affinity(client_ip="10.0.0.11", origin_host="other.example.test")
    with pytest.raises(StateError, match="already owns open channel or retained channel"):
        manager.open_tunnel(
            replacement,
            client_transport_id="client-transport-1",
            origin_transport_id="origin-transport-2",
            client_zeek_uid="Cproxy2",
            origin_zeek_uid="Corigin2",
            tunnel_group_id="proxy-group-2",
            client_source_port=50_002,
            origin_source_port=40_002,
            opened_at=_START + timedelta(seconds=3),
            closes_at=_START + timedelta(seconds=30),
            setup_started_at=_START + timedelta(seconds=3, milliseconds=10),
            setup_completed_at=_START + timedelta(seconds=3, milliseconds=30),
            setup_request_wire_bytes=120,
            setup_response_wire_bytes=240,
            planned_request_count=1,
            aggregate_request_wire_bytes=1_000,
            aggregate_response_wire_bytes=5_000,
        )

    manager.watermark(_START + timedelta(seconds=8))
    replacement_open = manager.open_tunnel(
        replacement,
        client_transport_id="client-transport-1",
        origin_transport_id="origin-transport-2",
        client_zeek_uid="Cproxy2",
        origin_zeek_uid="Corigin2",
        tunnel_group_id="proxy-group-2",
        client_source_port=50_002,
        origin_source_port=40_002,
        opened_at=_START + timedelta(seconds=9),
        closes_at=_START + timedelta(seconds=30),
        setup_started_at=_START + timedelta(seconds=9, milliseconds=10),
        setup_completed_at=_START + timedelta(seconds=9, milliseconds=30),
        setup_request_wire_bytes=120,
        setup_response_wire_bytes=240,
        planned_request_count=1,
        aggregate_request_wire_bytes=1_000,
        aggregate_response_wire_bytes=5_000,
    )
    assert replacement_open is not None


def test_invalid_upload_and_setup_only_budgets_are_atomic() -> None:
    """Invalid aggregate accounting cannot partially mutate shared state."""

    manager = _manager()
    with pytest.raises(ValueError, match="Setup-only"):
        _open(
            manager,
            request_count=0,
            aggregate_request_bytes=1,
            aggregate_response_bytes=0,
        )
    assert manager.census().application.retained_channels == 0

    opened = _open(manager)
    assert opened is not None
    with pytest.raises(StateError, match="Upload body"):
        manager.reserve_request(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=99,
            response_wire_bytes=0,
            upload_body_bytes=100,
        )
    snapshot = manager.channel_snapshot(opened.tunnel.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == 1


def test_large_unrelated_population_inspects_bounded_exact_candidates() -> None:
    """Reuse work is independent of unrelated proxy channels."""

    manager = _manager()
    selected: ExplicitProxyChannelAffinity | None = None
    for index in range(1_000):
        selected = _affinity(
            client_ip=f"10.{index // 65_536}.{(index // 256) % 256}.{index % 256}",
            origin_host=f"host-{index}.example.test",
        )
        assert _open(manager, selected, suffix=str(index + 1)) is not None

    assert selected is not None
    reused = manager.reserve_request(
        selected,
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1),
        request_wire_bytes=1_000,
        response_wire_bytes=5_000,
    )
    assert reused is not None
    census = manager.census()
    assert census.open_tunnel_views == 1_000
    assert census.sidecar_lookup_candidates_inspected == 1
    # One affinity candidate selects the tunnel and one exact channel
    # candidate validates the common aggregate mutation.
    assert census.application.lookup_candidates_inspected == 2
    assert census.application.maximum_affinity_bucket == 1


def test_exact_channel_lookup_reports_one_sidecar_candidate() -> None:
    """A successful channel route accounts for its one collision-checked row."""

    manager = _manager()
    opened = _open(manager)
    assert opened is not None
    before = manager.census().sidecar_lookup_candidates_inspected
    found = manager.get_tunnel(opened.tunnel.channel_id)
    after = manager.census().sidecar_lookup_candidates_inspected
    assert found == opened.tunnel
    assert after - before == 1


def test_disjoint_owner_sidecar_mutations_make_true_concurrent_progress() -> None:
    """One blocked owner shard cannot serialize an unrelated proxy request."""

    manager = _manager()
    first_affinity = _affinity(client_ip="10.0.0.10")
    second_affinity = _affinity(
        client_ip="10.0.0.11",
        origin_host="second.example.test",
        origin_ip="203.0.113.21",
    )
    assert _open(manager, first_affinity, suffix="1") is not None
    assert _open(manager, second_affinity, suffix="2") is not None
    first_shard = manager._sidecar_shard(first_affinity.owner_id, create=False)
    second_shard = manager._sidecar_shard(second_affinity.owner_id, create=False)
    assert first_shard is not None and second_shard is not None
    assert first_shard is not second_shard

    first_started = Event()

    def reserve_first():
        first_started.set()
        return manager.reserve_request(
            first_affinity,
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=1_000,
            response_wire_bytes=5_000,
        )

    with ThreadPoolExecutor(max_workers=2) as executor, first_shard.lock:
        blocked = executor.submit(reserve_first)
        assert first_started.wait(timeout=1)
        independent = executor.submit(
            manager.reserve_request,
            second_affinity,
            requested_at=_START + timedelta(seconds=1),
            completed_at=_START + timedelta(seconds=1),
            request_wire_bytes=1_000,
            response_wire_bytes=5_000,
        )
        assert independent.result(timeout=2) is not None
        assert not blocked.done()
    assert blocked.result(timeout=2) is not None


def test_thirty_day_workload_plateaus_sidecars_tombstones_and_expiry() -> None:
    """Hourly tunnels retain no duration-wide tuple or operation history."""

    manager = _manager(
        closed_grace=timedelta(seconds=5),
        close_guard=timedelta(seconds=1),
    )
    maximum_retained = 0
    duration_census = {}
    for hour in range(30 * 24):
        opened_at = _START + timedelta(hours=hour)
        owner = hour % 64
        affinity = replace(
            _affinity(),
            client_ip=f"10.0.{owner // 256}.{owner % 256}",
            origin_host=f"host-{hour}.example.test",
        )
        opened = _open(
            manager,
            affinity,
            suffix=str(hour + 1),
            opened_at=opened_at,
            duration=timedelta(seconds=60),
            request_count=1,
            aggregate_request_bytes=500,
            aggregate_response_bytes=1_500,
        )
        assert opened is not None
        reused = manager.reserve_request(
            affinity,
            requested_at=opened_at + timedelta(seconds=1),
            completed_at=opened_at + timedelta(seconds=1, milliseconds=100),
            request_wire_bytes=500,
            response_wire_bytes=1_500,
            upload_body_bytes=300,
        )
        assert reused is not None
        census = manager.watermark(opened_at + timedelta(seconds=65))
        maximum_retained = max(maximum_retained, census.application.retained_channels)
        assert census.open_tunnel_views == 0
        assert census.application.retained_channels == 0
        assert census.application.active_operations == 0
        if hour + 1 in {24, 7 * 24, 30 * 24}:
            duration_census[hour + 1] = census

    final = manager.watermark(_START + timedelta(days=30, minutes=2))
    assert maximum_retained == 0
    assert final.open_tunnel_views == 0
    assert final.application.retained_channels == 0
    assert final.application.used_operation_ids == 0
    assert final.application.max_shard_load == 0
    assert final.application.high_water_mark <= 64
    assert final.tunnel_expiry_entries == 0
    assert final.stale_tunnel_expiry_entries == 0
    assert final.sidecar_allocated_slots <= 64
    assert final.sidecar_compaction_rotations > 0
    assert final.sidecar_compaction_work <= 30 * 24
    assert final.sidecar_compaction_pending == 0
    assert final.sidecar_primary_map_amplification <= 1.25
    for hours in (24, 7 * 24, 30 * 24):
        point = duration_census[hours]
        assert point.open_tunnel_views == 0
        assert point.application.retained_channels == 0
        assert point.application.route_entries == 0
    seven_day = duration_census[7 * 24]
    thirty_day = duration_census[30 * 24]
    assert thirty_day.sidecar_shard_count == seven_day.sidecar_shard_count
    assert thirty_day.sidecar_allocated_slots == seven_day.sidecar_allocated_slots
    assert thirty_day.sidecar_primary_map_bytes == seven_day.sidecar_primary_map_bytes
    assert (
        thirty_day.sidecar_estimated_index_bytes <= seven_day.sidecar_estimated_index_bytes * 1.10
    )
    assert thirty_day.sidecar_estimated_bytes <= seven_day.sidecar_estimated_bytes * 1.10
    assert thirty_day.application.route_map_bytes <= seven_day.application.route_map_bytes * 1.10
    assert thirty_day.application.estimated_bytes <= seven_day.application.estimated_bytes * 1.10
    assert thirty_day.application.route_map_amplification <= 1.25
    assert thirty_day.application.route_compaction_pending == 0
    assert thirty_day.application.store_primary_compaction_pending == 0
