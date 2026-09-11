# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for duration-stable HTTP application channels."""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAdmissionToken,
    HttpChannelAffinity,
    HttpChannelTransport,
    http_channel_sidecar_result_digest,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 16, 12, tzinfo=UTC)
_END = _START + timedelta(days=3)


def _manager(**kwargs: object) -> HttpApplicationChannelManager:
    return HttpApplicationChannelManager(
        window_start=_START,
        window_end=_END,
        allow_private_registry=True,
        **kwargs,
    )


def _affinity(
    *,
    src_ip: str = "10.0.0.10",
    dst_ip: str = "203.0.113.20",
    dst_port: int = 80,
    host: str = "Portal.Example.Test.",
    user_agent: str = "Mozilla/5.0",
) -> HttpChannelAffinity:
    return HttpChannelAffinity.from_request(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        http_host=host,
        user_agent=user_agent,
    )


def test_http_manager_requires_explicit_private_or_exact_shared_registry() -> None:
    """Production injection is mandatory and must use one matching canonical window."""

    with pytest.raises(ValueError, match="requires the shared"):
        HttpApplicationChannelManager(window_start=_START, window_end=_END)

    shared = ApplicationChannelRegistry(window_start=_START, window_end=_END)
    manager = HttpApplicationChannelManager(
        window_start=_START,
        window_end=_END,
        registry=shared,
    )
    assert manager.application_registry is shared

    with pytest.raises(ValueError, match="window must exactly match"):
        HttpApplicationChannelManager(
            window_start=_START,
            window_end=_END + timedelta(seconds=1),
            registry=shared,
        )


def _open(
    manager: HttpApplicationChannelManager,
    affinity: HttpChannelAffinity | None = None,
    *,
    suffix: str = "1",
    opened_at: datetime = _START,
    duration: timedelta = timedelta(seconds=10),
    initial_request_offset: timedelta = timedelta(milliseconds=100),
    orig_budget: int = 1_000,
    resp_budget: int = 10_000,
    initial_request_body_bytes: int = 10,
    initial_response_body_bytes: int = 100,
    operation_budget: int | None = None,
):
    return manager.open_transport(
        affinity or _affinity(),
        transport_id=f"transport-{suffix}",
        zeek_uid=f"CUID{suffix}",
        conn_id=f"conn-{suffix}",
        src_port=50_000 + int(suffix),
        opened_at=opened_at,
        closes_at=opened_at + duration,
        initial_request_time=opened_at + initial_request_offset,
        orig_budget=orig_budget,
        resp_budget=resp_budget,
        initial_request_body_bytes=initial_request_body_bytes,
        initial_response_body_bytes=initial_response_body_bytes,
        operation_budget=operation_budget,
    )


def _prepare_open(
    manager: HttpApplicationChannelManager,
    affinity: HttpChannelAffinity | None = None,
    *,
    suffix: str = "1",
    opened_at: datetime = _START,
    duration: timedelta = timedelta(seconds=10),
    initial_request_offset: timedelta = timedelta(milliseconds=100),
    orig_budget: int = 1_000,
    resp_budget: int = 10_000,
    initial_request_body_bytes: int = 10,
    initial_response_body_bytes: int = 100,
    operation_budget: int | None = None,
) -> HttpChannelAdmissionToken | None:
    """Prepare the same canonical parent shape used by :func:`_open`."""

    return manager.prepare_open_transport(
        affinity or _affinity(),
        transport_id=f"transport-{suffix}",
        zeek_uid=f"CUID{suffix}",
        conn_id=f"conn-{suffix}",
        src_port=50_000 + int(suffix),
        opened_at=opened_at,
        closes_at=opened_at + duration,
        initial_request_time=opened_at + initial_request_offset,
        orig_budget=orig_budget,
        resp_budget=resp_budget,
        initial_request_body_bytes=initial_request_body_bytes,
        initial_response_body_bytes=initial_response_body_bytes,
        operation_budget=operation_budget,
    )


def test_http_affinity_preserves_legacy_exact_key_normalization() -> None:
    """Host/UA case normalize while every legacy tuple dimension remains exact."""

    first = _affinity()
    equivalent = _affinity(host="portal.example.test", user_agent="mozilla/5.0")

    assert first.host == "portal.example.test"
    assert first.user_agent == "mozilla/5.0"
    assert first.digest == equivalent.digest
    assert first.owner_id == "http-source:10.0.0.10"
    assert first.digest != _affinity(src_ip="10.0.0.11").digest
    assert first.digest != _affinity(dst_ip="203.0.113.21").digest
    assert first.digest != _affinity(dst_port=8080).digest
    assert first.digest != _affinity(host="other.example.test").digest
    assert first.digest != _affinity(user_agent="curl/8.0").digest


def test_reuse_returns_frozen_wire_identity_depth_and_monotonic_time() -> None:
    """A hit reuses UID/conn/port and immediately summarizes its operation."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None

    second = manager.reserve_reuse(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert second is not None
    assert second.channel_id == transport.channel_id
    assert second.zeek_uid == "CUID1"
    assert second.conn_id == "conn-1"
    assert second.src_port == 50_001
    assert second.trans_depth == 2
    assert second.canonical_request_time == _START + timedelta(seconds=1)

    snapshot = manager.channel_snapshot(transport.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == 2
    assert snapshot.completed_operations == 2
    assert snapshot.active_operations == 0
    assert snapshot.reserved_initiator_bytes == 30
    assert snapshot.reserved_responder_bytes == 300

    out_of_order = manager.reserve_reuse(
        _affinity(),
        requested_at=_START + timedelta(milliseconds=500),
    )
    assert out_of_order is not None
    assert out_of_order.trans_depth == 3
    assert out_of_order.canonical_request_time == second.canonical_request_time + timedelta(
        microseconds=1
    )


@pytest.mark.parametrize(
    "different",
    [
        _affinity(src_ip="10.0.0.11"),
        _affinity(dst_ip="203.0.113.21"),
        _affinity(dst_port=8080),
        _affinity(host="other.example.test"),
        _affinity(user_agent="curl/8.0"),
    ],
)
def test_reuse_never_broadly_searches_across_affinity_dimensions(
    different: HttpChannelAffinity,
) -> None:
    """Every legacy affinity dimension fences reuse through one exact lookup."""

    manager = _manager()
    assert _open(manager) is not None

    assert (
        manager.reserve_reuse(
            different,
            requested_at=_START + timedelta(seconds=1),
        )
        is None
    )
    assert manager.census().open_transport_views == 1


def test_close_guard_miss_leaves_the_open_channel_unchanged() -> None:
    """A request at the close guard consumes no state before replacement commits."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None
    assert transport.reuse_deadline == _START + timedelta(seconds=9, milliseconds=100)
    before = manager.channel_snapshot(transport.channel_id)

    assert (
        manager.reserve_reuse(
            _affinity(),
            requested_at=transport.reuse_deadline,
        )
        is None
    )
    assert manager.get_transport(transport.channel_id) == transport
    assert manager.channel_snapshot(transport.channel_id) == before


def test_required_child_span_may_end_exactly_at_parent_close() -> None:
    """The immutable transport close is an inclusive child-containment fence."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None

    reused = manager.reserve_reuse(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        required_until=transport.closes_at,
    )

    assert reused is not None
    assert reused.channel_id == transport.channel_id
    snapshot = manager.channel_snapshot(transport.channel_id)
    assert snapshot is not None
    assert snapshot.is_open
    assert snapshot.reserved_operations == 2


def test_required_child_span_overflow_leaves_exact_channel_unchanged() -> None:
    """A child beyond the parent close consumes no budget or existing state."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None
    before = manager.channel_snapshot(transport.channel_id)

    assert (
        manager.reserve_reuse(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            required_until=transport.closes_at + timedelta(microseconds=1),
            request_body_bytes=20,
            response_body_bytes=200,
        )
        is None
    )

    assert manager.get_transport(transport.channel_id) == transport
    assert manager.channel_snapshot(transport.channel_id) == before


def test_invalid_required_child_span_is_atomic() -> None:
    """An inverted child interval mutates neither sidecar nor common channel state."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None
    before = manager.channel_snapshot(transport.channel_id)

    with pytest.raises(ValueError, match="required_until"):
        manager.reserve_reuse(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            required_until=_START + timedelta(milliseconds=999),
        )

    assert manager.get_transport(transport.channel_id) == transport
    assert manager.channel_snapshot(transport.channel_id) == before


@pytest.mark.parametrize(
    ("open_kwargs", "request_bytes", "response_bytes"),
    [
        ({"orig_budget": 100, "resp_budget": 1_000}, 91, 0),
        ({"orig_budget": 1_000, "resp_budget": 200}, 0, 101),
        ({"operation_budget": 1}, 0, 0),
    ],
)
def test_capacity_miss_leaves_the_old_exact_channel_unchanged(
    open_kwargs: dict[str, int],
    request_bytes: int,
    response_bytes: int,
) -> None:
    """Directional or operation overflow cannot retire a reusable parent early."""

    manager = _manager()
    transport = _open(manager, **open_kwargs)
    assert transport is not None
    before = manager.channel_snapshot(transport.channel_id)

    assert (
        manager.reserve_reuse(
            _affinity(),
            requested_at=_START + timedelta(seconds=1),
            request_body_bytes=request_bytes,
            response_body_bytes=response_bytes,
        )
        is None
    )
    assert manager.get_transport(transport.channel_id) == transport
    assert manager.channel_snapshot(transport.channel_id) == before


def test_invalid_initial_budget_is_atomic() -> None:
    """A failed first reservation leaves no channel, sidecar, or expiry state."""

    manager = _manager()
    with pytest.raises(StateError, match="originator budget"):
        _open(
            manager,
            orig_budget=5,
            initial_request_body_bytes=6,
        )

    census = manager.census()
    assert census.open_transport_views == 0
    assert census.application.retained_channels == 0
    assert census.transport_expiry_entries == 0
    assert census.sidecar_estimated_index_bytes >= 0


def test_prepared_open_is_invisible_and_cancel_releases_both_capabilities() -> None:
    """Preparation and cancellation publish neither common state nor an HTTP sidecar."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    transport = token.result
    assert isinstance(transport, HttpChannelTransport)
    assert manager.authenticates_admission_token(token)
    assert manager.application_registry.authenticates_admission_token(token.application_token)
    assert manager.get_transport(transport.channel_id) is None
    assert manager.channel_snapshot(transport.channel_id) is None
    assert manager.census().application.retained_channels == 0

    assert manager.cancel_prepared_admission(token)
    assert not manager.authenticates_admission_token(token)
    assert not manager.application_registry.authenticates_admission_token(token.application_token)
    assert manager.get_transport(transport.channel_id) is None
    assert manager.channel_snapshot(transport.channel_id) is None
    assert not manager.cancel_prepared_admission(token)

    replacement = _prepare_open(manager)
    assert replacement is not None
    assert replacement is not token
    with pytest.raises(StateError, match="stale or already consumed"):
        with manager.prepared_admission(token):
            pass
    assert manager.authenticates_admission_token(replacement)
    assert manager.cancel_prepared_admission(replacement)


def test_prepared_open_commit_issues_authenticated_nested_receipts_once() -> None:
    """A claimed manager commit publishes exact state and two authenticated proofs once."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    publication_token = token.publication_token
    with manager.prepared_admission(token) as prepared:
        assert prepared.result is None
        admission = prepared.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    transport = admission.result
    assert isinstance(transport, HttpChannelTransport)
    assert admission.receipt.manager_kind == "http"
    assert admission.receipt.manager_id == manager.manager_id
    assert admission.receipt.publication_token == publication_token
    assert admission.application.receipt == admission.receipt.application_receipt
    assert (
        admission.receipt.application_receipt_token
        == admission.receipt.application_receipt.receipt_token
    )
    assert admission.receipt.channel_id == transport.channel_id
    assert admission.receipt.operation_id == admission.receipt.application_receipt.operation_id
    assert admission.receipt.transport_id == transport.transport_id
    assert admission.receipt.sidecar_result == transport
    assert admission.receipt.sidecar_result_digest == http_channel_sidecar_result_digest(transport)
    assert manager.authenticates_admission_receipt(admission.receipt)
    assert manager.application_registry.authenticates_admission_receipt(
        admission.receipt.application_receipt
    )
    assert manager.get_transport(transport.channel_id) == transport
    assert manager.channel_snapshot(transport.channel_id) == admission.application.snapshot
    assert not manager.authenticates_admission_token(token)

    foreign = _manager()
    assert not foreign.authenticates_admission_receipt(admission.receipt)
    tampered = replace(
        admission.receipt,
        sidecar_result=replace(transport, conn_id="tampered"),
    )
    assert not manager.authenticates_admission_receipt(tampered)
    wrong_type = replace(admission.receipt)
    object.__setattr__(wrong_type, "application_receipt", object())
    assert not manager.authenticates_admission_receipt(wrong_type)
    tampered_common = replace(
        admission.receipt.application_receipt,
        operation_id="tampered-operation",
    )
    assert not manager.application_registry.authenticates_admission_receipt(tampered_common)
    assert not manager.authenticates_admission_receipt(
        replace(admission.receipt, application_receipt=tampered_common)
    )
    with pytest.raises(StateError, match="stale or already consumed"):
        with manager.prepared_admission(token):
            pass


def test_prepared_reuse_abort_is_neutral_and_commit_consumes_budget_once() -> None:
    """A staged reuse mutates its aggregate snapshot only at the final commit."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None
    before = manager.channel_snapshot(transport.channel_id)
    token = manager.prepare_reuse(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert token is not None
    assert manager.channel_snapshot(transport.channel_id) == before
    with manager.prepared_admission(token):
        assert manager.channel_snapshot(transport.channel_id) == before
    assert manager.channel_snapshot(transport.channel_id) == before
    assert not manager.authenticates_admission_token(token)

    committed_token = manager.prepare_reuse(
        _affinity(),
        requested_at=_START + timedelta(seconds=1),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert committed_token is not None
    with manager.prepared_admission(committed_token) as prepared:
        admission = prepared.commit()
    reuse = admission.result
    assert reuse.trans_depth == 2
    assert manager.authenticates_admission_receipt(admission.receipt)
    snapshot = manager.channel_snapshot(transport.channel_id)
    assert snapshot is not None
    assert snapshot.reserved_operations == 2
    assert snapshot.completed_operations == 2
    assert snapshot.reserved_initiator_bytes == 30
    assert snapshot.reserved_responder_bytes == 300


def test_claimed_admission_fences_watermark_without_holding_body_locks() -> None:
    """The body can call back into the manager while its claimed frontier stays protected."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    with manager.prepared_admission(token) as prepared:
        assert not manager.cancel_prepared_admission(token)
        with pytest.raises(StateError, match="claimed admission"):
            manager.watermark(_START + timedelta(seconds=1))
        assert manager.channel_snapshot(token.result.channel_id) is None
        admission = prepared.commit_no_fail()
    assert manager.authenticates_admission_receipt(admission.receipt)


def test_unclaimed_admission_becomes_stale_behind_watermark_and_releases_reservations() -> None:
    """Only claims fence time; a later claim rejects and cleans an obsolete reservation."""

    manager = _manager()
    token = _prepare_open(manager)
    assert token is not None
    manager.watermark(_START + timedelta(seconds=1))
    with pytest.raises(StateError, match="behind the canonical watermark"):
        with manager.prepared_admission(token):
            pass
    assert not manager.authenticates_admission_token(token)
    assert manager.channel_snapshot(token.result.channel_id) is None

    replacement = _prepare_open(
        manager,
        opened_at=_START + timedelta(seconds=1),
    )
    assert replacement is not None
    assert manager.cancel_prepared_admission(replacement)


def test_foreign_manager_cannot_authenticate_claim_or_cancel_token() -> None:
    """Manager identity is an exact capability boundary."""

    manager = _manager()
    foreign = _manager()
    token = _prepare_open(manager)
    assert token is not None
    assert not foreign.authenticates_admission_token(token)
    assert not foreign.cancel_prepared_admission(token)
    with pytest.raises(StateError, match="belongs to another manager"):
        with foreign.prepared_admission(token):
            pass
    assert manager.cancel_prepared_admission(token)


def test_prepared_replacement_cancel_preserves_old_state_and_commit_swaps_once() -> None:
    """The old exact-affinity parent retires only inside a successful replacement commit."""

    manager = _manager()
    first = _open(manager)
    assert first is not None
    first_snapshot = manager.channel_snapshot(first.channel_id)

    cancelled = _prepare_open(
        manager,
        suffix="2",
        opened_at=_START + timedelta(seconds=2),
    )
    assert cancelled is not None
    second = cancelled.result
    assert isinstance(second, HttpChannelTransport)
    assert manager.get_transport(first.channel_id) == first
    assert manager.channel_snapshot(first.channel_id) == first_snapshot
    assert manager.get_transport(second.channel_id) is None
    assert manager.cancel_prepared_admission(cancelled)
    assert manager.get_transport(first.channel_id) == first
    assert manager.channel_snapshot(first.channel_id) == first_snapshot

    committed = _prepare_open(
        manager,
        suffix="2",
        opened_at=_START + timedelta(seconds=2),
    )
    assert committed is not None
    with manager.prepared_admission(committed) as prepared:
        assert manager.get_transport(first.channel_id) == first
        assert manager.channel_snapshot(first.channel_id) == first_snapshot
        admission = prepared.commit_no_fail()
    assert admission.result == second
    assert manager.get_transport(first.channel_id) is None
    assert manager.get_transport(second.channel_id) == second
    closed = manager.channel_snapshot(first.channel_id)
    assert closed is not None
    assert closed.close_reason == "replaced"
    assert manager.authenticates_admission_receipt(admission.receipt)


def test_opening_a_new_parent_replaces_only_the_same_exact_affinity() -> None:
    """One new parent replaces the legacy one-entry exact-affinity cache slot."""

    manager = _manager()
    first = _open(manager)
    second = _open(
        manager,
        suffix="2",
        opened_at=_START + timedelta(seconds=2),
    )
    assert first is not None
    assert second is not None
    assert manager.get_transport(first.channel_id) is None
    assert manager.get_transport(second.channel_id) == second

    first_snapshot = manager.channel_snapshot(first.channel_id)
    assert first_snapshot is not None
    assert first_snapshot.close_reason == "replaced"
    reused = manager.reserve_reuse(
        _affinity(),
        requested_at=_START + timedelta(seconds=3),
    )
    assert reused is not None
    assert reused.conn_id == "conn-2"


def test_explicit_close_is_idempotent_and_removes_protocol_state() -> None:
    """Finalization keeps only the common compact tombstone during its grace period."""

    manager = _manager()
    transport = _open(manager)
    assert transport is not None

    assert manager.close_transport(
        transport.channel_id,
        closed_at=_START + timedelta(seconds=2),
        reason="normal",
    )
    assert not manager.close_transport(
        transport.channel_id,
        closed_at=_START + timedelta(seconds=3),
        reason="duplicate",
    )
    assert manager.census().open_transport_views == 0
    snapshot = manager.channel_snapshot(transport.channel_id)
    assert snapshot is not None
    assert snapshot.close_reason == "normal"


def test_nonreusable_short_transport_is_never_retained() -> None:
    """A close guard that consumes the interval cannot create duration-wide state."""

    manager = _manager()
    assert (
        _open(
            manager,
            duration=timedelta(milliseconds=800),
            initial_request_offset=timedelta(milliseconds=100),
        )
        is None
    )
    assert manager.census().application.retained_channels == 0


def test_watermarks_plateau_transport_views_and_common_tombstones() -> None:
    """Repeated short channels retain no state once their explicit horizons pass."""

    manager = _manager(closed_grace=timedelta(seconds=5))
    for index in range(120):
        opened_at = _START + timedelta(minutes=index)
        transport = _open(
            manager,
            _affinity(host=f"host-{index}.example.test"),
            suffix=str(index + 1),
            opened_at=opened_at,
            duration=timedelta(seconds=2),
            initial_request_offset=timedelta(milliseconds=50),
        )
        assert transport is not None
        census = manager.watermark(opened_at + timedelta(seconds=7))
        assert census.open_transport_views == 0
        assert census.application.retained_channels == 0

    final = manager.census()
    assert final.open_transport_views == 0
    assert final.application.retained_channels == 0
    assert final.application.high_water_mark <= 1


def test_large_unrelated_population_inspects_bounded_exact_candidates() -> None:
    """Lookup work remains independent of unrelated channels at large cardinality."""

    manager = _manager()
    selected: HttpChannelAffinity | None = None
    for index in range(1_000):
        affinity = _affinity(
            src_ip=f"10.{index // 65_536}.{(index // 256) % 256}.{index % 256}",
            host=f"host-{index}.example.test",
        )
        selected = affinity
        assert _open(manager, affinity, suffix=str(index + 1)) is not None

    assert selected is not None
    reused = manager.reserve_reuse(
        selected,
        requested_at=_START + timedelta(seconds=1),
    )
    assert reused is not None
    census = manager.census()
    assert census.open_transport_views == 1_000
    # Preparation addresses the exact channel directly, so only that one
    # common-registry candidate is inspected regardless of population size.
    assert census.application.lookup_candidates_inspected == 1
    # Prepared sidecar probes are deliberately diagnostic-neutral until commit.
    assert census.sidecar_lookup_candidates_inspected == 0
    assert census.lookup_candidates_inspected == (
        census.application.lookup_candidates_inspected + census.sidecar_lookup_candidates_inspected
    )
    assert census.application.maximum_affinity_bucket == 1


def test_channel_and_operation_ids_are_independent_of_population_order() -> None:
    """Stable semantic IDs do not depend on unrelated insertion or worker scheduling."""

    target = _affinity()
    first_manager = _manager()
    first = _open(first_manager, target)
    first_reuse = first_manager.reserve_reuse(
        target,
        requested_at=_START + timedelta(seconds=1),
    )

    second_manager = _manager()
    assert (
        _open(
            second_manager,
            _affinity(host="unrelated.example.test"),
            suffix="9",
        )
        is not None
    )
    second = _open(second_manager, target)
    second_reuse = second_manager.reserve_reuse(
        target,
        requested_at=_START + timedelta(seconds=1),
    )

    assert first is not None and second is not None
    assert first_reuse is not None and second_reuse is not None
    assert first.channel_id == second.channel_id
    assert first_reuse.operation_id == second_reuse.operation_id


def _worker_identity_signature(worker_count: int) -> tuple[tuple[str, str, str, int], ...]:
    """Exercise disjoint exact channels and return their stable identity projection."""

    manager = _manager()
    items = tuple(
        (
            _affinity(
                src_ip=f"10.0.1.{ordinal}",
                host=f"worker-{ordinal}.example.test",
            ),
            str(ordinal),
        )
        for ordinal in range(1, 17)
    )

    def exercise(item: tuple[HttpChannelAffinity, str]) -> tuple[str, str, str, int]:
        affinity, suffix = item
        transport = _open(manager, affinity, suffix=suffix)
        assert transport is not None
        reuse = manager.reserve_reuse(
            affinity,
            requested_at=_START + timedelta(seconds=1),
        )
        assert reuse is not None
        return affinity.digest, transport.channel_id, reuse.operation_id, reuse.trans_depth

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        return tuple(sorted(executor.map(exercise, items)))


def test_http_channel_identity_is_identical_across_worker_counts() -> None:
    """Stable per-owner commit lanes yield the same identities with one or eight workers."""

    assert _worker_identity_signature(1) == _worker_identity_signature(8)


def test_http_channel_identity_ignores_python_hash_seed() -> None:
    """Exact affinity, channel, and operation IDs never depend on Python hashing."""

    script = """
from datetime import UTC, datetime, timedelta
from evidenceforge.generation.http_channels import HttpApplicationChannelManager, HttpChannelAffinity

start = datetime(2026, 8, 16, 12, tzinfo=UTC)
affinity = HttpChannelAffinity.from_request(
    src_ip="10.0.0.10",
    dst_ip="203.0.113.20",
    dst_port=80,
    http_host="Portal.Example.Test.",
    user_agent="Mozilla/5.0",
)
manager = HttpApplicationChannelManager(
    window_start=start,
    window_end=start + timedelta(days=1),
    allow_private_registry=True,
)
transport = manager.open_transport(
    affinity,
    transport_id="transport-1",
    zeek_uid="CUID1",
    conn_id="conn-1",
    src_port=50001,
    opened_at=start,
    closes_at=start + timedelta(seconds=10),
    initial_request_time=start + timedelta(milliseconds=100),
    orig_budget=1000,
    resp_budget=10000,
)
assert transport is not None
reuse = manager.reserve_reuse(affinity, requested_at=start + timedelta(seconds=1))
assert reuse is not None
print(affinity.digest, transport.channel_id, reuse.operation_id, reuse.trans_depth)
"""
    outputs = []
    for seed in ("1", "99991"):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(completed.stdout)

    assert outputs[0] == outputs[1]


def _owner_partition_affinities(
    manager: HttpApplicationChannelManager,
) -> tuple[HttpChannelAffinity, ...]:
    """Return one exact affinity for every stable HTTP owner partition."""

    affinities: dict[int, HttpChannelAffinity] = {}
    ordinal = 1
    while len(affinities) < manager._registry.shard_count:
        affinity = _affinity(
            src_ip=f"10.{ordinal // 65_536}.{(ordinal // 256) % 256}.{ordinal % 256}",
            host=f"plateau-{ordinal}.example.test",
        )
        affinities.setdefault(manager.owner_partition_id(affinity), affinity)
        ordinal += 1
    return tuple(affinities[partition] for partition in range(manager._registry.shard_count))


def test_http_sidecars_plateau_across_24h_7d_and_30d() -> None:
    """Open-only transport maps retain capacity by horizon, never elapsed duration."""

    manager = HttpApplicationChannelManager(
        window_start=_START,
        window_end=_START + timedelta(days=31),
        closed_grace=timedelta(seconds=5),
        allow_private_registry=True,
    )
    affinities = _owner_partition_affinities(manager)
    snapshots = {}
    for day in range(30):
        opened_at = _START + timedelta(days=day, minutes=1)
        for partition, affinity in enumerate(affinities):
            ordinal = day * len(affinities) + partition + 1
            assert (
                _open(
                    manager,
                    affinity,
                    suffix=str(ordinal),
                    opened_at=opened_at + timedelta(microseconds=partition),
                    duration=timedelta(seconds=2),
                    initial_request_offset=timedelta(milliseconds=50),
                )
                is not None
            )
        census = manager.watermark(opened_at + timedelta(seconds=7))
        assert census.open_transport_views == 0
        assert census.application.retained_channels == 0
        if day + 1 in {1, 7, 30}:
            snapshots[day + 1] = census

    day = snapshots[1]
    week = snapshots[7]
    month = snapshots[30]
    for census in (day, week, month):
        assert census.shard_count == manager._registry.shard_count
        assert census.transport_primary_compaction_pending == 0
        assert census.transport_primary_map_amplification <= 1.0
        assert census.transport_primary_compaction_rotations > 0
        assert census.application.route_entries == 0
        assert census.application.route_compaction_pending == 0
    assert day.transport_primary_map_bytes == week.transport_primary_map_bytes
    assert week.transport_primary_map_bytes == month.transport_primary_map_bytes
    assert month.sidecar_estimated_index_bytes <= week.sidecar_estimated_index_bytes * 1.1
    assert month.estimated_bytes <= week.estimated_bytes * 1.1
    assert month.application.estimated_bytes <= week.application.estimated_bytes * 1.1


def test_disjoint_http_owners_overlap_while_one_sidecar_shard_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One owner paused during canonical registration cannot serialize another owner."""

    manager = _manager()
    first_affinity = _affinity(src_ip="10.0.0.10", host="first.example.test")
    first_partition = manager.owner_partition_id(first_affinity)
    second_affinity = next(
        affinity
        for ordinal in range(11, 255)
        if manager.owner_partition_id(
            affinity := _affinity(
                src_ip=f"10.0.0.{ordinal}",
                host=f"second-{ordinal}.example.test",
            )
        )
        != first_partition
    )
    entered = Event()
    release = Event()
    original_open = manager._registry.prepare_open_channel_with_completed_operation

    def blocking_open(identity, reservation, **kwargs):
        if identity.owner_id == first_affinity.owner_id:
            entered.set()
            assert release.wait(timeout=2.0)
        return original_open(identity, reservation, **kwargs)

    monkeypatch.setattr(
        manager._registry,
        "prepare_open_channel_with_completed_operation",
        blocking_open,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        blocked = executor.submit(_open, manager, first_affinity, suffix="1")
        assert entered.wait(timeout=1.0)
        try:
            parallel = executor.submit(_open, manager, second_affinity, suffix="2")
            second = parallel.result(timeout=1.0)
            assert second is not None
        finally:
            release.set()
        first = blocked.result(timeout=2.0)
    assert first is not None
    assert manager.census().open_transport_views == 2
