# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for the protocol-neutral application-channel registry."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

import evidenceforge.generation.application_channels as application_channels_module
from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionToken,
    ApplicationChannelCloseRequest,
    ApplicationChannelPreparedCloseToken,
    ApplicationChannelRegistry,
    _ApplicationChannelAdmissionCapability,
    _RoutePartition,
)
from evidenceforge.generation.indexes import PackedHandleExpiryIndex
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 16, 12, tzinfo=UTC)
_END = _START + timedelta(days=2)


def _identity(
    channel_id: str = "channel-1",
    *,
    owner_id: str = "owner-1",
    affinity_digest: str = "affinity-a",
    transport_id: str = "transport-1",
    opened_at: datetime = _START,
    idle_timeout: timedelta = timedelta(minutes=10),
    hard_deadline: datetime | None = None,
    budget: ApplicationChannelBudget | None = None,
) -> ApplicationChannelIdentity:
    hard_deadline = hard_deadline or opened_at + timedelta(hours=1)
    return ApplicationChannelIdentity(
        channel_id=channel_id,
        protocol="HTTP",
        owner_id=owner_id,
        affinity_digest=affinity_digest,
        binding=ApplicationTransportBinding(
            transport_id=transport_id,
            opened_at=opened_at - timedelta(seconds=1),
            closes_at=hard_deadline + timedelta(minutes=1),
        ),
        opened_at=opened_at,
        idle_timeout=idle_timeout,
        hard_deadline=hard_deadline,
        budget=budget or ApplicationChannelBudget(10_000, 20_000, 10),
    )


def _operation(
    operation_id: str,
    *,
    ordinal: int,
    channel_id: str = "channel-1",
    started_at: datetime = _START + timedelta(minutes=1),
    ended_at: datetime = _START + timedelta(minutes=2),
    initiator_bytes: int = 100,
    responder_bytes: int = 200,
    parent_operation_id: str = "",
) -> ApplicationOperationReservation:
    return ApplicationOperationReservation(
        operation_id=operation_id,
        channel_id=channel_id,
        ordinal=ordinal,
        started_at=started_at,
        ended_at=ended_at,
        initiator_bytes=initiator_bytes,
        responder_bytes=responder_bytes,
        parent_operation_id=parent_operation_id,
    )


def _registry(**kwargs: object) -> ApplicationChannelRegistry:
    return ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        **kwargs,
    )


def test_application_identities_are_frozen_normalized_and_contained() -> None:
    """Canonical identities normalize time/protocol while preserving immutable binding truth."""

    naive_start = _START.replace(tzinfo=None)
    identity = _identity(opened_at=naive_start)

    assert identity.protocol == "http"
    assert identity.opened_at.tzinfo is UTC
    assert identity.binding.opened_at.tzinfo is UTC
    with pytest.raises(FrozenInstanceError):
        identity.binding.transport_id = "other"  # type: ignore[misc]
    with pytest.raises(ValueError, match="hard_deadline must be inside"):
        ApplicationChannelIdentity(
            channel_id="outside",
            protocol="http",
            owner_id="owner",
            affinity_digest="digest",
            binding=ApplicationTransportBinding("transport", _START, _START + timedelta(minutes=1)),
            opened_at=_START,
            idle_timeout=timedelta(seconds=1),
            hard_deadline=_START + timedelta(minutes=2),
            budget=ApplicationChannelBudget(1, 1, 1),
        )

    registry = _registry(shard_count=8)
    assert registry.window_start == _START
    assert registry.window_end == _END
    assert registry.shard_count == 8


def test_exact_indexes_resolve_binding_owner_and_bounded_affinity_reuse() -> None:
    """All reusable-channel paths use exact indexes and deterministic bounded candidates."""

    registry = _registry(max_reusable_per_affinity=2)
    first = registry.open_channel(_identity(affinity_digest="AFFINITY-A"))
    second = registry.open_channel(
        _identity(
            "channel-2",
            owner_id="owner-1",
            affinity_digest="affinity-a",
            transport_id="transport-2",
            opened_at=_START + timedelta(seconds=1),
        )
    )

    assert registry.get(first.channel_id) == first
    assert registry.find_open_by_transport("transport-2") == second
    assert registry.count_open_for_owner("owner-1") == 2
    first_page, cursor = registry.open_owner_page("owner-1", limit=1)
    second_page, cursor = registry.open_owner_page("owner-1", limit=1, cursor=cursor)
    assert first_page == (first,)
    assert second_page == (second,)
    assert cursor is None
    assert (
        registry.find_reusable(
            affinity_digest="AFFINITY-A",
            owner_id="owner-1",
            at=_START + timedelta(minutes=1),
        )
        == second
    )
    census = registry.census()
    assert census.lookup_candidates_inspected == 3
    assert census.maximum_affinity_bucket == 2
    assert census.shard_count == 1
    assert census.max_shard_load == 2
    assert census.estimated_bytes > 0
    inspected = census.lookup_candidates_inspected
    assert registry.get("missing-channel") is None
    assert registry.census().lookup_candidates_inspected == inspected

    with pytest.raises(StateError, match="limit is 2"):
        registry.open_channel(
            _identity(
                "channel-3",
                affinity_digest="affinity-a",
                transport_id="transport-3",
                opened_at=_START + timedelta(seconds=2),
            )
        )


def test_canonical_route_tokens_round_trip_through_trusted_combined_open() -> None:
    """Canonical hex routes and a pre-resolved owner shard preserve exact public reads."""

    registry = _registry()
    channel_id = "ssh-channel-0123456789abcdef0123456789abcdef"
    transport_id = "ssh-transport-fedcba9876543210fedcba9876543210"
    identity = _identity(channel_id, owner_id="ssh-owner", transport_id=transport_id)
    reservation = _operation(
        "ssh-operation-00112233445566778899aabbccddeeff",
        ordinal=0,
        channel_id=channel_id,
    )

    opened, close_token = registry.open_channel_with_completed_operation_and_token(
        identity,
        reservation,
        trusted_owner_partition_id=registry.owner_partition_id(identity.owner_id),
    )

    assert registry.get(channel_id) == opened
    assert registry.find_open_by_transport(transport_id) == opened
    assert (
        registry.close_channel_by_token(
            channel_id,
            token=close_token,
            closed_at=reservation.ended_at,
            reason="test",
        )
        is not None
    )


def test_exact_view_cache_is_bounded_accounted_and_invalidated_by_mutation() -> None:
    """Decoded snapshots remain bounded and can never outlive a row mutation."""

    registry = _registry()
    opened = registry.open_channel(_identity())

    assert registry.census().decoded_cache_entries == 0
    assert registry.get(opened.channel_id) == opened
    cached = registry.census()
    assert cached.decoded_cache_entries == 1
    assert cached.decoded_cache_capacity == 256
    assert cached.decoded_cache_estimated_bytes > 0

    registry.reserve_operation(_operation("operation-1", ordinal=0))
    reserved = registry.get(opened.channel_id)
    assert reserved is not None
    assert reserved.active_operations == 1
    assert reserved.reserved_operations == 1
    assert registry.census().decoded_cache_entries == 1

    assert registry.finalize_operation("operation-1") is True
    finalized = registry.get(opened.channel_id)
    assert finalized is not None
    assert finalized.active_operations == 0
    assert finalized.completed_operations == 1

    registry.close_channel(
        opened.channel_id,
        closed_at=_START + timedelta(minutes=3),
        reason="cache-test",
    )
    closed = registry.get(opened.channel_id)
    assert closed is not None
    assert closed.close_reason == "cache-test"
    registry.watermark(_START + timedelta(minutes=4))
    assert registry.get(opened.channel_id) is None
    assert registry.census().decoded_cache_entries == 0

    bounded = _registry()
    for ordinal in range(300):
        channel_id = f"bounded-cache-{ordinal:04d}"
        bounded.open_channel(
            _identity(
                channel_id,
                owner_id="bounded-cache-owner",
                affinity_digest=f"bounded-affinity-{ordinal:04d}",
                transport_id=f"bounded-transport-{ordinal:04d}",
            )
        )
        assert bounded.get(channel_id) is not None
    bounded_census = bounded.census()
    assert bounded_census.decoded_cache_entries == 256
    assert bounded_census.decoded_cache_capacity == 256


def test_combined_open_prepares_identity_hashes_and_payload_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admission reuses one packed identity across affinity validation and insertion."""

    store_type = application_channels_module._PackedChannelStore
    original_owner_key = store_type._owner_key
    original_affinity_key = store_type._affinity_key
    original_pack_identity = store_type._pack_identity
    calls = {"owner": 0, "affinity": 0, "pack": 0}

    def owner_key(cls: type[object], owner_id: str) -> int:
        del cls
        calls["owner"] += 1
        return original_owner_key(owner_id)

    def affinity_key(cls: type[object], owner_id: str, affinity_digest: str) -> int:
        del cls
        calls["affinity"] += 1
        return original_affinity_key(owner_id, affinity_digest)

    def pack_identity(identity: ApplicationChannelIdentity) -> bytes:
        calls["pack"] += 1
        return original_pack_identity(identity)

    monkeypatch.setattr(store_type, "_owner_key", classmethod(owner_key))
    monkeypatch.setattr(store_type, "_affinity_key", classmethod(affinity_key))
    monkeypatch.setattr(store_type, "_pack_identity", staticmethod(pack_identity))

    registry = _registry()
    identity = _identity()
    registry.open_channel_with_completed_operation_and_token(
        identity,
        _operation("operation-1", ordinal=0),
        trusted_owner_partition_id=registry.owner_partition_id(identity.owner_id),
    )

    assert calls == {"owner": 1, "affinity": 1, "pack": 1}


def test_owner_page_cursor_is_bounded_and_explicitly_mutation_fenced() -> None:
    """Page consumers never hold a live unguarded iterator across registry mutation."""

    registry = _registry()
    registry.open_channel(_identity())
    registry.open_channel(
        _identity(
            "channel-2",
            owner_id="owner-1",
            affinity_digest="affinity-b",
            transport_id="transport-2",
        )
    )
    page, cursor = registry.open_owner_page("owner-1", limit=1)
    assert len(page) == 1
    assert cursor is not None

    registry.open_channel(
        _identity(
            "same-owner-channel",
            owner_id="owner-1",
            affinity_digest="affinity-c",
            transport_id="transport-3",
        )
    )
    with pytest.raises(StateError, match="invalidated by mutation"):
        registry.open_owner_page("owner-1", limit=1, cursor=cursor)


def test_one_open_channel_owns_an_immutable_transport_binding() -> None:
    """A transport cannot be rebound while its exact channel remains open."""

    registry = _registry()
    registry.open_channel(_identity())

    with pytest.raises(StateError, match="already owns open channel"):
        registry.open_channel(
            _identity(
                "channel-2",
                affinity_digest="affinity-b",
                transport_id="transport-1",
            )
        )

    future_registry = _registry()
    future_registry.open_channel(_identity(opened_at=_START + timedelta(seconds=1)))
    with pytest.raises(StateError, match="already owns open channel"):
        future_registry.open_channel(
            _identity(
                "earlier-channel",
                affinity_digest="affinity-c",
                transport_id="transport-1",
                opened_at=_START,
            )
        )


def test_close_and_operation_finalization_are_idempotent() -> None:
    """Finalization changes current state once and retains no completed-operation records."""

    registry = _registry()
    registry.open_channel(_identity())
    registry.reserve_operation(_operation("operation-0", ordinal=0))
    with pytest.raises(StateError, match="cannot close with 1 active operations"):
        registry.close_channel(
            "channel-1",
            closed_at=_START + timedelta(minutes=3),
            reason="normal",
        )

    assert registry.finalize_operation("operation-0") is True
    assert registry.finalize_operation("operation-0") is False
    closed = registry.close_channel(
        "channel-1",
        closed_at=_START + timedelta(minutes=3),
        reason="normal",
    )
    assert (
        registry.close_channel(
            "channel-1",
            closed_at=_START + timedelta(minutes=4),
            reason="ignored duplicate",
        )
        == closed
    )
    assert closed.closed_at == _START + timedelta(minutes=3)
    assert registry.census().active_operations == 0

    with pytest.raises(StateError, match="retained channel"):
        registry.open_channel(
            _identity(
                "channel-2",
                affinity_digest="affinity-b",
                transport_id="transport-1",
                opened_at=_START + timedelta(minutes=4),
            )
        )


def test_versioned_close_is_idempotent_and_never_materializes_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A protocol sidecar can close by compact token without rebuilding rich state."""

    registry = _registry()
    registry.open_channel(_identity())
    token = registry.channel_close_token("channel-1")
    assert token is not None

    def fail_materialization(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("fast close reconstructed an application snapshot")

    monkeypatch.setattr(
        application_channels_module._PackedChannelStore,
        "_materialize",
        fail_materialization,
    )
    closed_at = _START + timedelta(minutes=3)
    first = registry.close_channel_by_token(
        "channel-1",
        token=token,
        closed_at=closed_at,
        reason="sidecar deadline",
    )
    second = registry.close_channel_by_token(
        "channel-1",
        token=token,
        closed_at=closed_at + timedelta(seconds=1),
        reason="ignored duplicate",
    )

    assert first.closed_at == closed_at
    assert first.newly_closed is True
    assert second.closed_at == closed_at
    assert second.newly_closed is False
    assert registry.census().open_channels == 0


def test_versioned_close_rejects_active_operations_and_recycled_handle_aba() -> None:
    """Blocker checks are atomic and recycled handles invalidate old sidecar tokens."""

    registry = _registry(closed_grace=timedelta(0), shard_count=1)
    registry.open_channel(_identity())
    token = registry.channel_close_token("channel-1")
    assert token is not None
    registry.reserve_operation(_operation("operation-0", ordinal=0))
    with pytest.raises(StateError, match="cannot close with 1 active operations"):
        registry.close_channel_by_token(
            "channel-1",
            token=token,
            closed_at=_START + timedelta(minutes=3),
            reason="blocked",
        )
    assert registry.get("channel-1") is not None

    assert registry.finalize_operation("operation-0") is True
    closed_at = _START + timedelta(minutes=3)
    registry.close_channel_by_token(
        "channel-1",
        token=token,
        closed_at=closed_at,
        reason="normal",
    )
    registry.watermark(closed_at)
    registry.open_channel(
        _identity(
            "channel-1",
            transport_id="transport-reopened",
            opened_at=closed_at + timedelta(seconds=1),
        )
    )
    with pytest.raises(StateError, match="Stale application channel close token"):
        registry.close_channel_by_token(
            "channel-1",
            token=token,
            closed_at=closed_at + timedelta(seconds=2),
            reason="stale ABA",
        )
    assert registry.get("channel-1") is not None


def test_versioned_close_page_is_bounded_and_preserves_request_order() -> None:
    """Batch close accepts one explicit page and returns deterministic minimal outcomes."""

    registry = _registry(shard_count=2)
    requests: list[ApplicationChannelCloseRequest] = []
    for ordinal in range(3):
        channel_id = f"channel-{ordinal}"
        registry.open_channel(
            _identity(
                channel_id,
                owner_id=f"owner-{ordinal}",
                affinity_digest=f"affinity-{ordinal}",
                transport_id=f"transport-{ordinal}",
            )
        )
        token = registry.channel_close_token(channel_id)
        assert token is not None
        requests.append(
            ApplicationChannelCloseRequest(
                channel_id=channel_id,
                token=token,
                closed_at=_START + timedelta(minutes=3),
                reason="bounded page",
            )
        )

    with pytest.raises(ValueError, match="contains 3 requests; limit is 2"):
        registry.close_channels_by_token(tuple(requests), limit=2)
    assert registry.census().open_channels == 3

    results = registry.close_channels_by_token(tuple(requests), limit=3)
    assert tuple(result.channel_id for result in results) == tuple(
        request.channel_id for request in requests
    )
    assert all(result.newly_closed for result in results)
    assert registry.census().open_channels == 0


def test_completed_operation_fast_path_matches_reserve_then_finalize() -> None:
    """Immediate reconciliation produces the exact same frozen aggregate outcome."""

    legacy = _registry()
    compact = _registry()
    identity = _identity()
    operation = _operation("operation-0", ordinal=0)
    legacy.open_channel(identity)
    compact.open_channel(identity)

    legacy.reserve_operation(operation)
    assert legacy.finalize_operation(operation.operation_id)
    compact_outcome = compact.reserve_completed_operation(operation)

    assert compact_outcome == legacy.get(identity.channel_id)
    assert compact.get(identity.channel_id) == legacy.get(identity.channel_id)
    legacy_census = legacy.census()
    compact_census = compact.census()
    assert (
        (
            compact_census.open_channels,
            compact_census.active_operations,
            compact_census.used_operation_ids,
        )
        == (
            legacy_census.open_channels,
            legacy_census.active_operations,
            legacy_census.used_operation_ids,
        )
        == (1, 0, 1)
    )


def test_initial_completed_operation_fast_path_is_equivalent_and_failure_atomic() -> None:
    """A completed first child opens once, while invalid input publishes no channel."""

    legacy = _registry()
    compact = _registry()
    identity = _identity()
    operation = _operation("operation-0", ordinal=0)
    legacy.open_channel(identity)
    legacy.reserve_operation(operation)
    assert legacy.finalize_operation(operation.operation_id)

    compact_outcome = compact.open_channel_with_completed_operation(identity, operation)
    assert compact_outcome == legacy.get(identity.channel_id)
    assert compact.census().active_operations == 0
    assert compact.census().used_operation_ids == 1

    failed = _registry()
    invalid = _operation(
        "operation-invalid",
        ordinal=0,
        responder_bytes=identity.budget.responder_bytes + 1,
    )
    with pytest.raises(StateError, match="responder byte budget"):
        failed.open_channel_with_completed_operation(identity, invalid)
    assert failed.get(identity.channel_id) is None
    assert failed.find_open_by_transport(identity.binding.transport_id) is None
    census = failed.census()
    assert (census.retained_channels, census.active_operations, census.used_operation_ids) == (
        0,
        0,
        0,
    )


def test_completed_operation_failure_rolls_back_and_contention_commits_once() -> None:
    """Invalid or duplicate immediate children cannot partially consume capacity."""

    registry = _registry()
    registry.open_channel(_identity(budget=ApplicationChannelBudget(100, 200, 1)))
    before = registry.get("channel-1")
    invalid = _operation(
        "invalid",
        ordinal=0,
        initiator_bytes=101,
        responder_bytes=0,
    )
    with pytest.raises(StateError, match="initiator byte budget"):
        registry.reserve_completed_operation(invalid)
    assert registry.get("channel-1") == before
    assert registry.census().used_operation_ids == 0

    operation = _operation(
        "winner",
        ordinal=0,
        initiator_bytes=100,
        responder_bytes=200,
    )

    def compete() -> bool:
        try:
            registry.reserve_completed_operation(operation)
        except StateError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _ordinal: compete(), range(2)))
    assert sorted(outcomes) == [False, True]
    snapshot = registry.get("channel-1")
    assert snapshot is not None
    assert (
        snapshot.reserved_operations,
        snapshot.completed_operations,
        snapshot.active_operations,
    ) == (1, 1, 0)
    assert registry.census().used_operation_ids == 1


def test_completed_operation_marker_expires_with_its_channel_horizon() -> None:
    """Compact outcomes retain no duration-wide operation history after purge."""

    registry = _registry(closed_grace=timedelta(seconds=5))
    registry.open_channel(_identity())
    registry.reserve_completed_operation(_operation("operation-0", ordinal=0))
    registry.close_channel(
        "channel-1",
        closed_at=_START + timedelta(minutes=3),
        reason="completed outcome retention",
    )
    retained = registry.watermark(_START + timedelta(minutes=3, seconds=4))
    assert retained.used_operation_ids == 1
    purged = registry.watermark(_START + timedelta(minutes=3, seconds=5))
    assert purged.retained_channels == 0
    assert purged.used_operation_ids == 0


def test_reservation_is_atomic_and_enforces_directional_budgets() -> None:
    """A failed budget reservation leaves channel counters and active state untouched."""

    registry = _registry()
    registry.open_channel(_identity(budget=ApplicationChannelBudget(150, 250, 2)))
    reserved = registry.reserve_operation(_operation("operation-0", ordinal=0))

    assert reserved.reserved_initiator_bytes == 100
    assert reserved.reserved_responder_bytes == 200
    assert reserved.reserved_operations == 1
    assert reserved.active_operations == 1

    with pytest.raises(StateError, match="initiator byte budget"):
        registry.reserve_operation(
            _operation(
                "operation-1",
                ordinal=1,
                initiator_bytes=51,
                responder_bytes=1,
            )
        )

    unchanged = registry.get("channel-1")
    assert unchanged == reserved
    assert registry.census().active_operations == 1
    assert registry.finalize_operation("operation-0") is True
    assert registry.finalize_operation("operation-0") is False
    finalized = registry.get("channel-1")
    assert finalized is not None
    assert finalized.completed_operations == 1
    assert finalized.active_operations == 0


def test_used_operation_ids_survive_finalization_and_purge_with_channel() -> None:
    """Bounded ID markers prevent retained-channel reuse and expire with its tombstone."""

    registry = _registry(closed_grace=timedelta(seconds=30))
    registry.open_channel(_identity())
    registry.reserve_operation(_operation("operation-0", ordinal=0))
    assert registry.finalize_operation("operation-0") is True
    assert registry.census().used_operation_ids == 1

    with pytest.raises(StateError, match="already used by channel"):
        registry.reserve_operation(_operation("operation-0", ordinal=1))

    registry.reserve_operation(_operation("operation-1", ordinal=1))
    assert registry.finalize_operation("operation-1") is True
    assert registry.census().used_operation_ids == 2
    closed_at = _START + timedelta(minutes=3)
    registry.close_channel("channel-1", closed_at=closed_at, reason="normal")
    assert registry.census().used_operation_ids == 2

    evicted = registry.watermark(closed_at + timedelta(seconds=30))
    assert evicted.retained_channels == 0
    assert evicted.used_operation_ids == 0

    reopened_at = closed_at + timedelta(seconds=31)
    registry.open_channel(_identity(opened_at=reopened_at))
    registry.reserve_operation(
        _operation(
            "operation-0",
            ordinal=0,
            started_at=reopened_at + timedelta(seconds=1),
            ended_at=reopened_at + timedelta(seconds=2),
        )
    )
    assert registry.census().used_operation_ids == 1


def test_child_spans_are_contained_and_finalize_post_order() -> None:
    """Children stay within an active parent and prevent premature parent finalization."""

    registry = _registry()
    registry.open_channel(_identity())
    parent = _operation(
        "parent",
        ordinal=0,
        started_at=_START + timedelta(minutes=1),
        ended_at=_START + timedelta(minutes=5),
    )
    registry.reserve_operation(parent)

    with pytest.raises(StateError, match="not contained"):
        registry.reserve_operation(
            _operation(
                "outside-child",
                ordinal=1,
                started_at=_START + timedelta(minutes=2),
                ended_at=_START + timedelta(minutes=6),
                parent_operation_id="parent",
            )
        )

    registry.reserve_operation(
        _operation(
            "child",
            ordinal=1,
            started_at=_START + timedelta(minutes=2),
            ended_at=_START + timedelta(minutes=4),
            parent_operation_id="parent",
        )
    )
    with pytest.raises(StateError, match="active child"):
        registry.finalize_operation("parent")
    assert registry.finalize_operation("child") is True
    assert registry.finalize_operation("parent") is True
    snapshot = registry.get("channel-1")
    assert snapshot is not None
    assert snapshot.completed_operations == 2
    assert snapshot.active_operations == 0


def test_operation_and_channel_window_fences_reject_retroactive_state() -> None:
    """No channel or child operation can escape or mutate behind the commit watermark."""

    registry = _registry()
    with pytest.raises(StateError, match="hard_deadline must be inside the window"):
        registry.open_channel(
            _identity(
                hard_deadline=_END + timedelta(seconds=1),
            )
        )

    with pytest.raises(StateError, match="outside the application channel window"):
        registry.open_channel(
            _identity(
                "at-exclusive-end",
                transport_id="end-transport",
                opened_at=_END,
                hard_deadline=_END,
            )
        )

    registry.open_channel(_identity(opened_at=_START + timedelta(minutes=10)))
    registry.watermark(_START + timedelta(minutes=11))
    with pytest.raises(StateError, match="before the current watermark"):
        registry.reserve_operation(
            _operation(
                "retroactive",
                ordinal=0,
                started_at=_START + timedelta(minutes=10, seconds=30),
                ended_at=_START + timedelta(minutes=12),
            )
        )


def test_operation_span_may_end_but_not_start_at_exclusive_window_end() -> None:
    """The scenario end is a valid span boundary but never a new occurrence time."""

    registry = _registry()
    registry.open_channel(
        _identity(
            opened_at=_END - timedelta(minutes=10),
            hard_deadline=_END,
        )
    )
    registry.reserve_operation(
        _operation(
            "ends-at-boundary",
            ordinal=0,
            started_at=_END - timedelta(minutes=1),
            ended_at=_END,
        )
    )
    assert registry.finalize_operation("ends-at-boundary") is True

    with pytest.raises(StateError, match="outside the application channel window"):
        registry.reserve_operation(
            _operation(
                "starts-at-boundary",
                ordinal=1,
                started_at=_END,
                ended_at=_END,
            )
        )


def test_idle_expiry_retains_only_a_short_channel_tombstone() -> None:
    """Watermarks close idle state and then evict its compact grace tombstone."""

    registry = _registry(closed_grace=timedelta(seconds=30))
    registry.open_channel(_identity(idle_timeout=timedelta(minutes=5)))
    deadline = _START + timedelta(minutes=5)

    assert (
        registry.find_reusable(
            affinity_digest="affinity-a",
            owner_id="owner-1",
            at=deadline,
        )
        is None
    )
    closed_census = registry.watermark(deadline)
    retained = registry.get("channel-1")
    assert retained is not None
    assert retained.closed_at == deadline
    assert closed_census.open_channels == 0
    assert closed_census.retained_closed_channels == 1

    assert registry.watermark(deadline + timedelta(seconds=29)).retained_channels == 1
    evicted = registry.watermark(deadline + timedelta(seconds=30))
    assert evicted.retained_channels == 0
    assert registry.get("channel-1") is None


def test_closed_channels_intern_exact_reasons_in_compact_handle_codes() -> None:
    """Repeated close reasons retain one string and release their compact references."""

    registry = _registry(closed_grace=timedelta(0))
    first = registry.open_channel_with_token(_identity())
    second = registry.open_channel_with_token(
        _identity(
            "channel-2",
            owner_id="owner-1",
            affinity_digest="affinity-b",
            transport_id="transport-2",
        )
    )
    closed_at = _START + timedelta(minutes=2)
    reason = "shared exact close reason"
    registry.close_channel_by_token(
        first[0].channel_id,
        token=first[1],
        closed_at=closed_at,
        reason=reason,
    )
    registry.close_channel_by_token(
        second[0].channel_id,
        token=second[1],
        closed_at=closed_at,
        reason=reason,
    )

    shard = registry._owner_shard(registry.owner_partition_id("owner-1"), create=False)
    assert shard is not None
    codes = tuple(shard.channels._close_reason_codes)
    assert codes[0] == codes[1] != 0
    assert shard.channels._close_reason_refcounts[codes[0]] == 2
    assert shard.channels._close_reason_routes == {reason: codes[0]}
    assert registry.get("channel-1").close_reason == reason  # type: ignore[union-attr]
    assert registry.get("channel-2").close_reason == reason  # type: ignore[union-attr]

    registry.watermark(closed_at)

    assert shard.channels._close_reason_routes == {}
    assert shard.channels._close_reason_value_bytes == 0
    assert tuple(shard.channels._close_reason_codes) == (0, 0)


def test_failed_watermark_restores_all_due_expiry_state_atomically() -> None:
    """An active due operation leaves every channel and the prior watermark unchanged."""

    registry = _registry(closed_grace=timedelta(minutes=10), shard_count=8)
    registry.open_channel(_identity(idle_timeout=timedelta(minutes=5)))
    registry.open_channel(
        _identity(
            "channel-2",
            owner_id="owner-2",
            affinity_digest="affinity-b",
            transport_id="transport-2",
            idle_timeout=timedelta(minutes=5),
        )
    )
    registry.reserve_operation(
        _operation(
            "blocking-operation",
            channel_id="channel-2",
            ordinal=0,
        )
    )
    due_at = _START + timedelta(minutes=7)

    with pytest.raises(StateError, match="active operations"):
        registry.watermark(due_at)

    first = registry.get("channel-1")
    second = registry.get("channel-2")
    assert first is not None and first.is_open
    assert second is not None and second.is_open
    failed = registry.census()
    assert failed.watermark == _START
    assert failed.open_channels == 2
    assert failed.active_operations == 1
    assert failed.expiry_entries >= 2

    assert registry.finalize_operation("blocking-operation") is True
    succeeded = registry.watermark(due_at)
    assert succeeded.open_channels == 0
    assert succeeded.retained_closed_channels == 2


def test_watermark_streams_due_channels_in_bounded_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hot watermarks never call the all-due compatibility materializer."""

    registry = _registry(closed_grace=timedelta(0))
    page_sizes: list[int] = []
    original_page = PackedHandleExpiryIndex.expire_before_page

    def expire_page(
        index: PackedHandleExpiryIndex,
        cutoff: float,
        *,
        inclusive: bool = False,
        limit: int = 4_096,
    ) -> tuple[tuple[int, float], ...]:
        page = original_page(index, cutoff, inclusive=inclusive, limit=limit)
        page_sizes.append(len(page))
        return page

    def materialize_all_due(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("hot watermark used the all-due compatibility wrapper")

    monkeypatch.setattr(application_channels_module, "_EXPIRY_PAGE_SIZE", 3)
    monkeypatch.setattr(PackedHandleExpiryIndex, "expire_before_page", expire_page)
    monkeypatch.setattr(PackedHandleExpiryIndex, "expire_before", materialize_all_due)
    monkeypatch.setattr(
        application_channels_module._PackedChannelStore,
        "_materialize",
        materialize_all_due,
    )

    for ordinal in range(8):
        registry.open_channel(
            _identity(
                f"channel-{ordinal}",
                affinity_digest=f"affinity-{ordinal}",
                transport_id=f"transport-{ordinal}",
                idle_timeout=timedelta(seconds=1),
            )
        )

    result = registry.watermark(_START + timedelta(seconds=1))

    assert result.retained_channels == 0
    assert page_sizes
    assert max(page_sizes) <= 3
    assert sum(page_sizes) == 16


def test_repeated_windows_plateau_without_completed_operation_history() -> None:
    """Expired channels are dropped wholesale instead of accumulating with duration."""

    registry = _registry(closed_grace=timedelta(seconds=5))
    for ordinal in range(100):
        opened_at = _START + timedelta(minutes=ordinal * 10)
        registry.open_channel(
            _identity(
                f"channel-{ordinal}",
                affinity_digest="shared-affinity",
                transport_id=f"transport-{ordinal}",
                opened_at=opened_at,
                idle_timeout=timedelta(seconds=1),
                hard_deadline=opened_at + timedelta(minutes=1),
            )
        )
        census = registry.watermark(opened_at + timedelta(seconds=6))
        assert census.retained_channels == 0
        assert census.active_operations == 0

    final = registry.census()
    assert final.high_water_mark == 1
    assert final.retained_channels == 0


def test_concurrent_reservations_commit_one_budget_winner() -> None:
    """The commit lock makes competing operation-budget reservations atomic."""

    registry = _registry()
    registry.open_channel(_identity(budget=ApplicationChannelBudget(100, 100, 1)))

    def reserve(operation_id: str) -> bool:
        try:
            registry.reserve_operation(
                _operation(
                    operation_id,
                    ordinal=0,
                    initiator_bytes=100,
                    responder_bytes=100,
                )
            )
        except StateError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(reserve, ("operation-a", "operation-b")))

    assert sorted(results) == [False, True]
    snapshot = registry.get("channel-1")
    assert snapshot is not None
    assert snapshot.reserved_operations == 1
    assert snapshot.active_operations == 1
    assert registry.census().active_operations == 1


def test_exact_lookup_on_disjoint_owner_does_not_take_another_shard_lock() -> None:
    """A blocked owner partition cannot stall an unrelated exact channel lookup."""

    registry = _registry(shard_count=8)
    first_owner = "owner-1"
    first_shard_id = registry._owner_shard_id(first_owner)
    second_owner = next(
        f"owner-{ordinal}"
        for ordinal in range(2, 100)
        if registry._owner_shard_id(f"owner-{ordinal}") != first_shard_id
    )
    registry.open_channel(_identity(owner_id=first_owner))
    registry.open_channel(
        _identity(
            "channel-2",
            owner_id=second_owner,
            affinity_digest="affinity-b",
            transport_id="transport-2",
        )
    )
    first_shard = registry._owner_shard(first_shard_id, create=False)
    assert first_shard is not None

    with first_shard.lock, ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(registry.get, "channel-2")
        snapshot = future.result(timeout=1.0)

    assert snapshot is not None
    assert snapshot.identity.owner_id == second_owner
    census = registry.census()
    assert census.shard_count == 2
    assert census.max_shard_load == 1


def test_disjoint_owner_mutations_progress_concurrently() -> None:
    """A mutation blocked in one owner shard does not serialize another owner."""

    registry = _registry(shard_count=64)
    first_owner = "blocked-owner"
    first_shard_id = registry._owner_shard_id(first_owner)
    first_channel_id = "blocked-channel"
    first_operation_id = "blocked-operation"
    blocked_routes = {
        registry._route_partition_id("channel", first_channel_id),
        registry._route_partition_id("operation", first_operation_id),
    }
    second_owner = next(
        f"parallel-owner-{ordinal}"
        for ordinal in range(100)
        if registry._owner_shard_id(f"parallel-owner-{ordinal}") != first_shard_id
    )
    second_channel_id = next(
        f"parallel-channel-{ordinal}"
        for ordinal in range(100)
        if registry._route_partition_id("channel", f"parallel-channel-{ordinal}")
        not in blocked_routes
    )
    second_operation_id = next(
        f"parallel-operation-{ordinal}"
        for ordinal in range(100)
        if registry._route_partition_id("operation", f"parallel-operation-{ordinal}")
        not in blocked_routes
    )
    registry.open_channel(
        _identity(
            first_channel_id,
            owner_id=first_owner,
            affinity_digest="blocked-affinity",
            transport_id="blocked-transport",
        )
    )
    registry.open_channel(
        _identity(
            second_channel_id,
            owner_id=second_owner,
            affinity_digest="parallel-affinity",
            transport_id="parallel-transport",
        )
    )
    first_shard = registry._owner_shard(first_shard_id, create=False)
    assert first_shard is not None

    executor = ThreadPoolExecutor(max_workers=2)
    first_shard.lock.acquire()
    try:
        blocked = executor.submit(
            registry.reserve_operation,
            _operation(
                first_operation_id,
                channel_id=first_channel_id,
                ordinal=0,
            ),
        )
        with registry._gate._condition:
            assert registry._gate._condition.wait_for(
                lambda: registry._gate._readers >= 1,
                timeout=1.0,
            )
        parallel = executor.submit(
            registry.reserve_operation,
            _operation(
                second_operation_id,
                channel_id=second_channel_id,
                ordinal=0,
            ),
        )
        parallel_snapshot = parallel.result(timeout=1.0)
        assert parallel_snapshot.active_operations == 1
    finally:
        first_shard.lock.release()
    blocked_snapshot = blocked.result(timeout=1.0)
    executor.shutdown(wait=True)

    assert blocked_snapshot.active_operations == 1


def test_prepared_open_cancel_restores_exact_structural_census() -> None:
    """Preparing and cancelling reserves IDs without publishing retained state."""

    registry = _registry()
    before = registry.census()
    identity = _identity()
    reservation = _operation("prepared-operation", ordinal=0)

    token = registry.prepare_open_channel_with_completed_operation(identity, reservation)

    prepared = registry.census()
    assert prepared.prepared_admissions == 1
    assert prepared.claimed_admissions == 0
    assert prepared.reserved_channel_ids == 1
    assert prepared.reserved_transport_ids == 1
    assert prepared.reserved_operation_ids == 1
    assert prepared.retained_channels == 0
    assert registry.get(identity.channel_id) is None
    with pytest.raises(StateError, match="prepared admission"):
        registry.open_channel(identity)

    assert registry.cancel_prepared_admission(token)
    assert not registry.cancel_prepared_admission(token)
    assert registry.census() == before


def test_prepared_open_claim_commits_once_and_returns_close_token() -> None:
    """A claimed open becomes visible only through its one-shot final commit."""

    registry = _registry()
    identity = _identity()
    reservation = _operation("prepared-operation", ordinal=0)
    token = registry.prepare_open_channel_with_completed_operation(identity, reservation)

    with registry.prepared_admission(token) as prepared:
        claimed = registry.census()
        assert claimed.prepared_admissions == 1
        assert claimed.claimed_admissions == 1
        assert registry.get(identity.channel_id) is None
        result = prepared.commit()
        assert result.snapshot.completed_operations == 1
        assert result.close_token is not None
        with pytest.raises(StateError, match="already committed"):
            prepared.commit()

    assert registry.get(identity.channel_id) == result.snapshot
    assert registry.census().prepared_admissions == 0
    assert not registry.cancel_prepared_admission(token)


def test_prepared_open_completed_and_close_is_one_atomic_common_mutation() -> None:
    """A setup-only channel is born closed without any externally visible open state."""

    registry = _registry()
    identity = _identity()
    reservation = _operation("prepared-setup-only", ordinal=0)
    shard_id = registry.owner_partition_id(identity.owner_id)
    token = registry.prepare_open_channel_with_completed_operation_and_close(
        identity,
        reservation,
        closed_at=reservation.ended_at,
        reason="setup-only",
    )

    assert token.kind == "open_completed_close"
    assert registry.get(identity.channel_id) is None
    with registry.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    snapshot = result.snapshot
    assert snapshot.closed_at == reservation.ended_at
    assert snapshot.close_reason == "setup-only"
    assert snapshot.completed_operations == 1
    assert snapshot.reserved_operations == 1
    assert result.close_token is None
    assert result.receipt is not None
    assert result.receipt.kind == "open_completed_close"
    assert registry.authenticates_admission_receipt(result.receipt)
    assert registry.get(identity.channel_id) == snapshot
    census = registry.census()
    assert census.open_channels == 0
    assert census.prepared_admissions == 0
    shard = registry._owner_shard(shard_id, create=False)
    assert shard is not None
    assert shard.mutation_version == 1


def test_prepared_claim_abort_is_census_neutral() -> None:
    """Leaving a claim uncommitted cancels every reservation and allocation."""

    registry = _registry()
    before = registry.census()
    identity = _identity()
    token = registry.prepare_open_channel_with_completed_operation(
        identity,
        _operation("prepared-operation", ordinal=0),
    )

    with registry.prepared_admission(token) as prepared:
        assert not prepared.committed

    assert registry.get(identity.channel_id) is None
    assert registry.census() == before


def test_prepared_completed_operation_defers_budget_until_commit() -> None:
    """Immediate child preparation does not consume budget or a used-ID marker."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    reservation = _operation("prepared-operation", ordinal=0)
    before = registry.census()
    token = registry.prepare_completed_operation(reservation)

    assert registry.get(opened.channel_id) == opened
    prepared = registry.census()
    assert prepared.used_operation_ids == before.used_operation_ids
    assert prepared.active_operations == before.active_operations
    with pytest.raises(StateError, match="prepared admission"):
        registry.reserve_completed_operation(_operation("competing-operation", ordinal=0))

    with registry.prepared_admission(token) as admission:
        committed = admission.commit().snapshot

    assert committed.completed_operations == 1
    assert committed.active_operations == 0
    assert committed.reserved_initiator_bytes == reservation.initiator_bytes
    assert committed.reserved_responder_bytes == reservation.responder_bytes
    assert registry.census().used_operation_ids == before.used_operation_ids + 1


def test_prepared_completed_operation_and_close_is_one_atomic_mutation() -> None:
    """The common claim publishes the completed child and exact close with no open interim."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    reservation = _operation("terminal-operation", ordinal=0)
    shard = registry._owner_shard(
        registry.owner_partition_id(opened.identity.owner_id), create=False
    )
    assert shard is not None
    before_version = shard.mutation_version
    before_used = registry.census().used_operation_ids
    token = registry.prepare_completed_operation_and_close(
        reservation,
        closed_at=reservation.ended_at,
        reason="terminal denied",
    )

    assert token.kind == "completed_operation_close"
    assert registry.get(opened.channel_id) == opened
    assert registry.census().open_channels == 1
    with registry.prepared_admission(token) as admission:
        assert registry.get(opened.channel_id) == opened
        result = admission.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            admission.commit_no_fail()

    assert result.snapshot.completed_operations == 1
    assert result.snapshot.reserved_operations == 1
    assert result.snapshot.closed_at == reservation.ended_at
    assert result.snapshot.close_reason == "terminal denied"
    assert result.close_token is None
    assert registry.get(opened.channel_id) == result.snapshot
    assert registry.census().open_channels == 0
    assert registry.census().used_operation_ids == before_used + 1
    assert shard.mutation_version == before_version + 1
    receipt = result.receipt
    assert receipt is not None
    assert receipt.kind == "completed_operation_close"
    assert receipt.snapshot == result.snapshot
    assert registry.authenticates_admission_receipt(receipt)
    assert not registry.authenticates_admission_receipt(
        replace(receipt, operation_id="retargeted-operation")
    )
    assert not registry.authenticates_admission_token(token)


def test_prepared_completed_operation_and_close_cancel_copy_foreign_and_tamper() -> None:
    """Terminal common capabilities are exact, registry-bound, sealed, and cancel-neutral."""

    registry = _registry()
    foreign = _registry()
    opened = registry.open_channel(_identity())
    reservation = _operation("terminal-operation", ordinal=0)
    before = registry.census()
    token = registry.prepare_completed_operation_and_close(
        reservation,
        closed_at=reservation.ended_at,
        reason="terminal denied",
    )
    copied = replace(token)

    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_admission(copied):
            pytest.fail("copied terminal token unexpectedly entered a claim")
    with pytest.raises(StateError, match="another registry"):
        with foreign.prepared_admission(token):
            pytest.fail("foreign registry unexpectedly claimed a terminal token")
    assert registry.get(opened.channel_id) == opened
    assert registry.cancel_prepared_admission(token)
    cancelled = registry.census()
    assert cancelled.prepared_admissions == 0
    assert cancelled.claimed_admissions == 0
    assert cancelled.used_operation_ids == before.used_operation_ids
    assert cancelled.open_channels == before.open_channels
    assert cancelled.retained_channels == before.retained_channels
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_admission(token):
            pytest.fail("cancelled terminal token unexpectedly entered a claim")

    tampered = registry.prepare_completed_operation_and_close(
        reservation,
        closed_at=reservation.ended_at,
        reason="terminal denied",
    )
    object.__setattr__(tampered, "channel_close_reason", "retargeted close")
    assert not registry.authenticates_admission_token(tampered)
    with pytest.raises(StateError, match="integrity validation failed"):
        with registry.prepared_admission(tampered):
            pytest.fail("tampered terminal token unexpectedly entered a claim")
    assert registry.get(opened.channel_id) == opened
    rejected = registry.census()
    assert rejected.prepared_admissions == 0
    assert rejected.claimed_admissions == 0
    assert rejected.used_operation_ids == before.used_operation_ids
    assert rejected.open_channels == before.open_channels
    assert rejected.retained_channels == before.retained_channels


def test_prepared_completed_operation_and_close_rejects_generation_drift() -> None:
    """An ABA generation change invalidates the frozen common preimage before commit."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    reservation = _operation("terminal-operation", ordinal=0)
    token = registry.prepare_completed_operation_and_close(
        reservation,
        closed_at=reservation.ended_at,
        reason="terminal denied",
    )
    routed = registry._channel_route(opened.channel_id)
    assert routed is not None
    _route, shard_id, channel_handle = routed
    shard = registry._owner_shard(shard_id, create=False)
    assert shard is not None
    with shard.lock:
        retained = shard.channels.delete(channel_handle)
        assert shard.channels.insert(retained) == channel_handle

    with pytest.raises(StateError, match="invalidated"):
        with registry.prepared_admission(token):
            pytest.fail("generation-drifted token unexpectedly entered a claim")
    assert registry.get(opened.channel_id) == opened
    assert registry.census().prepared_admissions == 0


def test_claimed_admission_fences_watermark_until_commit_or_abort() -> None:
    """A watermark cannot invalidate a token already claimed by an outer transaction."""

    registry = _registry()
    identity = _identity(opened_at=_START + timedelta(minutes=1))
    token = registry.prepare_open_channel_with_completed_operation(
        identity,
        _operation(
            "prepared-operation",
            ordinal=0,
            started_at=_START + timedelta(minutes=1),
            ended_at=_START + timedelta(minutes=2),
        ),
    )

    with registry.prepared_admission(token):
        with pytest.raises(StateError, match="claimed admission"):
            registry.watermark(_START + timedelta(minutes=2))

    census = registry.watermark(_START + timedelta(minutes=2))
    assert census.watermark == _START + timedelta(minutes=2)
    assert census.prepared_admissions == 0


def test_prepared_tokens_are_registry_bound_and_stale_after_cancel() -> None:
    """Foreign and consumed tokens cannot claim or commit another registry's state."""

    registry = _registry()
    foreign = _registry()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("prepared-operation", ordinal=0),
    )

    with pytest.raises(StateError, match="another registry"):
        with foreign.prepared_admission(token):
            pytest.fail("foreign token unexpectedly entered a claim")
    assert registry.cancel_prepared_admission(token)
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_admission(token):
            pytest.fail("cancelled token unexpectedly entered a claim")


@pytest.mark.parametrize(
    "target",
    [
        "semantic_payload",
        "nested_semantic_payload",
        "reservation_id",
        "registry_route",
        "owner_shard",
        "channel_handle",
        "channel_generation",
        "expected_snapshot",
        "prepared_snapshot",
        "reserved_channel_ids",
        "reserved_transport_ids",
        "integrity_token",
    ],
)
def test_prepared_token_in_place_tamper_rejects_and_releases_original_capability(
    target: str,
) -> None:
    """Every semantic and routing target is sealed independently from the public object."""

    registry = _registry()
    before = registry.census()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("prepared-operation", ordinal=0),
    )
    prepared_snapshot = token._prepared_snapshot
    assert token.identity is not None and prepared_snapshot is not None
    values: dict[str, tuple[str, object]] = {
        "semantic_payload": (
            "identity",
            replace(token.identity, channel_id="tampered-channel"),
        ),
        "reservation_id": ("_reservation_id", token._reservation_id + 1),
        "registry_route": ("_registry_token", token._registry_token + 1),
        "owner_shard": ("_owner_shard_id", token._owner_shard_id + 1),
        "channel_handle": ("_channel_handle", 0),
        "channel_generation": ("_channel_generation", 1),
        "expected_snapshot": ("_expected_snapshot", prepared_snapshot),
        "prepared_snapshot": ("_prepared_snapshot", None),
        "reserved_channel_ids": ("_reserved_channel_ids", ("tampered-channel",)),
        "reserved_transport_ids": ("_reserved_transport_ids", ("tampered-transport",)),
        "integrity_token": ("_integrity_token", "0" * 64),
    }
    if target == "nested_semantic_payload":
        object.__setattr__(token.reservation, "operation_id", "tampered-operation")
    else:
        field_name, value = values[target]
        object.__setattr__(token, field_name, value)

    assert not registry.authenticates_admission_token(token)
    with pytest.raises(StateError, match="integrity validation failed"):
        with registry.prepared_admission(token):
            pytest.fail("tampered token unexpectedly entered a claim")

    assert registry.census() == before
    assert not registry.cancel_prepared_admission(token)


def test_claimed_token_tamper_rejects_commit_and_cleans_reservations() -> None:
    """Mutation during the no-lock claim body cannot redirect or strand commit state."""

    registry = _registry()
    before = registry.census()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("prepared-operation", ordinal=0),
    )

    with registry.prepared_admission(token) as prepared:
        object.__setattr__(token, "_owner_shard_id", token._owner_shard_id + 1)
        with pytest.raises(StateError, match="integrity validation failed"):
            prepared.commit_no_fail()

    assert registry.census() == before
    assert registry.get("channel-1") is None


def test_prepared_publication_token_and_commit_receipt_are_registry_authenticated() -> None:
    """External coordinators consume public keyed capabilities rather than private fields."""

    registry = _registry()
    foreign = _registry()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("prepared-operation", ordinal=0),
    )

    assert token.publication_token
    assert registry.authenticates_admission_token(token)
    assert not foreign.authenticates_admission_token(token)
    with registry.prepared_admission(token) as prepared:
        assert prepared.result is None
        result = prepared.commit_no_fail()

    receipt = result.receipt
    assert receipt is not None
    assert receipt.publication_token == token.publication_token
    assert receipt.channel_id == result.snapshot.channel_id
    assert receipt.operation_id == token.reservation.operation_id
    assert receipt.snapshot == result.snapshot
    assert receipt.close_token == result.close_token
    assert receipt.receipt_token
    assert registry.authenticates_admission_receipt(receipt)
    assert not foreign.authenticates_admission_receipt(receipt)
    assert not registry.authenticates_admission_token(token)
    assert not registry.authenticates_admission_receipt(
        replace(receipt, channel_id="tampered-channel")
    )


def test_recoverable_prepared_commit_adopts_ambiguous_common_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-mutation exception retains one exact result instead of splitting owners."""

    registry = _registry()
    identity = _identity()
    reservation = _operation("recoverable-operation", ordinal=0)
    token = registry.prepare_open_channel_with_completed_operation(
        identity,
        reservation,
        retain_result_for_recovery=True,
    )
    original = registry._commit_prepared_open_locked
    primary = RuntimeError("lost common commit return")
    failed = False

    def commit_then_fail(prepared_token: ApplicationChannelAdmissionToken) -> object:
        nonlocal failed
        result = original(prepared_token)
        if not failed:
            failed = True
            raise primary
        return result

    monkeypatch.setattr(registry, "_commit_prepared_open_locked", commit_then_fail)
    with registry.prepared_admission(token) as prepared:
        recovered = prepared.commit_no_fail()
        assert prepared.committed
        assert prepared.recovery_status == "committed"
        assert prepared.result is recovered

    assert recovered is not None
    assert registry.get(identity.channel_id) == recovered.snapshot
    assert registry.recover_committed_admission(token) is recovered
    assert registry.recover_committed_admission(replace(token)) is None
    assert recovered.receipt is not None
    assert registry.authenticates_admission_receipt(recovered.receipt)
    assert not registry.authenticates_admission_receipt(replace(recovered.receipt))
    assert not _registry().authenticates_admission_receipt(recovered.receipt)
    census = registry.census()
    assert census.prepared_admissions == 1
    assert census.claimed_admissions == 1
    assert census.recoverable_admission_results == 1
    assert registry.acknowledge_committed_admission(token, recovered)
    assert not registry.authenticates_admission_receipt(recovered.receipt)
    assert registry.recover_committed_admission(token) is None
    assert registry.census().recoverable_admission_results == 0


def test_recoverable_admission_capacity_is_reserved_and_never_silently_evicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unacknowledged exact results consume bounded capacity until explicit acknowledgement."""

    monkeypatch.setattr(application_channels_module, "_MAX_RECOVERABLE_ADMISSION_RESULTS", 1)
    registry = _registry()
    first_token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("recoverable-operation", ordinal=0),
        retain_result_for_recovery=True,
    )
    with registry.prepared_admission(first_token) as prepared:
        first_result = prepared.commit_no_fail()

    with pytest.raises(StateError, match="recovery capacity"):
        registry.prepare_open_channel_with_completed_operation(
            _identity(
                channel_id="channel-2",
                owner_id="owner-2",
                affinity_digest="affinity-b",
                transport_id="transport-2",
            ),
            _operation(
                "recoverable-operation-2",
                ordinal=0,
                channel_id="channel-2",
            ),
            retain_result_for_recovery=True,
        )

    assert registry.recover_committed_admission(first_token) is first_result
    assert registry.acknowledge_committed_admission(first_token, first_result)
    replacement = registry.prepare_open_channel_with_completed_operation(
        _identity(
            channel_id="channel-2",
            owner_id="owner-2",
            affinity_digest="affinity-b",
            transport_id="transport-2",
        ),
        _operation(
            "recoverable-operation-2",
            ordinal=0,
            channel_id="channel-2",
        ),
        retain_result_for_recovery=True,
    )
    assert registry.cancel_prepared_admission(replacement)


def test_prepared_close_only_cancel_copy_foreign_tamper_and_commit_recovery() -> None:
    """Close-only ownership is exact, authenticated, cancel-neutral, and recoverable."""

    registry = _registry()
    foreign = _registry()
    opened = registry.open_channel(_identity())
    before = registry.census()
    closed_at = _START + timedelta(minutes=3)
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=closed_at,
        reason="persistent transport finalized",
    )
    copied = replace(token)

    assert registry.recover_committed_close(token) is None
    with pytest.raises(StateError, match="copied|stale"):
        with registry.prepared_close(copied):
            pytest.fail("copied close token unexpectedly claimed")
    with pytest.raises(StateError, match="foreign"):
        with foreign.prepared_close(token):
            pytest.fail("foreign close token unexpectedly claimed")
    assert registry.cancel_prepared_close(token)
    assert registry.census() == before

    tampered = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=closed_at,
        reason="persistent transport finalized",
    )
    object.__setattr__(tampered, "reason", "retargeted")
    with pytest.raises(StateError, match="integrity"):
        with registry.prepared_close(tampered):
            pytest.fail("tampered close token unexpectedly claimed")
    assert registry.census() == before

    committed_token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=closed_at,
        reason="persistent transport finalized",
    )
    with registry.prepared_close(committed_token) as prepared:
        result = prepared.commit_no_fail()

    assert result.snapshot.closed_at == closed_at
    assert result.close.newly_closed
    assert registry.authenticates_close_admission_receipt(result.receipt)
    assert not registry.authenticates_close_admission_receipt(replace(result.receipt))
    assert registry.recover_committed_close(committed_token) is result
    assert registry.acknowledge_committed_close(committed_token, result)
    assert not registry.authenticates_close_admission_receipt(result.receipt)
    assert registry.recover_committed_close(committed_token) is None


def test_prepared_close_only_recovers_exact_result_after_mutation_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception after the close mutation preserves primary error and exact recovery."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=_START + timedelta(minutes=3),
        reason="persistent transport finalized",
    )
    original = registry._commit_prepared_close_locked
    primary = RuntimeError("lost close return")
    failed = False

    def close_then_fail(trusted: ApplicationChannelPreparedCloseToken) -> object:
        nonlocal failed
        result = original(trusted)
        if not failed:
            failed = True
            raise primary
        return result

    monkeypatch.setattr(registry, "_commit_prepared_close_locked", close_then_fail)
    with registry.prepared_close(token) as prepared:
        recovered = prepared.commit_no_fail()
        assert prepared.committed
        assert prepared.recovery_status == "committed"
        assert prepared.result is recovered

    assert recovered is not None
    assert registry.get(opened.channel_id) == recovered.snapshot
    assert registry.recover_committed_close(token) is recovered
    assert registry.acknowledge_committed_close(token, recovered)


def test_prepared_close_only_rejects_time_before_last_completed_operation() -> None:
    """A close cannot truncate the canonical activity interval it finalizes."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    operation = _operation("completed-before-close", ordinal=0)
    updated = registry.reserve_completed_operation(operation)
    assert updated.last_activity_at == operation.ended_at

    with pytest.raises(StateError, match="before its last activity"):
        registry.prepare_close_channel(
            opened.channel_id,
            closed_at=operation.ended_at - timedelta(microseconds=1),
            reason="too early",
        )


def test_public_reconcile_resolves_indeterminate_commit_to_exact_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained ambiguous claim can later certify success and release its fences."""

    registry = _registry()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("indeterminate-success", ordinal=0),
        retain_result_for_recovery=True,
    )
    primary = RuntimeError("ambiguous common tail")

    def block_recovery(stage: str) -> None:
        if stage == "open-row":
            raise primary

    monkeypatch.setattr(registry, "_prepared_commit_fault", block_recovery)
    with pytest.raises(RuntimeError, match="ambiguous common tail"):
        with registry.prepared_admission(token) as prepared:
            prepared.commit_no_fail()
    held = registry.census()
    assert held.prepared_admissions == 1
    assert held.claimed_admissions == 1
    assert held.recoverable_admission_slots == 1

    monkeypatch.setattr(registry, "_prepared_commit_fault", lambda _stage: None)
    recovery = registry.reconcile_committed_admission(token)
    assert recovery.status == "committed"
    assert recovery.result is not None
    assert registry.census().prepared_admissions == 1
    assert registry.recover_committed_admission(token) is recovery.result
    assert registry.acknowledge_committed_admission(token, recovery.result)


def test_public_reconcile_resolves_indeterminate_commit_to_certified_prestate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later-certified prestate unclaims but preserves exact cancellation ownership."""

    registry = _registry()
    before = registry.census()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("indeterminate-prestate", ordinal=0),
        retain_result_for_recovery=True,
    )
    primary = RuntimeError("failed before common mutation")
    original_prestate = registry._prepared_admission_prestate_is_intact_locked
    suppress_once = True

    def fail_before_mutation(_prepared_token: object) -> object:
        raise primary

    def delay_prestate(capability: _ApplicationChannelAdmissionCapability) -> bool:
        nonlocal suppress_once
        if suppress_once:
            suppress_once = False
            return False
        return original_prestate(capability)

    monkeypatch.setattr(registry, "_commit_prepared_open_locked", fail_before_mutation)
    monkeypatch.setattr(registry, "_prepared_admission_prestate_is_intact_locked", delay_prestate)
    with pytest.raises(RuntimeError, match="failed before common mutation"):
        with registry.prepared_admission(token) as prepared:
            prepared.commit_no_fail()
    assert registry.census().claimed_admissions == 1

    recovery = registry.reconcile_committed_admission(token)
    assert recovery.status == "not_committed"
    assert registry.census().claimed_admissions == 0
    assert registry.cancel_prepared_admission(token)
    assert registry.census() == before


def test_prepared_close_claim_fences_competing_mutation_and_watermark() -> None:
    """A close claim owns its channel until exact commit, cancel, or reconciliation."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    closed_at = _START + timedelta(minutes=3)
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=closed_at,
        reason="prepared close",
    )
    with pytest.raises(StateError, match="prepared admission"):
        registry.close_channel(
            opened.channel_id,
            closed_at=closed_at,
            reason="competing close",
        )

    with registry.prepared_close(token):
        with pytest.raises(StateError, match="claimed admission"):
            registry.watermark(closed_at + timedelta(microseconds=1))

    assert registry.census().prepared_close_tokens == 0
    assert registry.census().prepared_close_capabilities == 0
    assert registry.census().recoverable_admission_slots == 0


@pytest.mark.parametrize(
    "fault_stage",
    (
        "open-row",
        "open-operation-marker",
        "open-channel-route",
        "open-transport-route",
        "open-expiry",
        "open-accounting-installed",
        "open-accounting",
    ),
)
def test_recoverable_open_converges_at_every_primitive_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Every fresh-open primitive fault converges once with an adoption fence."""

    registry = _registry()
    identity = _identity()
    operation = _operation("faulted-open", ordinal=0)
    token = registry.prepare_open_channel_with_completed_operation(
        identity,
        operation,
        retain_result_for_recovery=True,
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    monkeypatch.setattr(registry, "_prepared_commit_fault", fail_once)
    with registry.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert registry.get(identity.channel_id) == result.snapshot
    assert result.snapshot.completed_operations == 1
    assert result.snapshot.reserved_initiator_bytes == operation.initiator_bytes
    assert result.snapshot.reserved_responder_bytes == operation.responder_bytes
    assert result.receipt is not None
    assert registry.authenticates_admission_receipt(result.receipt)
    census = registry.census()
    assert census.retained_channels == 1
    assert census.open_channels == 1
    assert census.used_operation_ids == 1
    assert census.route_entries == 2
    assert census.prepared_admissions == 1
    assert census.claimed_admissions == 1
    assert census.prepared_commit_journals == 1
    assert census.recoverable_admission_results == 1
    assert census.recoverable_admission_receipts == 1

    shard = registry._owner_shard(registry.owner_partition_id(identity.owner_id), create=False)
    assert shard is not None
    with shard.lock:
        assert shard.mutation_version == 1
        assert shard.open_channels == 1
        assert shard._accounting.prepared_commit_ids == frozenset({token._reservation_id})
        assert result.close_token is not None
        _shard_id, handle = registry._unpack_channel_locator(result.close_token.locator)
        assert (
            shard.active_expiry.get(handle)
            == registry._effective_deadline(result.snapshot).timestamp()
        )
        assert shard.closed_expiry.get(handle) is None

    with pytest.raises(StateError, match="prepared admission"):
        registry.reserve_completed_operation(_operation("blocked-before-ack", ordinal=1))
    with pytest.raises(StateError, match="claimed admission"):
        registry.watermark(operation.started_at + timedelta(microseconds=1))

    assert registry.acknowledge_committed_admission(token, result)
    terminal = registry.census()
    assert terminal.prepared_admissions == 0
    assert terminal.claimed_admissions == 0
    assert terminal.prepared_commit_journals == 0
    assert terminal.recoverable_admission_results == 0
    assert terminal.recoverable_admission_receipts == 0
    with shard.lock:
        assert not shard._accounting.prepared_commit_ids


@pytest.mark.parametrize(
    "fault_stage",
    (
        "operation-marker",
        "operation-row",
        "operation-expiry",
        "operation-accounting-installed",
        "operation-accounting",
    ),
)
def test_recoverable_operation_converges_at_every_primitive_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Every reuse-operation primitive fault applies bytes and counters exactly once."""

    registry = _registry()
    identity = _identity()
    registry.open_channel(identity)
    operation = _operation("faulted-reuse", ordinal=0)
    token = registry.prepare_completed_operation(
        operation,
        retain_result_for_recovery=True,
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    monkeypatch.setattr(registry, "_prepared_commit_fault", fail_once)
    with registry.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert result.snapshot.completed_operations == 1
    assert result.snapshot.reserved_initiator_bytes == operation.initiator_bytes
    assert result.snapshot.reserved_responder_bytes == operation.responder_bytes
    assert registry.get(identity.channel_id) == result.snapshot
    census = registry.census()
    assert census.retained_channels == 1
    assert census.open_channels == 1
    assert census.used_operation_ids == 1
    assert census.prepared_commit_journals == 1
    assert census.recoverable_admission_results == 1

    shard = registry._owner_shard(registry.owner_partition_id(identity.owner_id), create=False)
    assert shard is not None
    with shard.lock:
        assert shard.mutation_version == 2
        assert shard._accounting.prepared_commit_ids == frozenset({token._reservation_id})
        handle = token._channel_handle
        assert handle is not None
        assert (
            shard.active_expiry.get(handle)
            == registry._effective_deadline(result.snapshot).timestamp()
        )
        assert shard.closed_expiry.get(handle) is None

    with pytest.raises(StateError, match="prepared admission"):
        registry.close_channel(
            identity.channel_id,
            closed_at=_START + timedelta(minutes=3),
            reason="blocked before adoption",
        )
    assert registry.acknowledge_committed_admission(token, result)
    terminal = registry.census()
    assert terminal.prepared_admissions == 0
    assert terminal.prepared_commit_journals == 0
    assert terminal.recoverable_admission_results == 0
    with shard.lock:
        assert not shard._accounting.prepared_commit_ids


@pytest.mark.parametrize(
    "fault_stage",
    (
        "close-row",
        "close-expiry",
        "close-accounting-installed",
        "close-accounting",
    ),
)
def test_recoverable_close_converges_at_every_primitive_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Every close primitive fault converges before the channel can be evicted."""

    registry = _registry()
    identity = _identity()
    opened = registry.open_channel(identity)
    closed_at = _START + timedelta(minutes=3)
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=closed_at,
        reason="persistent transport finalized",
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    monkeypatch.setattr(registry, "_prepared_commit_fault", fail_once)
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert result.snapshot.closed_at == closed_at
    assert registry.get(identity.channel_id) == result.snapshot
    assert registry.authenticates_close_admission_receipt(result.receipt)
    census = registry.census()
    assert census.retained_channels == 1
    assert census.open_channels == 0
    assert census.prepared_admissions == 1
    assert census.claimed_admissions == 1
    assert census.prepared_close_commit_journals == 1
    assert census.recoverable_close_results == 1
    assert census.recoverable_close_receipts == 1

    shard = registry._owner_shard(registry.owner_partition_id(identity.owner_id), create=False)
    assert shard is not None
    with shard.lock:
        assert shard.mutation_version == 2
        assert shard.open_channels == 0
        assert shard._accounting.prepared_commit_ids == frozenset({token._reservation_id})
        assert shard.active_expiry.get(token._channel_handle) is None
        assert shard.operation_blocker_expiry.get(token._channel_handle) is None
        assert (
            shard.closed_expiry.get(token._channel_handle)
            == (closed_at + registry._closed_grace).timestamp()
        )

    with pytest.raises(StateError, match="claimed admission"):
        registry.watermark(closed_at + registry._closed_grace)
    assert registry.acknowledge_committed_close(token, result)
    terminal = registry.census()
    assert terminal.prepared_admissions == 0
    assert terminal.prepared_close_commit_journals == 0
    assert terminal.recoverable_close_results == 0
    assert terminal.recoverable_close_receipts == 0
    with shard.lock:
        assert not shard._accounting.prepared_commit_ids
    registry.watermark(closed_at + registry._closed_grace)
    assert registry.get(identity.channel_id) is None


@pytest.mark.parametrize("fault_stage", ("admission-receipt", "admission-result"))
def test_recoverable_admission_converges_at_every_retention_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Receipt-first retention recovers before or after its terminal result marker."""

    registry = _registry()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("retention-fault", ordinal=0),
        retain_result_for_recovery=True,
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    monkeypatch.setattr(registry, "_prepared_retention_fault", fail_once)
    with registry.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert registry.recover_committed_admission(token) is result
    assert result.receipt is not None
    assert registry.authenticates_admission_receipt(result.receipt)
    census = registry.census()
    assert census.recoverable_admission_results == 1
    assert census.recoverable_admission_receipts == 1
    assert registry.acknowledge_committed_admission(token, result)


@pytest.mark.parametrize("fault_stage", ("close-receipt", "close-result"))
def test_recoverable_close_converges_at_every_retention_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Close receipt retention recovers on either side of its terminal marker."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=_START + timedelta(minutes=3),
        reason="retention fault",
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    monkeypatch.setattr(registry, "_prepared_retention_fault", fail_once)
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert registry.recover_committed_close(token) is result
    assert registry.authenticates_close_admission_receipt(result.receipt)
    assert registry.census().recoverable_close_results == 1
    assert registry.acknowledge_committed_close(token, result)


@pytest.mark.parametrize(
    "fault_stage",
    (
        "admission-ack-record",
        "admission-secondary-indexes",
        "admission-accounting-marker",
        "admission-primary-token",
        "admission-capability",
        "admission-ack-slot",
        "admission-ack-result",
        "admission-ack-receipt",
        "admission-ack-release-marker",
    ),
)
def test_recoverable_admission_ack_retries_every_release_tail_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """An interrupted ack retains exact recovery and a global adoption fence."""

    registry = _registry()
    token = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("ack-fault", ordinal=0),
        retain_result_for_recovery=True,
    )
    with registry.prepared_admission(token) as prepared:
        result = prepared.commit_no_fail()
    assert result.receipt is not None
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    if fault_stage == "admission-ack-record":
        monkeypatch.setattr(registry, "_prepared_retention_fault", fail_once)
    else:
        monkeypatch.setattr(registry, "_prepared_release_fault", fail_once)
    with pytest.raises(RuntimeError, match="injected"):
        registry.acknowledge_committed_admission(token, result)

    assert faulted
    assert registry.recover_committed_admission(token) is result
    assert registry.authenticates_admission_receipt(result.receipt)
    held = registry.census()
    assert held.acknowledging_admission_results == 1
    assert held.recoverable_admission_results == 1
    with pytest.raises(StateError, match="incomplete prepared release"):
        registry.reserve_completed_operation(_operation("blocked-by-ack", ordinal=1))
    with pytest.raises(StateError, match="incomplete prepared release"):
        registry.watermark(_START + timedelta(minutes=1))

    monkeypatch.setattr(registry, "_prepared_retention_fault", lambda _stage: None)
    monkeypatch.setattr(registry, "_prepared_release_fault", lambda _stage: None)
    assert registry.acknowledge_committed_admission(token, result)
    terminal = registry.census()
    assert terminal.releasing_admissions == 0
    assert terminal.acknowledging_admission_results == 0
    assert terminal.recoverable_admission_results == 0
    assert terminal.recoverable_admission_receipts == 0


@pytest.mark.parametrize(
    "fault_stage",
    (
        "close-ack-record",
        "close-secondary-indexes",
        "close-accounting-marker",
        "close-primary-token",
        "close-capability",
        "close-ack-slot",
        "close-ack-result",
        "close-ack-receipt",
        "close-ack-release-marker",
    ),
)
def test_recoverable_close_ack_retries_every_release_tail_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """An interrupted close ack stays exact, authenticated, and globally fenced."""

    registry = _registry()
    opened = registry.open_channel(_identity())
    token = registry.prepare_close_channel(
        opened.channel_id,
        closed_at=_START + timedelta(minutes=3),
        reason="ack fault",
    )
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError(f"injected {stage}")

    if fault_stage == "close-ack-record":
        monkeypatch.setattr(registry, "_prepared_retention_fault", fail_once)
    else:
        monkeypatch.setattr(registry, "_prepared_release_fault", fail_once)
    with pytest.raises(RuntimeError, match="injected"):
        registry.acknowledge_committed_close(token, result)

    assert faulted
    assert registry.recover_committed_close(token) is result
    assert registry.authenticates_close_admission_receipt(result.receipt)
    held = registry.census()
    assert held.acknowledging_close_results == 1
    assert held.recoverable_close_results == 1
    with pytest.raises(StateError, match="incomplete prepared release"):
        registry.watermark(_START + timedelta(minutes=4))

    monkeypatch.setattr(registry, "_prepared_retention_fault", lambda _stage: None)
    monkeypatch.setattr(registry, "_prepared_release_fault", lambda _stage: None)
    assert registry.acknowledge_committed_close(token, result)
    terminal = registry.census()
    assert terminal.releasing_admissions == 0
    assert terminal.acknowledging_close_results == 0
    assert terminal.recoverable_close_results == 0
    assert terminal.recoverable_close_receipts == 0


def test_affinity_release_retry_does_not_decrement_a_sibling_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retrying a partial release preserves another same-affinity preparation."""

    registry = _registry(max_reusable_per_affinity=3)
    first = registry.prepare_open_channel_with_completed_operation(
        _identity(),
        _operation("first-affinity", ordinal=0),
        retain_result_for_recovery=True,
    )
    second = registry.prepare_open_channel_with_completed_operation(
        _identity(channel_id="channel-2", transport_id="transport-2"),
        _operation("second-affinity", ordinal=0, channel_id="channel-2"),
        retain_result_for_recovery=True,
    )
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == "admission-secondary-indexes" and not faulted:
            faulted = True
            raise RuntimeError("injected affinity release")

    monkeypatch.setattr(registry, "_prepared_release_fault", fail_once)
    with pytest.raises(RuntimeError, match="affinity release"):
        registry.cancel_prepared_admission(first)
    affinity_key = ("owner-1", "affinity-a")
    assert registry._prepared_affinity_reservations[affinity_key] == {second._reservation_id}
    assert registry.census().releasing_admissions == 1
    with pytest.raises(StateError, match="incomplete prepared release"):
        registry.prepare_open_channel_with_completed_operation(
            _identity(channel_id="channel-3", transport_id="transport-3"),
            _operation("blocked-affinity", ordinal=0, channel_id="channel-3"),
            retain_result_for_recovery=True,
        )

    assert registry.cancel_prepared_admission(first)
    assert registry._prepared_affinity_reservations[affinity_key] == {second._reservation_id}
    assert registry.cancel_prepared_admission(second)
    terminal = registry.census()
    assert terminal.releasing_admissions == 0
    assert terminal.prepared_admissions == 0


def test_recoverable_admission_churn_releases_every_transient_owner() -> None:
    """Long-running prepare/cancel and commit/ack churn has no transient plateau growth."""

    registry = _registry()
    identity = _identity(budget=ApplicationChannelBudget(1_000_000, 1_000_000, 3_000))
    before = registry.census()
    for _index in range(2_000):
        token = registry.prepare_open_channel_with_completed_operation(
            identity,
            _operation("cancelled-recovery", ordinal=0),
            retain_result_for_recovery=True,
        )
        assert registry.cancel_prepared_admission(token)
    assert registry.census() == before

    registry.open_channel(identity)
    for index in range(1_000):
        reservation = _operation(
            f"recoverable-churn-{index}",
            ordinal=index,
            initiator_bytes=1,
            responder_bytes=1,
        )
        token = registry.prepare_completed_operation(
            reservation,
            retain_result_for_recovery=True,
        )
        with registry.prepared_admission(token) as prepared:
            result = prepared.commit_no_fail()
        assert registry.acknowledge_committed_admission(token, result)

    terminal = registry.census()
    assert terminal.prepared_admission_tokens == 0
    assert terminal.prepared_admission_capabilities == 0
    assert terminal.prepared_close_tokens == 0
    assert terminal.prepared_close_capabilities == 0
    assert terminal.prepared_commit_journals == 0
    assert terminal.prepared_close_commit_journals == 0
    assert terminal.releasing_admissions == 0
    assert terminal.acknowledging_admission_results == 0
    assert terminal.acknowledging_close_results == 0
    assert terminal.recoverable_admission_slots == 0
    assert terminal.recoverable_admission_results == 0
    assert terminal.recoverable_admission_receipts == 0
    assert terminal.recoverable_close_results == 0
    assert terminal.recoverable_close_receipts == 0


def test_consumed_token_cannot_alias_a_reprepared_capability() -> None:
    """A stale token cannot claim a later reservation for the same semantic IDs."""

    registry = _registry()
    identity = _identity()
    reservation = _operation("prepared-operation", ordinal=0)
    stale = registry.prepare_open_channel_with_completed_operation(identity, reservation)
    assert registry.cancel_prepared_admission(stale)
    current = registry.prepare_open_channel_with_completed_operation(identity, reservation)

    assert not registry.authenticates_admission_token(stale)
    assert registry.authenticates_admission_token(current)
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_admission(stale):
            pytest.fail("stale token unexpectedly aliased a later capability")
    assert registry.cancel_prepared_admission(current)


def _partition_fixture(
    registry: ApplicationChannelRegistry,
    nonce: int,
) -> tuple[tuple[str, str, str, str], ...]:
    """Build one semantic fixture per stable owner and exact-route partition."""

    owners: dict[int, str] = {}
    channel_ids: dict[int, str] = {}
    transport_ids: dict[int, str] = {}
    operation_ids: dict[int, str] = {}
    ordinal = 0
    while any(
        len(values) < registry.shard_count
        for values in (owners, channel_ids, transport_ids, operation_ids)
    ):
        candidate = f"plateau-{nonce}-{ordinal}"
        owners.setdefault(registry.owner_partition_id(candidate), candidate)
        channel_ids.setdefault(
            registry._route_partition_id("channel", f"channel-{candidate}"),
            f"channel-{candidate}",
        )
        transport_ids.setdefault(
            registry._route_partition_id("transport", f"transport-{candidate}"),
            f"transport-{candidate}",
        )
        operation_ids.setdefault(
            registry._route_partition_id("operation", f"operation-{candidate}"),
            f"operation-{candidate}",
        )
        ordinal += 1
    return tuple(
        (
            owners[partition],
            channel_ids[partition],
            transport_ids[partition],
            operation_ids[partition],
        )
        for partition in range(registry.shard_count)
    )


def _duration_plateau_census(days: int):
    """Run a dense fixed-rate duration workload through only public mutations."""

    end = _START + timedelta(days=days + 1)
    registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=end,
        closed_grace=timedelta(0),
    )
    for day in range(days):
        base = _START + timedelta(days=day, minutes=1)
        fixtures = _partition_fixture(registry, day)
        for partition, (owner, channel_stub, transport_stub, operation_stub) in enumerate(fixtures):
            opened_at = base + timedelta(microseconds=partition)
            channel_id = channel_stub
            transport_id = transport_stub
            operation_id = operation_stub
            registry.open_channel(
                _identity(
                    channel_id,
                    owner_id=owner,
                    affinity_digest=f"affinity-{partition}",
                    transport_id=transport_id,
                    opened_at=opened_at,
                    idle_timeout=timedelta(minutes=3),
                    hard_deadline=base + timedelta(minutes=4),
                )
            )
            registry.reserve_operation(
                _operation(
                    operation_id,
                    channel_id=channel_id,
                    ordinal=0,
                    started_at=base + timedelta(seconds=10),
                    ended_at=base + timedelta(seconds=20),
                )
            )
            assert registry.finalize_operation(operation_id)
            registry.close_channel(
                channel_id,
                closed_at=base + timedelta(minutes=1),
                reason="plateau probe",
            )
        census = registry.watermark(base + timedelta(minutes=2))
        assert census.retained_channels == 0
        assert census.route_entries == 0
    return registry.census()


def test_route_and_primary_maps_plateau_across_24h_7d_and_30d() -> None:
    """Deleted exact routes retain bounded map capacity, not duration-wide keys."""

    day = _duration_plateau_census(1)
    week = _duration_plateau_census(7)
    month = _duration_plateau_census(30)

    for census in (day, week, month):
        assert census.route_entries == 0
        assert census.route_compaction_pending == 0
        assert census.store_primary_compaction_pending == 0
        assert census.route_map_amplification <= 1.0
        assert census.route_compaction_rotations > 0
        assert census.store_primary_compaction_rotations > 0
    assert week.route_map_bytes == day.route_map_bytes
    assert month.route_map_bytes == week.route_map_bytes
    assert week.store_primary_map_bytes == day.store_primary_map_bytes
    assert month.store_primary_map_bytes == week.store_primary_map_bytes
    assert month.estimated_bytes <= week.estimated_bytes * 1.1


def test_sparse_empty_route_partitions_are_reclaimed_at_watermarks() -> None:
    """Novel daily semantic IDs do not retain empty lazy route partitions."""

    registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_START + timedelta(days=31),
        closed_grace=timedelta(0),
    )
    snapshots = {}
    for day in range(30):
        opened_at = _START + timedelta(days=day, minutes=1)
        channel_id = f"sparse-channel-{day}"
        registry.open_channel(
            _identity(
                channel_id,
                owner_id="sparse-owner",
                affinity_digest=f"sparse-affinity-{day}",
                transport_id=f"sparse-transport-{day}",
                opened_at=opened_at,
                idle_timeout=timedelta(minutes=5),
            )
        )
        registry.close_channel(
            channel_id,
            closed_at=opened_at + timedelta(minutes=1),
            reason="sparse plateau probe",
        )
        census = registry.watermark(opened_at + timedelta(minutes=2))
        assert registry.get(channel_id) is None
        assert census.retained_channels == 0
        assert census.route_entries == 0
        assert census.route_map_bytes == 0
        assert census.estimated_route_index_bytes == 0
        if day + 1 in {7, 30}:
            snapshots[day + 1] = census

    assert snapshots[30].estimated_index_bytes <= snapshots[7].estimated_index_bytes
    assert snapshots[30].estimated_bytes <= snapshots[7].estimated_bytes * 1.1


def test_route_compaction_does_not_hold_the_global_mutation_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked map rotation cannot stop a disjoint owner from opening."""

    registry = _registry(closed_grace=timedelta(0), shard_count=16)
    first_owner = "compaction-owner"
    first_channel = "compaction-channel"
    first_transport = "compaction-transport"
    registry.open_channel(
        _identity(
            first_channel,
            owner_id=first_owner,
            transport_id=first_transport,
            idle_timeout=timedelta(seconds=1),
        )
    )
    target_partition = registry._route_partition_id("channel", first_channel)
    entered = Event()
    release = Event()
    original = _RoutePartition.compact_primary

    def blocking_compaction(partition: _RoutePartition, max_work: int) -> int:
        if partition.partition_id == target_partition and not entered.is_set():
            entered.set()
            assert release.wait(timeout=2.0)
        return original(partition, max_work)

    monkeypatch.setattr(_RoutePartition, "compact_primary", blocking_compaction)
    cutoff = _START + timedelta(seconds=2)
    second_owner = next(
        f"disjoint-owner-{ordinal}"
        for ordinal in range(100)
        if registry.owner_partition_id(f"disjoint-owner-{ordinal}")
        != registry.owner_partition_id(first_owner)
    )
    second_channel = next(
        f"disjoint-channel-{ordinal}"
        for ordinal in range(100)
        if registry._route_partition_id("channel", f"disjoint-channel-{ordinal}")
        != target_partition
    )
    second_transport = next(
        f"disjoint-transport-{ordinal}"
        for ordinal in range(100)
        if registry._route_partition_id("transport", f"disjoint-transport-{ordinal}")
        != target_partition
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        watermark = executor.submit(registry.watermark, cutoff)
        assert entered.wait(timeout=1.0)
        try:
            opened = executor.submit(
                registry.open_channel,
                _identity(
                    second_channel,
                    owner_id=second_owner,
                    affinity_digest="disjoint-affinity",
                    transport_id=second_transport,
                    opened_at=cutoff,
                    idle_timeout=timedelta(minutes=1),
                ),
            )
            assert opened.result(timeout=1.0).channel_id == second_channel
        finally:
            release.set()
        assert watermark.result(timeout=2.0).watermark == cutoff
