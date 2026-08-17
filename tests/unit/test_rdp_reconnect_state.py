# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused state, scale, and retention tests for reconnectable RDP sessions."""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationTransportBinding,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpRetentionLease,
    RdpSessionAffinity,
    RdpSessionState,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelCloseToken,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)


def _manager(
    *,
    window_end: datetime | None = None,
    closed_grace: timedelta = timedelta(seconds=5),
    post_logout_grace: timedelta = timedelta(seconds=5),
) -> tuple[RdpReconnectStateManager, ApplicationChannelRegistry]:
    end = window_end or _START + timedelta(days=1)
    application = ApplicationChannelRegistry(
        window_start=_START,
        window_end=end,
        closed_grace=closed_grace,
    )
    manager = RdpReconnectStateManager(
        application_registry=application,
        window_start=_START,
        window_end=end,
        post_logout_grace=post_logout_grace,
        max_retention_extension=timedelta(hours=2),
    )
    return manager, application


def _affinity(index: int) -> RdpSessionAffinity:
    return RdpSessionAffinity(
        source_host=f"CLIENT-{index:06d}.example.test",
        source_address=f"10.20.{index // 250}.{index % 250 + 1}",
        target_host=f"RDS-{index % 17:02d}.example.test",
        target_address=f"10.30.0.{index % 17 + 1}",
        principal=f"EXAMPLE\\user{index:06d}",
        logon_id=f"0x{0x100000 + index:X}",
        session_id=index + 1,
    )


def _identity(
    index: int,
    *,
    started_at: datetime = _START,
    idle_timeout: timedelta = timedelta(minutes=20),
    reconnect_timeout: timedelta = timedelta(minutes=10),
    hard_deadline: datetime | None = None,
    budget: ApplicationChannelBudget | None = None,
) -> RdpLogicalSessionIdentity:
    return RdpLogicalSessionIdentity(
        logical_session_id=f"rdp-logical-{index:08d}",
        affinity=_affinity(index),
        started_at=started_at,
        idle_timeout=idle_timeout,
        reconnect_timeout=reconnect_timeout,
        hard_deadline=hard_deadline or started_at + timedelta(hours=1),
        budget=budget or ApplicationChannelBudget(20_000, 40_000, 20),
    )


def _transport(
    index: int,
    generation: int,
    *,
    connected_at: datetime,
    closes_at: datetime | None = None,
    budget: ApplicationChannelBudget | None = None,
) -> RdpTransportPlan:
    return RdpTransportPlan(
        channel_id=f"rdp-channel-{index:08d}-{generation}",
        binding=ApplicationTransportBinding(
            transport_id=f"rdp-transport-{index:08d}-{generation}",
            opened_at=connected_at - timedelta(milliseconds=100),
            closes_at=closes_at or connected_at + timedelta(minutes=30),
        ),
        connected_at=connected_at,
        budget=budget or ApplicationChannelBudget(10_000, 20_000, 10),
    )


def test_multiple_reconnects_preserve_logical_identity_and_transport_immutability() -> None:
    """Reconnect increments generation and never rewrites a closed binding."""

    manager, application = _manager()
    identity = _identity(1)
    first_plan = _transport(1, 0, connected_at=_START)
    opened = manager.open_session(identity, first_plan)
    assert manager.open_session(identity, first_plan) == opened
    assert opened.state is RdpSessionState.CONNECTED
    assert opened.generation.ordinal == 0
    assert opened.token_active and opened.session_active

    admission = manager.reserve_operation(
        identity.logical_session_id,
        started_at=_START + timedelta(seconds=1),
        ended_at=_START + timedelta(seconds=2),
        initiator_bytes=200,
        responder_bytes=500,
    )
    assert manager.finalize_operation(
        identity.logical_session_id,
        admission.reservation.operation_id,
    )
    assert not manager.finalize_operation(
        identity.logical_session_id,
        admission.reservation.operation_id,
    )
    manager.record_member_admission(
        identity.logical_session_id,
        admitted_at=_START + timedelta(seconds=2),
    )
    first_disconnected = manager.disconnect(
        identity.logical_session_id,
        channel_id=first_plan.channel_id,
        disconnected_at=_START + timedelta(minutes=2),
    )
    assert first_disconnected.state is RdpSessionState.DISCONNECTED
    assert (
        manager.disconnect(
            identity.logical_session_id,
            channel_id=first_plan.channel_id,
            disconnected_at=_START + timedelta(minutes=2),
        )
        == first_disconnected
    )
    assert first_disconnected.token_active and first_disconnected.session_active
    first_channel = application.get(first_plan.channel_id)
    assert first_channel is not None
    assert first_channel.identity.binding == first_plan.binding
    assert first_channel.closed_at == _START + timedelta(minutes=2)

    manager.record_dependent_admission(
        identity.logical_session_id,
        admitted_at=_START + timedelta(minutes=3),
    )
    second_plan = _transport(1, 1, connected_at=_START + timedelta(minutes=4))
    second = manager.reconnect(
        identity.logical_session_id,
        affinity=identity.affinity,
        transport=second_plan,
        expected_generation=1,
    )
    assert (
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=second_plan,
            expected_generation=1,
        )
        == second
    )
    assert second.identity == identity
    assert second.generation.ordinal == 1
    manager.disconnect(
        identity.logical_session_id,
        channel_id=second_plan.channel_id,
        disconnected_at=_START + timedelta(minutes=5),
    )
    third_plan = _transport(1, 2, connected_at=_START + timedelta(minutes=6))
    third = manager.reconnect(
        identity.logical_session_id,
        affinity=identity.affinity,
        transport=third_plan,
        expected_generation=2,
    )
    assert third.generation.ordinal == 2
    assert application.get(first_plan.channel_id) == first_channel

    logged_out = manager.logout(
        identity.logical_session_id,
        logged_out_at=_START + timedelta(minutes=7),
    )
    assert logged_out.state is RdpSessionState.LOGGED_OUT
    assert not logged_out.token_active and not logged_out.session_active
    assert (
        manager.logout(
            identity.logical_session_id,
            logged_out_at=_START + timedelta(minutes=7),
        )
        == logged_out
    )
    with pytest.raises(StateError, match="cannot admit"):
        manager.record_member_admission(
            identity.logical_session_id,
            admitted_at=_START + timedelta(minutes=8),
        )
    with pytest.raises(StateError, match="cannot admit"):
        manager.record_dependent_admission(
            identity.logical_session_id,
            admitted_at=_START + timedelta(minutes=8),
        )


def test_invalid_transition_order_generation_affinity_and_boundaries() -> None:
    """Every transition is fenced by state, generation, affinity, and time."""

    manager, _application = _manager()
    identity = _identity(
        2,
        idle_timeout=timedelta(minutes=5),
        reconnect_timeout=timedelta(minutes=3),
    )
    first = _transport(2, 0, connected_at=_START, closes_at=_START + timedelta(minutes=20))
    manager.open_session(identity, first)
    with pytest.raises(StateError, match="must disconnect"):
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=_transport(2, 1, connected_at=_START + timedelta(minutes=1)),
            expected_generation=1,
        )
    with pytest.raises(StateError, match="not the current"):
        manager.disconnect(
            identity.logical_session_id,
            channel_id="wrong-channel",
            disconnected_at=_START + timedelta(minutes=1),
        )
    disconnected = manager.disconnect(
        identity.logical_session_id,
        channel_id=first.channel_id,
        disconnected_at=_START + timedelta(minutes=2),
    )
    assert disconnected.reconnect_deadline == _START + timedelta(minutes=5)
    with pytest.raises(StateError, match="generation"):
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=_transport(2, 1, connected_at=_START + timedelta(minutes=3)),
            expected_generation=2,
        )
    with pytest.raises(StateError, match="affinity"):
        manager.reconnect(
            identity.logical_session_id,
            affinity=_affinity(999),
            transport=_transport(2, 1, connected_at=_START + timedelta(minutes=3)),
            expected_generation=1,
        )
    with pytest.raises(StateError, match="at or after"):
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=_transport(2, 1, connected_at=_START + timedelta(minutes=5)),
            expected_generation=1,
        )

    manager.watermark(_START + timedelta(minutes=5))
    assert manager.get(identity.logical_session_id).state is RdpSessionState.LOGGED_OUT  # type: ignore[union-attr]
    with pytest.raises(StateError, match="cannot reconnect"):
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=_transport(2, 1, connected_at=_START + timedelta(minutes=6)),
            expected_generation=1,
        )
    with pytest.raises(StateError, match="behind watermark"):
        manager.record_member_admission(
            identity.logical_session_id,
            admitted_at=_START + timedelta(minutes=4),
        )


def test_transport_plan_requires_a_strictly_positive_connected_interval() -> None:
    """A connection exactly at transport close is not a usable generation."""

    binding = ApplicationTransportBinding(
        transport_id="zero-use-transport",
        opened_at=_START - timedelta(seconds=1),
        closes_at=_START,
    )
    with pytest.raises(ValueError, match="inside its transport binding"):
        RdpTransportPlan(
            channel_id="zero-use-channel",
            binding=binding,
            connected_at=_START,
            budget=ApplicationChannelBudget(1, 1, 1),
        )


def test_manager_requires_exact_shared_application_window() -> None:
    """The isolated sidecar cannot drift from the injected registry window."""

    application = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_START + timedelta(days=1),
    )
    with pytest.raises(ValueError, match="exact same window"):
        RdpReconnectStateManager(
            application_registry=application,
            window_start=_START,
            window_end=_START + timedelta(days=2),
        )


def test_compatibility_max_window_clamps_post_window_retention_horizon() -> None:
    """Direct-test datetime.max windows cannot overflow their bounded grace."""

    window_start = datetime.min.replace(tzinfo=UTC)
    window_end = datetime.max.replace(tzinfo=UTC)
    application = ApplicationChannelRegistry(
        window_start=window_start,
        window_end=window_end,
    )
    manager = RdpReconnectStateManager(
        application_registry=application,
        window_start=window_start,
        window_end=window_end,
    )

    assert manager._retention_horizon == window_end


def test_watermark_returns_bounded_exact_logout_closures_without_history() -> None:
    """One page returns terminal intents once and leaves remaining due work indexed."""

    manager, application = _manager(post_logout_grace=timedelta(seconds=10))
    identities = [
        _identity(
            index,
            idle_timeout=timedelta(seconds=1),
            reconnect_timeout=timedelta(seconds=1),
            hard_deadline=_START + timedelta(seconds=10),
        )
        for index in range(3)
    ]
    for index, identity in enumerate(identities):
        manager.open_session(
            identity,
            _transport(
                index,
                0,
                connected_at=_START,
                closes_at=_START + timedelta(seconds=10),
            ),
        )

    first = manager.watermark(_START + timedelta(seconds=4), limit=2)
    assert len(first.closures) == 2
    assert first.has_more
    assert first.census.logged_out_sessions == 2
    assert {closure.logical_session_id for closure in first.closures}.issubset(
        {identity.logical_session_id for identity in identities}
    )
    for closure in first.closures:
        identity = next(
            identity
            for identity in identities
            if identity.logical_session_id == closure.logical_session_id
        )
        assert closure.target_hostname == identity.affinity.target_host
        assert closure.principal == identity.affinity.principal
        assert closure.logon_id == identity.affinity.logon_id
        assert closure.session_id == identity.affinity.session_id
        assert closure.generation_ordinal == 0
        assert closure.closed_at == _START + timedelta(seconds=2)
        assert closure.reason == "rdp_reconnect_timeout"
        channel = application.get(closure.channel_id)
        assert channel is not None
        assert channel.identity.binding.transport_id == closure.transport_id
        assert channel.closed_at == _START + timedelta(seconds=1)

    second = manager.watermark(_START + timedelta(seconds=4), limit=2)
    assert len(second.closures) == 1
    assert not second.has_more
    assert second.census.logged_out_sessions == 3
    assert not {closure.logical_session_id for closure in first.closures}.intersection(
        {closure.logical_session_id for closure in second.closures}
    )
    repeated = manager.watermark(_START + timedelta(seconds=4), limit=2)
    assert repeated.closures == ()
    assert not repeated.has_more
    assert not hasattr(manager, "_completed_closures")

    with pytest.raises(ValueError, match="limit must be positive"):
        manager.watermark(_START + timedelta(seconds=4), limit=0)


def test_lifecycle_authority_can_reconcile_auto_logout_later_before_eviction() -> None:
    """A descendant-close clamp may move terminal time later, never earlier."""

    manager, _application = _manager(post_logout_grace=timedelta(seconds=1))
    identity = _identity(
        30,
        idle_timeout=timedelta(seconds=1),
        reconnect_timeout=timedelta(seconds=1),
        hard_deadline=_START + timedelta(seconds=10),
    )
    manager.open_session(
        identity,
        _transport(
            30,
            0,
            connected_at=_START,
            closes_at=_START + timedelta(seconds=10),
        ),
    )

    result = manager.watermark(_START + timedelta(minutes=1), limit=1)
    assert len(result.closures) == 1
    assert result.has_more
    closure = result.closures[0]
    assert closure.closed_at == _START + timedelta(seconds=2)
    assert manager.get(identity.logical_session_id) is not None

    lifecycle_close = _START + timedelta(seconds=12)
    reconciled = manager.logout(
        identity.logical_session_id,
        logged_out_at=lifecycle_close,
        reason="rdp_logoff",
    )
    assert reconciled.logged_out_at == lifecycle_close
    assert reconciled.last_transition_at == lifecycle_close
    with pytest.raises(StateError, match="move an accepted terminal time backward"):
        manager.logout(
            identity.logical_session_id,
            logged_out_at=closure.closed_at,
            reason="rdp_logoff",
        )

    drained = manager.watermark(_START + timedelta(minutes=1), limit=1)
    assert drained.closures == ()
    assert manager.get(identity.logical_session_id) is None


def test_many_reconnect_generations_do_not_reuse_or_mutate_channel_affinity() -> None:
    """Generation-specific channel affinity permits repeated immutable reconnects."""

    manager, application = _manager(closed_grace=timedelta(minutes=30))
    identity = _identity(20, reconnect_timeout=timedelta(minutes=5))
    plan = _transport(20, 0, connected_at=_START)
    manager.open_session(identity, plan)
    retained_bindings = [plan.binding]
    for generation in range(1, 21):
        disconnected_at = _START + timedelta(seconds=generation * 4 - 2)
        manager.disconnect(
            identity.logical_session_id,
            channel_id=plan.channel_id,
            disconnected_at=disconnected_at,
        )
        plan = _transport(
            20,
            generation,
            connected_at=disconnected_at + timedelta(seconds=1),
        )
        retained_bindings.append(plan.binding)
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=plan,
            expected_generation=generation,
        )
    snapshot = manager.get(identity.logical_session_id)
    assert snapshot is not None and snapshot.generation.ordinal == 20
    assert application.census().retained_channels == 21
    for generation, binding in enumerate(retained_bindings):
        channel = application.get(f"rdp-channel-{20:08d}-{generation}")
        assert channel is not None and channel.identity.binding == binding


def test_operation_budget_containment_and_active_close_barrier() -> None:
    """Logical and per-transport budgets fence operations and closure."""

    manager, _application = _manager()
    identity = _identity(
        3,
        budget=ApplicationChannelBudget(100, 200, 2),
    )
    plan = _transport(
        3,
        0,
        connected_at=_START,
        budget=ApplicationChannelBudget(100, 200, 2),
    )
    manager.open_session(identity, plan)
    active = manager.reserve_operation(
        identity.logical_session_id,
        started_at=_START + timedelta(seconds=1),
        ended_at=_START + timedelta(seconds=5),
        initiator_bytes=60,
        responder_bytes=150,
    )
    with pytest.raises(StateError, match="active operations"):
        manager.disconnect(
            identity.logical_session_id,
            channel_id=plan.channel_id,
            disconnected_at=_START + timedelta(seconds=6),
        )
    with pytest.raises(StateError, match="initiator byte budget"):
        manager.reserve_operation(
            identity.logical_session_id,
            started_at=_START + timedelta(seconds=6),
            ended_at=_START + timedelta(seconds=7),
            initiator_bytes=41,
        )
    assert manager.finalize_operation(
        identity.logical_session_id,
        active.reservation.operation_id,
    )
    second = manager.reserve_operation(
        identity.logical_session_id,
        started_at=_START + timedelta(seconds=6),
        ended_at=_START + timedelta(seconds=7),
        initiator_bytes=40,
        responder_bytes=50,
    )
    assert second.session.reserved_operations == 2
    with pytest.raises(StateError, match="logical operation budget"):
        manager.reserve_operation(
            identity.logical_session_id,
            started_at=_START + timedelta(seconds=8),
            ended_at=_START + timedelta(seconds=9),
        )


def test_explicit_lease_extends_then_releases_bounded_tombstone() -> None:
    """A bounded explicit lease extends grace without reviving a logout."""

    manager, application = _manager(post_logout_grace=timedelta(seconds=5))
    identity = _identity(4)
    plan = _transport(4, 0, connected_at=_START)
    manager.open_session(identity, plan)
    lease = RdpRetentionLease(
        lease_id="correlation-read",
        logical_session_id=identity.logical_session_id,
        acquired_at=_START + timedelta(seconds=1),
        retain_until=_START + timedelta(minutes=2),
        reason="late source projection",
    )
    assert manager.add_retention_lease(lease) == lease
    assert manager.add_retention_lease(lease) == lease
    logged_out = manager.logout(
        identity.logical_session_id,
        logged_out_at=_START + timedelta(seconds=2),
    )
    assert logged_out.retention_deadline == lease.retain_until
    manager.watermark(_START + timedelta(seconds=30))
    application.watermark(_START + timedelta(seconds=30))
    assert manager.get(identity.logical_session_id) is not None
    assert manager.release_retention_lease(
        identity.logical_session_id,
        lease.lease_id,
        released_at=_START + timedelta(seconds=30),
    )
    assert not manager.release_retention_lease(
        identity.logical_session_id,
        lease.lease_id,
        released_at=_START + timedelta(seconds=30),
    )
    manager.watermark(_START + timedelta(seconds=31))
    application.watermark(_START + timedelta(seconds=31))
    assert manager.get(identity.logical_session_id) is None


def test_unreferenced_logged_out_eviction_does_not_reconstruct_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Packed route metadata removes an expired tombstone without decoding frozen rows."""

    manager, application = _manager(post_logout_grace=timedelta(seconds=5))
    identity = _identity(404)
    manager.open_session(identity, _transport(404, 0, connected_at=_START))
    manager.logout(
        identity.logical_session_id,
        logged_out_at=_START + timedelta(seconds=1),
    )
    shard = manager._shard(identity.logical_session_id, create=False)
    assert shard is not None

    def fail_reconstruction(_handle: int, **_kwargs: object) -> None:
        raise AssertionError("logged-out eviction reconstructed a frozen snapshot")

    monkeypatch.setattr(shard.sessions, "get_by_handle", fail_reconstruction)
    result = manager.watermark(_START + timedelta(seconds=7))
    application.watermark(_START + timedelta(seconds=7))

    assert result.census.retained_sessions == 0
    assert manager.get(identity.logical_session_id) is None


def test_exact_affinity_lookup_inspects_one_of_one_thousand() -> None:
    """Exact affinity routing never scans neighboring logical sessions."""

    manager, _application = _manager()
    for index in range(1_000):
        identity = _identity(index)
        manager.open_session(identity, _transport(index, 0, connected_at=_START))
    before = manager.census().lookup_candidates_inspected
    expected = _identity(777)
    found = manager.find_by_affinity(expected.affinity)
    after = manager.census().lookup_candidates_inspected
    assert found is not None
    assert found.logical_session_id == expected.logical_session_id
    assert after - before == 1
    assert manager.find_by_affinity(_affinity(2_000)) is None


def test_exact_logical_lookup_inspects_one_routed_candidate() -> None:
    """A routed logical-ID read inspects one candidate and a route miss inspects none."""

    manager, _application = _manager()
    identity = _identity(777)
    manager.open_session(identity, _transport(777, 0, connected_at=_START))
    before = manager.census()

    found = manager.get(identity.logical_session_id)
    after_hit = manager.census()
    missing = manager.get("missing-logical-session")
    after_miss = manager.census()

    assert found is not None
    assert found.logical_session_id == identity.logical_session_id
    assert missing is None
    assert (
        after_hit.logical_lookup_candidates_inspected - before.logical_lookup_candidates_inspected
        == 1
    )
    assert (
        after_miss.logical_lookup_candidates_inspected
        == after_hit.logical_lookup_candidates_inspected
    )
    assert after_hit.lookup_candidates_inspected - before.lookup_candidates_inspected == 1


@pytest.mark.slow
def test_one_million_exact_affinity_queries_keep_one_candidate_bound() -> None:
    """A million routed reads each inspect exactly one of 1,000 affinities."""

    manager, _application = _manager()
    affinities: list[RdpSessionAffinity] = []
    for index in range(1_000):
        identity = _identity(index)
        affinities.append(identity.affinity)
        manager.open_session(identity, _transport(index, 0, connected_at=_START))
    before = manager.census().lookup_candidates_inspected
    for query in range(1_000_000):
        found = manager.find_by_affinity(affinities[query % len(affinities)])
        assert found is not None
    after = manager.census().lookup_candidates_inspected
    assert after - before == 1_000_000


def _concurrency_digest(workers: int) -> tuple[tuple[object, ...], ...]:
    manager, _application = _manager()

    def exercise(index: int) -> tuple[object, ...]:
        identity = _identity(index)
        first = _transport(index, 0, connected_at=_START)
        manager.open_session(identity, first)
        operation = manager.reserve_operation(
            identity.logical_session_id,
            started_at=_START + timedelta(seconds=1),
            ended_at=_START + timedelta(seconds=2),
            initiator_bytes=index + 1,
            responder_bytes=index + 2,
        )
        manager.finalize_operation(identity.logical_session_id, operation.reservation.operation_id)
        manager.disconnect(
            identity.logical_session_id,
            channel_id=first.channel_id,
            disconnected_at=_START + timedelta(minutes=2),
        )
        second = _transport(index, 1, connected_at=_START + timedelta(minutes=3))
        manager.reconnect(
            identity.logical_session_id,
            affinity=identity.affinity,
            transport=second,
            expected_generation=1,
        )
        snapshot = manager.logout(
            identity.logical_session_id,
            logged_out_at=_START + timedelta(minutes=4),
        )
        return (
            snapshot.logical_session_id,
            snapshot.state,
            snapshot.generation.ordinal,
            snapshot.reserved_initiator_bytes,
            snapshot.reserved_responder_bytes,
            snapshot.completed_operations,
            snapshot.logged_out_at,
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return tuple(sorted(pool.map(exercise, range(96))))


def test_concurrent_one_four_eight_worker_digests_match() -> None:
    """Disjoint fixed shards produce identical state at 1/4/8 workers."""

    assert _concurrency_digest(1) == _concurrency_digest(4) == _concurrency_digest(8)


def test_public_state_digest_ignores_python_hash_seed() -> None:
    """Semantic sharding and state transitions must not depend on hash randomization."""

    script = """
import json

from tests.unit.test_rdp_reconnect_state import _START, _identity, _manager, _transport

manager, _application = _manager()
for key in {f"session-{index}" for index in range(64)}:
    index = int(key.rpartition("-")[2])
    identity = _identity(index)
    first = _transport(index, 0, connected_at=_START)
    manager.open_session(identity, first)
    manager.disconnect(
        identity.logical_session_id,
        channel_id=first.channel_id,
        disconnected_at=_START + identity.idle_timeout,
    )
    manager.reconnect(
        identity.logical_session_id,
        affinity=identity.affinity,
        transport=_transport(index, 1, connected_at=_START + identity.idle_timeout),
        expected_generation=1,
    )

rows = []
for index in range(64):
    identity = _identity(index)
    snapshot = manager.get(identity.logical_session_id)
    assert snapshot is not None
    rows.append(
        [
            snapshot.logical_session_id,
            snapshot.state.value,
            snapshot.generation.ordinal,
            snapshot.generation.binding.transport_id,
            manager.partition_id(snapshot.logical_session_id),
            manager.affinity_partition_id(snapshot.identity.affinity),
        ]
    )
print(json.dumps(rows, separators=(",", ":")))
"""
    digests: list[str] = []
    for hash_seed in ("1", "99991"):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": hash_seed},
        )
        digests.append(completed.stdout)
    assert digests[0] == digests[1]


def test_disjoint_partitions_reach_application_open_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The manager does not serialize independent owner/affinity partitions."""

    manager, application = _manager()
    first = _identity(100)
    second = next(
        _identity(index)
        for index in range(101, 10_000)
        if manager.partition_id(_identity(index).logical_session_id)
        != manager.partition_id(first.logical_session_id)
        and manager.affinity_partition_id(_identity(index).affinity)
        != manager.affinity_partition_id(first.affinity)
    )
    rendezvous = Barrier(2)
    original_open = application.open_channel_with_token

    def overlapping_open(
        identity: ApplicationChannelIdentity,
    ) -> tuple[ApplicationChannelSnapshot, ApplicationChannelCloseToken]:
        rendezvous.wait(timeout=2)
        return original_open(identity)

    monkeypatch.setattr(application, "open_channel_with_token", overlapping_open)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = tuple(
            pool.submit(
                manager.open_session,
                identity,
                _transport(index, 0, connected_at=_START),
            )
            for index, identity in ((100, first), (second.affinity.session_id - 1, second))
        )
        snapshots = tuple(future.result(timeout=3) for future in futures)
    assert {snapshot.logical_session_id for snapshot in snapshots} == {
        first.logical_session_id,
        second.logical_session_id,
    }


def _duration_checkpoints(
    duration_hours: int = 30 * 24,
) -> tuple[
    RdpReconnectStateManager,
    dict[int, tuple[int, int]],
]:
    end = _START + timedelta(days=31)
    manager, application = _manager(
        window_end=end,
        closed_grace=timedelta(seconds=1),
        post_logout_grace=timedelta(seconds=1),
    )
    checkpoints: dict[int, tuple[int, int]] = {}
    index = 0
    for hour in range(duration_hours):
        hour_start = _START + timedelta(hours=hour)
        for offset in (timedelta(seconds=1), timedelta(seconds=10)):
            started = hour_start + offset
            identity = _identity(
                index,
                started_at=started,
                hard_deadline=started + timedelta(minutes=10),
            )
            plan = _transport(
                index,
                0,
                connected_at=started,
                closes_at=started + timedelta(minutes=5),
            )
            manager.open_session(identity, plan)
            manager.logout(
                identity.logical_session_id,
                logged_out_at=started + timedelta(seconds=1),
            )
            index += 1
        cutoff = hour_start + timedelta(minutes=59)
        manager.watermark(cutoff)
        application.watermark(cutoff)
        if hour + 1 in {24, 7 * 24, 30 * 24}:
            census = manager.census()
            checkpoints[hour + 1] = (census.estimated_bytes, census.primary_map_bytes)
    return manager, checkpoints


def test_thirty_day_unique_session_churn_plateaus_without_completed_history() -> None:
    """Fixed-rate unique-key churn plateaus after shards and reusable slots warm."""

    manager, checkpoints = _duration_checkpoints()
    one_day = checkpoints[24]
    seven_days = checkpoints[7 * 24]
    thirty_days = checkpoints[30 * 24]
    assert manager.census().retained_sessions == 0
    assert thirty_days[0] <= seven_days[0] * 1.10
    assert thirty_days[1] <= max(seven_days[1] * 1.10, one_day[1])
    assert not hasattr(manager, "_completed_transports")
    assert not hasattr(manager, "_completed_operations")


def test_partial_session_eviction_incrementally_compacts_packed_row_arenas() -> None:
    """Surviving tombstones do not pin deleted identity/generation arena rows."""

    manager, application = _manager(post_logout_grace=timedelta(seconds=1))
    retained_ids: list[str] = []
    for index in range(256):
        identity = _identity(index)
        manager.open_session(identity, _transport(index, 0, connected_at=_START))
        if index % 16 == 0:
            retained_ids.append(identity.logical_session_id)
            manager.add_retention_lease(
                RdpRetentionLease(
                    lease_id=f"partial-compaction-{index}",
                    logical_session_id=identity.logical_session_id,
                    acquired_at=_START,
                    retain_until=_START + timedelta(minutes=2),
                    reason="partial packed arena compaction regression",
                )
            )
        manager.logout(
            identity.logical_session_id,
            logged_out_at=_START + timedelta(microseconds=1),
        )

    manager.watermark(_START + timedelta(seconds=2))
    application.watermark(_START + timedelta(seconds=2))
    assert manager.census().retained_sessions == len(retained_ids)
    for shard in manager._shards.values():
        store = shard.sessions
        identity_backing = sum(len(arena) for arena in store._identity_arenas)
        generation_backing = sum(len(arena) for arena in store._generation_arenas)
        assert identity_backing <= store._identity_live_bytes * 2
        assert generation_backing <= store._generation_live_bytes * 2
    assert not manager.census().compaction_pending


def test_public_census_accounts_for_compact_sidecars_and_shared_application() -> None:
    """Census exposes bounded cardinality, expiry, and byte estimates."""

    manager, _application = _manager()
    identity = _identity(5)
    manager.open_session(identity, _transport(5, 0, connected_at=_START))
    census = manager.census()
    assert census.retained_sessions == 1
    assert census.connected_sessions == 1
    assert (
        census.connected_sessions + census.disconnected_sessions + census.logged_out_sessions == 1
    )
    assert census.sidecar_shard_count <= manager.application_registry.shard_count
    assert census.affinity_partition_count <= manager.application_registry.shard_count
    assert census.estimated_bytes >= census.estimated_index_bytes > 0
    assert census.primary_map_bytes > 0
    assert census.application.retained_channels == 1
