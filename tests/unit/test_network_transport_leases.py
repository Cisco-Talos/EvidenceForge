# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical source-port lease allocation and lifecycle contracts."""

from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.network_runtime import (
    NetworkTransactionPreparation,
    NetworkTransactionRuntime,
    NetworkTransportLease,
)
from evidenceforge.generation.state_manager import ConnectionMaterializationMode, StateManager
from evidenceforge.models.exceptions import TransportPortExhaustionError
from tests.network_factories import network_plan

_START = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def _runtime() -> tuple[NetworkTransactionRuntime, StateManager]:
    state = StateManager()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=_START,
        window_end=_START + timedelta(days=4),
    )
    return runtime, state


def _begin(
    runtime: NetworkTransactionRuntime,
    rng: random.Random,
    intent: str,
    opened_at: datetime,
) -> NetworkTransactionPreparation:
    return runtime.begin(
        owner_rng=rng,
        stable_id=intent,
        linearization_time=opened_at,
    )


def _reserve(
    preparation: NetworkTransactionPreparation,
    *,
    intent: str,
    opened_at: datetime,
    duration: float = 10.0,
    source_port: int | None = None,
    protocol: str = "tcp",
    source_os_category: str = "windows",
    port_range: tuple[int, int] | None = None,
    src_ip: str = "10.0.0.10",
) -> NetworkTransportLease:
    return preparation.reserve_transport_tuple(
        intent_stable_id=intent,
        src_ip=src_ip,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol=protocol,
        opened_at=opened_at,
        closed_at=opened_at + timedelta(seconds=duration),
        source_port=source_port,
        source_os_category=source_os_category,
        port_range=port_range,
    )


def _commit(
    runtime: NetworkTransactionRuntime,
    state: StateManager,
    rng: random.Random,
    preparation: NetworkTransactionPreparation,
    lease: NetworkTransportLease,
) -> None:
    identity = preparation.reserve_physical_identity()
    transaction = replace(
        network_plan(
            src_ip=lease.src_ip,
            src_port=lease.src_port,
            dst_ip=lease.dst_ip,
            dst_port=lease.dst_port,
            protocol=lease.protocol,
            service="https",
            zeek_uid=identity.zeek_uid,
            conn_id=identity.conn_id,
            duration=(lease.closed_at - lease.opened_at).total_seconds(),
            source_visible_start_time=lease.opened_at,
            conn_state="SF",
            history="ShADadFf",
            orig_bytes=120,
            resp_bytes=480,
        ),
        stable_id=lease.occurrence_stable_id,
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    state.materialize_connection_composite(root.state_plan, rng)
    with runtime.claimed_preparation(root.runtime_token) as prepared:
        prepared.commit_no_fail()


@pytest.mark.parametrize(
    ("os_category", "minimum", "maximum"),
    (("windows", 49_152, 65_535), ("linux", 32_768, 60_999)),
)
def test_automatic_lease_uses_os_ephemeral_range(
    os_category: str,
    minimum: int,
    maximum: int,
) -> None:
    runtime, _state = _runtime()
    rng = random.Random(10)
    preparation = _begin(runtime, rng, f"intent-{os_category}", _START)

    lease = _reserve(
        preparation,
        intent=f"intent-{os_category}",
        opened_at=_START,
        source_os_category=os_category,
    )

    assert minimum <= lease.src_port <= maximum
    assert lease.automatic
    assert runtime.census().pending_transport_leases == 1
    preparation.cancel()


def test_exact_port_claim_is_atomic_and_overlap_failure_is_neutral() -> None:
    runtime, _state = _runtime()
    first_rng = random.Random(11)
    first = _begin(runtime, first_rng, "first", _START)
    _reserve(first, intent="first", opened_at=_START, source_port=50_000)
    digest = runtime.state_digest()

    second_rng = random.Random(12)
    second = _begin(runtime, second_rng, "second", _START + timedelta(seconds=1))
    rng_state = second_rng.getstate()
    with pytest.raises(TransportPortExhaustionError) as raised:
        _reserve(
            second,
            intent="second",
            opened_at=_START + timedelta(seconds=1),
            source_port=50_000,
        )

    assert not raised.value.automatic
    assert raised.value.active_count == 1
    assert runtime.state_digest() == digest
    second.cancel()
    assert second_rng.getstate() == rng_state
    first.cancel()
    assert runtime.census().pending_transport_leases == 0


def test_half_open_boundary_reuse_and_future_overlap() -> None:
    runtime, _state = _runtime()
    first = _begin(runtime, random.Random(13), "first", _START)
    _reserve(first, intent="first", opened_at=_START, source_port=50_001)

    boundary = _begin(runtime, random.Random(14), "boundary", _START + timedelta(seconds=10))
    boundary_lease = _reserve(
        boundary,
        intent="boundary",
        opened_at=_START + timedelta(seconds=10),
        source_port=50_001,
    )
    assert boundary_lease.src_port == 50_001

    future = _begin(runtime, random.Random(15), "future", _START + timedelta(seconds=5))
    with pytest.raises(TransportPortExhaustionError):
        _reserve(
            future,
            intent="future",
            opened_at=_START + timedelta(seconds=5),
            source_port=50_001,
        )
    future.cancel()
    boundary.cancel()
    first.cancel()


def test_zero_length_interval_does_not_hide_an_overlapping_neighbor() -> None:
    """Empty intervals never obscure a live interval in the tuple index."""

    runtime, _state = _runtime()
    live = _begin(runtime, random.Random(140), "live", _START)
    _reserve(live, intent="live", opened_at=_START, source_port=50_001)
    empty = _begin(runtime, random.Random(141), "empty", _START + timedelta(seconds=5))
    _reserve(
        empty,
        intent="empty",
        opened_at=_START + timedelta(seconds=5),
        duration=0.0,
        source_port=50_001,
    )
    overlapping = _begin(runtime, random.Random(142), "overlap", _START + timedelta(seconds=6))

    with pytest.raises(TransportPortExhaustionError):
        _reserve(
            overlapping,
            intent="overlap",
            opened_at=_START + timedelta(seconds=6),
            source_port=50_001,
        )

    overlapping.cancel()
    empty.cancel()
    live.cancel()


def test_ipv4_mapped_addresses_share_one_lease_bucket() -> None:
    runtime, _state = _runtime()
    first = _begin(runtime, random.Random(16), "mapped", _START)
    lease = _reserve(
        first,
        intent="mapped",
        opened_at=_START,
        source_port=50_002,
        src_ip="::ffff:10.0.0.10",
    )
    assert lease.src_ip == "10.0.0.10"

    second = _begin(runtime, random.Random(17), "plain", _START + timedelta(seconds=1))
    with pytest.raises(TransportPortExhaustionError):
        _reserve(
            second,
            intent="plain",
            opened_at=_START + timedelta(seconds=1),
            source_port=50_002,
        )
    second.cancel()
    first.cancel()


def test_tcp_and_udp_lease_independently() -> None:
    runtime, _state = _runtime()
    tcp = _begin(runtime, random.Random(18), "tcp", _START)
    udp = _begin(runtime, random.Random(19), "udp", _START)

    tcp_lease = _reserve(tcp, intent="tcp", opened_at=_START, source_port=50_003)
    udp_lease = _reserve(
        udp,
        intent="udp",
        opened_at=_START,
        source_port=50_003,
        protocol="udp",
    )

    assert tcp_lease.protocol == "tcp"
    assert udp_lease.protocol == "udp"
    tcp.cancel()
    udp.cancel()


def test_adaptive_reuse_ignores_freshness_only_after_128_candidates() -> None:
    runtime, state = _runtime()
    first_rng = random.Random(20)
    first = _begin(runtime, first_rng, "first", _START)
    first_lease = _reserve(
        first,
        intent="first",
        opened_at=_START,
        port_range=(50_010, 50_010),
    )
    _commit(runtime, state, first_rng, first, first_lease)

    later_rng = random.Random(21)
    later = _begin(runtime, later_rng, "later", _START + timedelta(seconds=20))
    later_lease = _reserve(
        later,
        intent="later",
        opened_at=_START + timedelta(seconds=20),
        port_range=(50_010, 50_010),
    )
    _commit(runtime, state, later_rng, later, later_lease)

    assert later_lease.src_port == first_lease.src_port
    assert runtime.census().adaptive_transport_reuses == 1
    assert runtime.census().transport_candidate_inspections == 130


def test_true_simultaneous_exhaustion_uses_reduced_range() -> None:
    runtime, _state = _runtime()
    owners: list[NetworkTransactionPreparation] = []
    for index, port in enumerate((50_020, 50_021)):
        preparation = _begin(runtime, random.Random(30 + index), f"owner-{index}", _START)
        _reserve(
            preparation,
            intent=f"owner-{index}",
            opened_at=_START,
            source_port=port,
        )
        owners.append(preparation)
    exhausted = _begin(runtime, random.Random(32), "exhausted", _START)

    with pytest.raises(TransportPortExhaustionError) as raised:
        _reserve(
            exhausted,
            intent="exhausted",
            opened_at=_START,
            port_range=(50_020, 50_021),
        )

    assert raised.value.automatic
    assert raised.value.active_count == 2
    exhausted.cancel()
    for preparation in owners:
        preparation.cancel()


def test_later_reuse_changes_occurrence_id_and_exact_retry_adopts() -> None:
    runtime, state = _runtime()
    first_rng = random.Random(40)
    first = _begin(runtime, first_rng, "same-intent", _START)
    first_lease = _reserve(
        first,
        intent="same-intent",
        opened_at=_START,
        source_port=50_030,
    )
    _commit(runtime, state, first_rng, first, first_lease)

    retry = _begin(runtime, random.Random(41), "same-intent", _START)
    retry_lease = _reserve(
        retry,
        intent="same-intent",
        opened_at=_START,
        source_port=50_030,
    )
    assert retry_lease.occurrence_stable_id == first_lease.occurrence_stable_id
    retry.cancel()

    later = _begin(runtime, random.Random(42), "same-intent", _START + timedelta(seconds=10))
    later_lease = _reserve(
        later,
        intent="same-intent",
        opened_at=_START + timedelta(seconds=10),
        source_port=50_030,
    )
    assert later_lease.occurrence_stable_id != first_lease.occurrence_stable_id
    later.cancel()


def test_concurrent_exact_claim_has_one_winner() -> None:
    runtime, _state = _runtime()

    def reserve(index: int) -> tuple[NetworkTransactionPreparation, bool]:
        preparation = _begin(runtime, random.Random(50 + index), f"concurrent-{index}", _START)
        try:
            _reserve(
                preparation,
                intent=f"concurrent-{index}",
                opened_at=_START,
                source_port=50_040,
            )
        except TransportPortExhaustionError:
            return preparation, False
        return preparation, True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(reserve, range(2)))

    assert sum(won for _preparation, won in results) == 1
    for preparation, _won in results:
        preparation.cancel()


def test_watermark_prunes_hard_lease_then_freshness() -> None:
    runtime, state = _runtime()
    rng = random.Random(60)
    preparation = _begin(runtime, rng, "watermark", _START)
    lease = _reserve(preparation, intent="watermark", opened_at=_START, source_port=50_050)
    _commit(runtime, state, rng, preparation, lease)

    runtime.advance_watermark_page(_START + timedelta(seconds=10))
    census = runtime.census()
    assert census.live_transport_leases == 0
    assert census.retained_transport_freshness == 1

    runtime.advance_watermark_page(_START + timedelta(days=1, seconds=10))
    assert runtime.census().retained_transport_freshness == 0


@pytest.mark.slow
def test_lease_candidate_work_does_not_scale_with_unrelated_history() -> None:
    """Candidate inspection stays local after many unrelated committed tuples."""

    runtime, state = _runtime()
    for index in range(400):
        opened_at = _START + timedelta(seconds=index * 20)
        rng = random.Random(1_000 + index)
        preparation = _begin(runtime, rng, f"history-{index}", opened_at)
        lease = preparation.reserve_transport_tuple(
            intent_stable_id=f"history-{index}",
            src_ip=f"10.1.{index // 250}.{index % 250 + 1}",
            dst_ip="10.0.0.20",
            dst_port=443,
            protocol="tcp",
            opened_at=opened_at,
            closed_at=opened_at + timedelta(seconds=1),
            preferred_source_port=50_100,
            port_range=(50_100, 50_100),
        )
        _commit(runtime, state, rng, preparation, lease)

    inspections_before = runtime.census().transport_candidate_inspections
    opened_at = _START + timedelta(hours=3)
    rng = random.Random(2_000)
    preparation = _begin(runtime, rng, "probe", opened_at)
    lease = preparation.reserve_transport_tuple(
        intent_stable_id="probe",
        src_ip="10.9.9.9",
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        opened_at=opened_at,
        closed_at=opened_at + timedelta(seconds=1),
        preferred_source_port=50_100,
        port_range=(50_100, 50_100),
    )
    _commit(runtime, state, rng, preparation, lease)

    assert runtime.census().transport_candidate_inspections - inspections_before == 1


@pytest.mark.slow
def test_retained_lease_state_plateaus_across_multi_day_generation() -> None:
    """Hard leases drain and freshness retains only a rolling one-day horizon."""

    runtime, state = _runtime()
    retained_counts: list[int] = []
    for day in range(3):
        day_start = _START + timedelta(days=day)
        for index in range(48):
            opened_at = day_start + timedelta(seconds=index * 30)
            rng = random.Random(3_000 + day * 100 + index)
            intent = f"day-{day}-transport-{index}"
            preparation = _begin(runtime, rng, intent, opened_at)
            lease = _reserve(
                preparation,
                intent=intent,
                opened_at=opened_at,
                duration=1.0,
                port_range=(50_200, 50_295),
            )
            _commit(runtime, state, rng, preparation, lease)
        cutoff = day_start + timedelta(days=1)
        while True:
            page = runtime.advance_watermark_page(cutoff, limit=32)
            if not page.has_more:
                break
        census = runtime.census()
        assert census.live_transport_leases == 0
        retained_counts.append(census.retained_transport_freshness)

    assert max(retained_counts[1:]) <= 96
