# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded-retention contracts for SSH client source-port reservations."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.network_runtime import NetworkRuntimePointFamily
from evidenceforge.generation.process_runtime_cache import (
    ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES,
    ActivityGeneratorRetentionDisposition,
    BoundedRuntimeCache,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 1, 1, tzinfo=UTC)
_SOURCE_IP = "10.0.0.10"
_TARGET_IP = "10.0.0.20"
_SOURCE_PORT = 51_111
_RATE_PER_HOUR = 4


def _generator(*, duration_days: int = 31) -> ActivityGenerator:
    state_manager = StateManager()
    state_manager.set_current_time(_START)
    return ActivityGenerator(
        state_manager,
        {},
        generation_window_start=_START,
        generation_window_end=_START + timedelta(days=duration_days),
    )


def _reserve(
    generator: ActivityGenerator,
    *,
    at: datetime,
    source_ip: str,
    source_port: int,
    seed: int,
) -> int:
    return generator.reserve_ssh_source_port(
        source_ip,
        _TARGET_IP,
        source_port,
        random.Random(seed),
        "linux",
        time=at,
    )


def test_explicit_port_is_never_silently_substituted() -> None:
    """Exact SSH intent retains its authored port at every reservation horizon."""

    generator = _generator()
    first = _reserve(
        generator,
        at=_START,
        source_ip=_SOURCE_IP,
        source_port=_SOURCE_PORT,
        seed=1,
    )
    same_connection = _reserve(
        generator,
        at=_START + timedelta(milliseconds=250),
        source_ip=_SOURCE_IP,
        source_port=first,
        seed=2,
    )
    later_connection = _reserve(
        generator,
        at=_START + timedelta(seconds=2),
        source_ip=_SOURCE_IP,
        source_port=first,
        seed=3,
    )
    exact_horizon = _reserve(
        generator,
        at=_START + timedelta(hours=24),
        source_ip=_SOURCE_IP,
        source_port=first,
        seed=4,
    )
    after_horizon = _reserve(
        generator,
        at=_START + timedelta(hours=24, microseconds=1),
        source_ip=_SOURCE_IP,
        source_port=first,
        seed=5,
    )

    assert {
        first,
        same_connection,
        later_connection,
        exact_horizon,
        after_horizon,
    } == {_SOURCE_PORT}


def test_exhausted_candidate_draws_fail_instead_of_reusing_a_live_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bounded retry path must never fall through to a reserved 24-hour tuple."""

    generator = _generator()
    monkeypatch.setattr(generator_module, "_ephemeral_port", lambda _rng, _os: _SOURCE_PORT)
    first = generator.reserve_ssh_source_port(
        _SOURCE_IP,
        _TARGET_IP,
        None,
        random.Random(1),
        "linux",
        time=_START,
    )
    assert first == _SOURCE_PORT

    with pytest.raises(StateError, match="after 100 exact-key attempts"):
        generator.reserve_ssh_source_port(
            _SOURCE_IP,
            _TARGET_IP,
            None,
            random.Random(2),
            "linux",
            time=_START + timedelta(seconds=2),
        )

    assert len(generator._ssh_source_ports) == 1


def test_reservation_avoids_a_tuple_already_owned_by_network_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generic connection reservation remains authoritative for later SSH allocation."""

    generator = _generator()
    generator._network_transaction_runtime.set_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        (_SOURCE_IP, _SOURCE_PORT, _TARGET_IP, 22, "tcp"),
        _START.timestamp(),
        expires_at=_START + timedelta(hours=24),
    )
    candidate_ports = iter((_SOURCE_PORT, _SOURCE_PORT + 1))
    monkeypatch.setattr(
        generator_module,
        "_ephemeral_port",
        lambda _rng, _os: next(candidate_ports),
    )

    reserved = generator.reserve_ssh_source_port(
        _SOURCE_IP,
        _TARGET_IP,
        None,
        random.Random(1),
        "linux",
        time=_START + timedelta(seconds=1),
    )

    assert reserved == _SOURCE_PORT + 1


def _duration_profile(hours: int) -> tuple[int, int, int, int]:
    generator = _generator(duration_days=32)
    ordinal = 0
    for hour in range(hours):
        hour_start = _START + timedelta(hours=hour)
        for in_hour in range(_RATE_PER_HOUR):
            at = hour_start + timedelta(minutes=in_hour * 10)
            source_ip = f"10.{(ordinal // 62_500) + 1}.{(ordinal // 250) % 250}.{ordinal % 250 + 1}"
            source_port = 32_768 + ordinal % (60_999 - 32_768 + 1)
            assert (
                _reserve(
                    generator,
                    at=at,
                    source_ip=source_ip,
                    source_port=source_port,
                    seed=ordinal,
                )
                == source_port
            )
            ordinal += 1
        generator.advance_process_state_watermark(hour_start - timedelta(hours=24))

    metrics = generator._ssh_source_ports.metrics(estimate_bytes=True)
    return (
        len(generator._ssh_source_ports),
        metrics.backing_entries,
        metrics.stale_entries,
        metrics.high_water_mark,
    )


def test_reservations_plateau_from_seven_to_thirty_days_with_bounded_backing() -> None:
    """Long runs retain one fixed 24-hour working set rather than lifetime history."""

    day = _duration_profile(24)
    week = _duration_profile(24 * 7)
    month = _duration_profile(24 * 30)

    assert day[0] == 24 * _RATE_PER_HOUR
    assert week == month
    assert week[0] == 25 * _RATE_PER_HOUR
    assert week[1] <= week[0] * 2
    assert week[2] == 0
    assert week[3] <= 26 * _RATE_PER_HOUR


def test_repeated_expiry_cycles_reclaim_all_physical_backing() -> None:
    """Repeated fill/drain cycles leave neither stale heap rows nor allocated backing."""

    generator = _generator(duration_days=64)
    records_per_cycle = 128
    for cycle in range(20):
        cycle_start = _START + timedelta(days=cycle * 2)
        for ordinal in range(records_per_cycle):
            _reserve(
                generator,
                at=cycle_start + timedelta(microseconds=ordinal),
                source_ip=f"10.{cycle + 1}.0.{ordinal % 250 + 1}",
                source_port=40_000 + ordinal,
                seed=cycle * records_per_cycle + ordinal,
            )
        generator.advance_process_state_watermark(
            cycle_start + timedelta(microseconds=records_per_cycle)
        )
        metrics = generator._ssh_source_ports.metrics(estimate_bytes=True)
        assert len(generator._ssh_source_ports) == 0
        assert metrics.backing_entries == 0
        assert metrics.stale_entries == 0

    assert generator._ssh_source_ports.expiry_work == 20 * records_per_cycle


def _deterministic_reservations() -> tuple[tuple[int, ...], tuple[int, int, int]]:
    generator = _generator()
    ports = tuple(
        generator.reserve_ssh_source_port(
            _SOURCE_IP,
            _TARGET_IP,
            None,
            random.Random(ordinal),
            "linux",
            time=_START + timedelta(seconds=ordinal * 2),
        )
        for ordinal in range(96)
    )
    metrics = generator._ssh_source_ports.metrics()
    return ports, (
        len(generator._ssh_source_ports),
        metrics.backing_entries,
        metrics.high_water_mark,
    )


def test_reservation_sequence_index_shape_and_policy_are_deterministic() -> None:
    """Equivalent inputs are deterministic and the census owns no growth exclusion."""

    first = _deterministic_reservations()
    second = _deterministic_reservations()
    policies = {
        policy.field_name: policy for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
    }

    assert first == second
    assert len(set(first[0])) == len(first[0])
    assert isinstance(_generator()._ssh_source_ports, BoundedRuntimeCache)
    assert policies["_ssh_source_ports"].disposition is (
        ActivityGeneratorRetentionDisposition.BOUNDED
    )
    assert policies["_ssh_source_ports"].owner == "bounded_temporal_index"
