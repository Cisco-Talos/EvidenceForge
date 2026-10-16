# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Mac uptime uses explicit ratios and existing durable boot ownership."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.lifecycle_production_adapters import service_boot_id
from evidenceforge.generation.state_manager import MaterializationBatchPlan, StateManager
from evidenceforge.generation.timing.distributions import TimingDistributionError
from evidenceforge.generation.timing.macos import MachTimebase, MacosBootClock
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import generation_seed_scope, stable_uuid
from tests.unit.test_macos_audit_identity import _START, _start


def _clock() -> MacosBootClock:
    return MacosBootClock(
        hostname="MAC-A",
        boot_time=_START,
        boot_uuid="12345678-1234-4234-8234-123456789abc",
        timebase=MachTimebase(125, 3),
    )


def test_mach_projection_is_integer_exact_monotonic_and_independent_of_export_order() -> None:
    clock = _clock()
    assert clock.ticks_at(_START) == 0
    assert clock.ticks_at(_START + timedelta(microseconds=1)) == 24
    assert clock.ticks_at(_START + timedelta(seconds=1)) == 24_000_000
    later = _START + timedelta(days=1500, microseconds=1)
    expected = (1500 * 86_400 * 1_000_000 + 1) * 24
    assert clock.ticks_at(later) == expected
    assert clock.ticks_at(_START + timedelta(microseconds=1)) == 24
    assert clock.ticks_at(later.astimezone(timezone(timedelta(hours=-4)))) == expected
    assert clock.timebase.ticks_for_nanoseconds(41) == 0
    assert clock.timebase.ticks_for_nanoseconds(42) == 1
    assert (
        replace(clock, timebase=MachTimebase(1, 1)).ticks_at(_START + timedelta(seconds=1))
        == 1_000_000_000
    )
    with pytest.raises(TimingDistributionError, match="nonnegative"):
        clock.ticks_at(_START - timedelta(microseconds=1))
    with pytest.raises(TimingDistributionError, match="timezone-aware"):
        clock.ticks_at(datetime(2026, 10, 16))


@pytest.mark.parametrize("value", [0, -1, True, 1.0, "1", None, 2**32])
def test_timebase_rejects_unknown_coerced_and_out_of_range_components(value: object) -> None:
    for numerator, denominator in ((value, 1), (1, value)):
        with pytest.raises(TimingDistributionError, match="uint32"):
            MachTimebase(numerator, denominator)


@pytest.mark.parametrize("value", [-1, True, 1.0, None])
def test_timebase_rejects_noninteger_elapsed_values(value: object) -> None:
    with pytest.raises(TimingDistributionError, match="nonnegative"):
        MachTimebase(1, 1).ticks_for_nanoseconds(value)


def test_mach_tick_range_fails_before_counter_wrap() -> None:
    timebase = MachTimebase(1, 1)
    assert timebase.ticks_for_nanoseconds(2**64 - 1) == 2**64 - 1
    with pytest.raises(TimingDistributionError, match="uint64"):
        timebase.ticks_for_nanoseconds(2**64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostname", ""),
        ("boot_time", datetime(2026, 10, 16)),
        ("boot_uuid", None),
        ("boot_uuid", "bad"),
        ("boot_uuid", "00000000-0000-0000-0000-000000000000"),
        ("boot_uuid", "12345678123442348234123456789abc"),
        ("timebase", None),
    ],
)
def test_boot_projection_requires_complete_explicit_facts(field: str, value: object) -> None:
    with pytest.raises(TimingDistributionError):
        replace(_clock(), **{field: value})


def test_registered_boot_projection_reuses_identity_without_allocation_and_survives_restore() -> (
    None
):
    manager = StateManager()
    _start(manager)
    boot_time = _START - timedelta(hours=2)
    manager.register_boot_time("MAC-A", boot_time)
    before = manager.materialization_digest()
    clock = manager.get_macos_boot_clock("MAC-A", timebase=MachTimebase(125, 3))
    assert manager.materialization_digest() == before
    assert clock.boot_uuid.lower() == service_boot_id("MAC-A", boot_time)
    assert clock.boot_uuid.lower() == stable_uuid(
        "lifecycle-service-boot", "mac-a", boot_time.isoformat()
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    assert restored.get_macos_boot_clock("MAC-A", timebase=clock.timebase) == clock
    assert clock.ticks_at(_START) == 2 * 3600 * 24_000_000
    _start(manager, "MAC-B")
    manager.register_boot_time("MAC-B", boot_time)
    assert (
        manager.get_macos_boot_clock("MAC-B", timebase=clock.timebase).boot_uuid != clock.boot_uuid
    )
    with generation_seed_scope(99):
        assert manager.get_macos_boot_clock("MAC-A", timebase=clock.timebase).boot_uuid != (
            clock.boot_uuid
        )
    manager.register_boot_time("MAC-A", boot_time + timedelta(seconds=1))
    assert (
        manager.get_macos_boot_clock("MAC-A", timebase=clock.timebase).boot_uuid != clock.boot_uuid
    )
    assert clock.boot_time == boot_time


@pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
def test_native_projection_rejects_unknown_or_incomplete_host_state(platform: str) -> None:
    manager = StateManager()
    timebase = MachTimebase(1, 1)
    with pytest.raises(StateError, match="established Mac"):
        manager.get_macos_boot_clock("UNKNOWN", timebase=timebase)
    _start(manager, "HOST", platform)
    with pytest.raises(StateError, match="established Mac"):
        manager.get_macos_boot_clock("HOST", timebase=timebase)
    if platform != "macos":
        manager.register_boot_time("HOST", _START)
        with pytest.raises(StateError, match="established Mac"):
            manager.get_macos_boot_clock("HOST", timebase=timebase)


def test_boot_projection_follows_materialization_rollback_and_replan() -> None:
    manager = StateManager()

    def plan_boot() -> MaterializationBatchPlan:
        builder = manager.begin_materialization_batch()
        builder.plan_boot_time("MAC-A", _START)
        builder.plan_process(
            system="MAC-A",
            parent_pid=0,
            image="/sbin/launchd",
            command_line="/sbin/launchd",
            username="root",
            integrity_level="System",
            os_category="macos",
            start_time=_START,
        )
        return builder.seal()

    plan = plan_boot()
    timebase = MachTimebase(125, 3)
    before = manager.materialization_digest()
    with manager.prepared_materialization_batch(plan) as prepared:
        prepared.apply_provisional()
        provisional = manager.get_macos_boot_clock("MAC-A", timebase=timebase)
    assert manager.materialization_digest() == before
    with pytest.raises(StateError, match="established Mac"):
        manager.get_macos_boot_clock("MAC-A", timebase=timebase)
    with manager.prepared_materialization_batch(plan_boot()) as prepared:
        prepared.apply_provisional()
        prepared.finalize_no_fail()
    assert manager.get_macos_boot_clock("MAC-A", timebase=timebase) == provisional
