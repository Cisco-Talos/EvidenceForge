# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Slow bounded-state and output-finalization checks for canonical SMB."""

from __future__ import annotations

import gc
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil
import pytest

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAffinity,
    SmbChannelCensus,
)

_HOURS_PER_DAY = 24
_PLATFORM_COUNT = 2
_MAX_DAILY_CHANNELS = _HOURS_PER_DAY * _PLATFORM_COUNT
_MAX_CANDIDATES_PER_PLATFORM = 4
_MAX_EXPIRY_ENTRIES_PER_CHANNEL = 3
_RSS_ALLOCATOR_SLACK_BYTES = 2 * 1_024 * 1_024


def _line_key(line: str) -> tuple[int, str]:
    timestamp, _separator, _payload = line.partition("|")
    return int(timestamp), line


def _render_days(output: Path, days: int) -> tuple[float, int]:
    writer = ExternalSortedLineWriter(
        output,
        sort_key=_line_key,
        buffer_size=1_000,
        buffer_bytes=256 * 1024,
        merge_fan_in=8,
    )
    started = time.perf_counter()
    max_buffered = 0
    for hour in range(days * 24):
        for item in range(100):
            sequence = hour * 100 + item
            writer.write(f"{sequence % 173}|smb-record-{sequence:08d}-{'x' * 64}")
            max_buffered = max(max_buffered, len(writer._buffer))
    writer.close()
    return time.perf_counter() - started, max_buffered


def _platform_affinities() -> tuple[SmbChannelAffinity, ...]:
    """Return exact Windows and Linux-to-Samba application-channel identities."""

    return (
        SmbChannelAffinity(
            client_identity="WIN-CLIENT-01",
            client_ip="10.0.1.10",
            client_session="0x1001",
            server_identity="FS-WIN-01",
            server_ip="10.0.1.20",
            principal="EXAMPLE\\alice",
            auth_protocol="kerberos",
            account_scope="EXAMPLE",
            dialect="3.1.1",
            signing_policy="required",
            encryption_policy="off",
            server_policy="windows:file-server",
            share_policy="disk:standard",
            client_access="windows_native",
        ),
        SmbChannelAffinity(
            client_identity="LINUX-CLIENT-01",
            client_ip="10.0.2.10",
            client_session="uid:1001",
            server_identity="SAMBA-01",
            server_ip="10.0.2.20",
            principal="alice",
            auth_protocol="ntlmv2",
            account_scope="WORKGROUP",
            dialect="3.1.1",
            signing_policy="required",
            encryption_policy="off",
            server_policy="samba:file-server",
            share_policy="disk:standard",
            client_access="cifs_mount",
        ),
    )


def _transport_plan(
    affinity: SmbChannelAffinity,
    *,
    ordinal: int,
    opened_at: datetime,
) -> NetworkTransactionPlan:
    """Build one immutable TCP/445 transport owned by the SMB manager workload."""

    duration = timedelta(minutes=20)
    closed_at = opened_at + duration
    stable_id = f"smb-long-transport-{ordinal:06d}"
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname=affinity.server_identity,
        outcome="success",
        phase_times=(("attempt", opened_at), ("close", closed_at)),
        started_at=opened_at,
        closed_at=closed_at,
        src_ip=affinity.client_ip,
        src_port=49_152 + ordinal,
        dst_ip=affinity.server_ip,
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=f"CSMBLONG{ordinal:06d}",
        conn_id=f"smb-long-connection-{ordinal:06d}",
        duration=duration.total_seconds(),
        conn_state="SF",
        history="ShADadfF",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=512, packets=3, ip_bytes=632),
            resp=DirectionalTrafficLedger(payload_bytes=2_048, packets=5, ip_bytes=2_248),
        ),
    )


@pytest.mark.slow
def test_31_day_smb_state_and_external_sorting_remain_bounded(tmp_path: Path) -> None:
    """A 31-day output keeps finalization memory independent of record count."""

    tracemalloc.start()
    seven_day_seconds, seven_day_buffer = _render_days(tmp_path / "seven-days.json", 7)
    _current, seven_day_peak = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    thirty_one_day_seconds, thirty_one_day_buffer = _render_days(
        tmp_path / "thirty-one-days.json", 31
    )
    _current, thirty_one_day_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert seven_day_buffer <= 1_000
    assert thirty_one_day_buffer <= 1_000
    assert thirty_one_day_peak <= seven_day_peak * 2.5 + 2 * 1024 * 1024
    assert thirty_one_day_seconds <= seven_day_seconds * 7 + 1.0
    with (tmp_path / "thirty-one-days.json").open(encoding="utf-8") as output:
        assert sum(1 for _line in output) == 31 * 24 * 100


@pytest.mark.slow
def test_31_day_mixed_windows_and_samba_state_remains_bounded() -> None:
    """Hourly SMB closure and daily common expiry plateau by day seven."""

    started_at = datetime(2024, 1, 1, tzinfo=UTC)
    window_end = started_at + timedelta(days=32)
    application = ApplicationChannelRegistry(
        window_start=started_at,
        window_end=window_end,
        closed_grace=timedelta(0),
    )
    manager = SmbApplicationChannelManager(
        application_registry=application,
        window_start=started_at,
        window_end=window_end,
    )
    affinities = _platform_affinities()
    process = psutil.Process()
    gc.collect()
    baseline_rss = process.memory_info().rss
    daily_snapshots: dict[int, tuple[SmbChannelCensus, int]] = {}
    max_hourly_candidate_work = 0
    max_application_expiry_entries = 0

    for hour in range(31 * _HOURS_PER_DAY):
        hour_started_at = started_at + timedelta(hours=hour)
        candidate_count_before = manager.census().lookup_candidates_inspected
        expected_channels: set[str] = set()
        for platform_index, affinity in enumerate(affinities):
            ordinal = hour * _PLATFORM_COUNT + platform_index + 1
            opened_at = hour_started_at + timedelta(microseconds=platform_index)
            transport = _transport_plan(
                affinity,
                ordinal=ordinal,
                opened_at=opened_at,
            )
            lease = manager.open_session(
                affinity,
                transport_plan=transport,
                sensor_observations=(),
                ground_truth_transport_uid=transport.zeek_uid,
                logon_id=f"0x{ordinal:016X}",
                auth_session_ref=f"smb-long-auth-{ordinal:06d}",
                principal=affinity.principal,
                auth_protocol=affinity.auth_protocol,
                account_scope=affinity.account_scope,
                effective_uid=None if platform_index == 0 else 1_001,
                effective_gid=None if platform_index == 0 else 1_001,
                client_access=affinity.client_access,
                server_hostname=affinity.server_identity,
                client_ip=affinity.client_ip,
                lifecycle_group_id=transport.stable_id,
                share_ref=f"{affinity.server_identity}.collaboration",
                semantic_operation_id=f"smb-long-operation-{ordinal:06d}",
                operation_started_at=opened_at + timedelta(seconds=10),
                operation_ended_at=opened_at + timedelta(seconds=11),
                operation_initiator_bytes=128,
                operation_responder_bytes=1_024,
                idle_timeout=timedelta(minutes=15),
                initiator_budget=4_096,
                responder_budget=16_384,
                operation_budget=8,
            )
            handle = manager.open_handle(
                lease,
                file_id=(f"{affinity.server_identity}-working-file-{hour % 64:02d}"),
                content_version=1,
                access="read",
                opened_at=lease.started_at + timedelta(milliseconds=100),
            )
            assert manager.close_handle(handle, lease, closed_at=lease.ended_at)
            assert manager.finalize_operation(lease)
            expected_channels.add(lease.channel_id)
            assert manager.session_view(lease.channel_id) is not None

        assert len(expected_channels) == _PLATFORM_COUNT
        frontier = hour_started_at + timedelta(hours=1)
        result = manager.watermark(frontier, limit=_PLATFORM_COUNT)
        assert not result.has_more
        assert {closure.channel_id for closure in result.closures} == expected_channels
        census = result.census
        assert census.open_sessions == 0
        assert census.open_trees == 0
        assert census.open_handles == 0
        assert census.session_backing_entries == 0
        assert census.expiry_entries == 0
        assert census.application.open_channels == 0
        assert census.application.active_operations == 0
        assert census.application.retained_channels <= _MAX_DAILY_CHANNELS
        max_application_expiry_entries = max(
            max_application_expiry_entries,
            census.application.expiry_entries,
        )
        hourly_candidate_work = census.lookup_candidates_inspected - candidate_count_before
        assert hourly_candidate_work >= _PLATFORM_COUNT
        assert hourly_candidate_work <= _PLATFORM_COUNT * _MAX_CANDIDATES_PER_PLATFORM
        max_hourly_candidate_work = max(max_hourly_candidate_work, hourly_candidate_work)

        if (hour + 1) % _HOURS_PER_DAY == 0:
            application.watermark(frontier)
            daily = manager.census()
            assert daily.open_sessions == 0
            assert daily.session_backing_entries == 0
            assert daily.expiry_entries == 0
            assert daily.application.retained_channels == 0
            assert daily.application.active_operations == 0
            assert daily.application.used_operation_ids == 0
            assert daily.application.route_entries == 0
            assert daily.application.expiry_entries == 0
            assert daily.application.route_compaction_pending == 0
            assert daily.application.store_primary_compaction_pending == 0
            day = (hour + 1) // _HOURS_PER_DAY
            if day in {7, 31}:
                gc.collect()
                daily_snapshots[day] = (daily, process.memory_info().rss)

    assert max_hourly_candidate_work >= _PLATFORM_COUNT
    assert max_hourly_candidate_work <= _PLATFORM_COUNT * _MAX_CANDIDATES_PER_PLATFORM
    assert 0 < max_application_expiry_entries
    assert max_application_expiry_entries <= _MAX_DAILY_CHANNELS * _MAX_EXPIRY_ENTRIES_PER_CHANNEL
    day_seven, day_seven_rss = daily_snapshots[7]
    day_thirty_one, day_thirty_one_rss = daily_snapshots[31]
    assert day_thirty_one.estimated_bytes <= day_seven.estimated_bytes * 1.1
    assert day_thirty_one.estimated_index_bytes <= day_seven.estimated_index_bytes * 1.1
    assert day_thirty_one_rss <= day_seven_rss * 1.1
    day_seven_rss_growth = max(0, day_seven_rss - baseline_rss)
    day_thirty_one_rss_growth = max(0, day_thirty_one_rss - baseline_rss)
    assert day_thirty_one_rss_growth <= max(
        day_seven_rss_growth * 1.1,
        _RSS_ALLOCATOR_SLACK_BYTES,
    )

    terminal = manager.census()
    assert terminal.open_sessions == 0
    assert terminal.open_trees == 0
    assert terminal.open_handles == 0
    assert terminal.session_backing_entries == 0
    assert terminal.tree_backing_entries == 0
    assert terminal.handle_backing_entries == 0
    assert terminal.stale_sidecar_entries == 0
    assert terminal.expiry_entries == 0
    assert terminal.stale_expiry_entries == 0
    assert terminal.primary_compaction_pending == 0
    assert terminal.application.retained_channels == 0
    assert terminal.application.open_channels == 0
    assert terminal.application.active_operations == 0
    assert terminal.application.used_operation_ids == 0
    assert terminal.application.prepared_admissions == 0
    assert terminal.application.claimed_admissions == 0
    assert terminal.application.reserved_channel_ids == 0
    assert terminal.application.reserved_transport_ids == 0
    assert terminal.application.reserved_operation_ids == 0
    assert terminal.application.route_entries == 0
    assert terminal.application.expiry_entries == 0
    assert terminal.application.stale_expiry_entries == 0
    assert terminal.application.route_compaction_pending == 0
    assert terminal.application.store_primary_compaction_pending == 0
