# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Slow bounded-state and output-finalization checks for canonical SMB."""

from __future__ import annotations

import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.storage_world import CompiledStorageFile


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


@pytest.mark.slow
def test_31_day_smb_state_and_external_sorting_remain_bounded(tmp_path: Path) -> None:
    """A 31-day workload keeps active state and finalization memory output-independent."""

    manager = StateManager()
    started_at = datetime(2024, 1, 1, tzinfo=UTC)
    working_set = tuple(
        CompiledStorageFile(
            file_id=f"working-file-{index}",
            share="FS-01.collaboration",
            path=f"Projects\\Working\\document-{index:02d}.docx",
            size_bytes=64_000 + index,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            tags=("working-set",),
        )
        for index in range(64)
    )
    max_sessions = 0
    max_trees = 0
    for hour in range(31 * 24):
        timestamp = started_at + timedelta(hours=hour)
        session = manager.open_smb_session(
            client_ip="10.0.1.10",
            principal="alice",
            server="FS-01",
            security_policy="standard",
            logon_id=f"0x{hour:016X}",
            transport_uid=f"C{hour:016d}",
            started_at=timestamp,
            reuse=True,
        )
        manager.get_or_open_smb_tree(session.session_id, "FS-01.collaboration", timestamp)
        manager.touch_smb_file(working_set[hour % len(working_set)])
        manager.sweep_smb_state(timestamp + timedelta(hours=2))
        summary = manager.get_state_summary()
        max_sessions = max(max_sessions, summary["smb_sessions"])
        max_trees = max(max_trees, summary["smb_trees"])

    summary = manager.get_state_summary()
    assert max_sessions <= 1
    assert max_trees <= 1
    assert summary["smb_sessions"] == 0
    assert summary["smb_trees"] == 0
    assert summary["smb_handles"] == 0
    assert summary["smb_mutations"] == len(working_set)

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
