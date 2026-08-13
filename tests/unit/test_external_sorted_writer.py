# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for bounded, atomic external line sorting."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


def _key(line: str) -> tuple[int, str]:
    timestamp, _separator, _payload = line.partition("|")
    return int(timestamp), line


def test_external_writer_hierarchically_merges_more_than_fan_in_runs(tmp_path: Path) -> None:
    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(
        output,
        sort_key=_key,
        buffer_size=1,
        buffer_bytes=1024,
        merge_fan_in=3,
    )

    for value in reversed(range(25)):
        writer.write(f"{value % 5}|record-{value:02d}")
    writer.close()

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines == sorted(lines, key=_key)
    assert not list(tmp_path.glob(".zeek.json.sort-*"))
    assert not list(tmp_path.glob(".zeek.json.*.merging"))


def test_external_writer_flushes_at_byte_cap(tmp_path: Path) -> None:
    writer = ExternalSortedLineWriter(
        tmp_path / "zeek.json",
        sort_key=_key,
        buffer_size=100,
        buffer_bytes=8,
    )

    writer.write("2|payload")

    assert len(writer._run_paths) == 1
    assert writer._buffer == []
    writer.close()


def test_external_writer_is_thread_safe_and_deterministic(tmp_path: Path) -> None:
    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(output, sort_key=_key, buffer_size=7)
    records = [f"{index % 4}|record-{index:03d}" for index in range(120)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(writer.write, reversed(records)))
    writer.close()

    assert output.read_text(encoding="utf-8").splitlines() == sorted(records, key=_key)


def test_external_writer_preserves_prior_output_on_merge_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "zeek.json"
    output.write_text("previous\n", encoding="utf-8")
    writer = ExternalSortedLineWriter(output, sort_key=_key, buffer_size=1)
    writer.write("2|new")
    writer.write("1|new")

    def fail_merge(_paths: object, _destination: object) -> None:
        raise OSError("injected merge failure")

    monkeypatch.setattr(writer, "_merge_runs_unlocked", fail_merge)

    with pytest.raises(OSError, match="injected merge failure"):
        writer.close()

    assert output.read_text(encoding="utf-8") == "previous\n"
    assert not list(tmp_path.glob(".zeek.json.sort-*"))
    assert not list(tmp_path.glob(".zeek.json.*.merging"))
