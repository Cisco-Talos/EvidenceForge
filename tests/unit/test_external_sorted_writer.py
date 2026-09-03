# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for bounded, atomic external line sorting."""

import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread

import pytest

from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationError,
    ExactPublicationKey,
)
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


def _key(line: str) -> tuple[int, str]:
    timestamp, _separator, _payload = line.partition("|")
    return int(timestamp), line


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("exact_journal_row_capacity", 0),
        ("exact_journal_row_capacity", True),
        ("exact_journal_byte_capacity", -1),
        ("exact_journal_byte_capacity", True),
    ],
)
def test_external_writer_rejects_unbounded_exact_capacity_values(
    tmp_path: Path,
    keyword: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="positive exact int"):
        ExternalSortedLineWriter(
            tmp_path / "invalid.log",
            sort_key=_key,
            **{keyword: value},  # type: ignore[arg-type]
        )


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


def test_checkpoint_mode_seals_only_new_runs_until_final_merge(tmp_path: Path) -> None:
    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(output, sort_key=_key, checkpoint_mode=True)

    writer.write("3|third")
    writer.write("1|first")
    writer.flush()
    first_count, first_sequence, first_runs = writer.checkpoint_snapshot()
    writer.checkpoint_committed()

    assert not output.exists()
    assert first_count == 2
    assert first_sequence == 1
    assert len(first_runs) == 1

    writer.write("2|second")
    writer.flush()
    second_count, second_sequence, second_runs = writer.checkpoint_snapshot()
    delta_count, delta_sequence, total_runs, delta_runs = writer.checkpoint_snapshot_since(
        len(first_runs)
    )

    assert not output.exists()
    assert second_count == 3
    assert second_sequence == 2
    assert second_runs[:1] == first_runs
    assert len(second_runs) == 2
    assert (delta_count, delta_sequence, total_runs) == (second_count, second_sequence, 2)
    assert delta_runs == second_runs[1:]

    writer.close()
    assert output.read_text(encoding="utf-8").splitlines() == [
        "1|first",
        "2|second",
        "3|third",
    ]


def test_deferred_publication_compacts_runs_without_rewriting_destination(tmp_path: Path) -> None:
    output = tmp_path / "deferred.json"
    writer = ExternalSortedLineWriter(
        output,
        sort_key=_key,
        merge_fan_in=2,
        defer_publication=True,
    )

    for value in reversed(range(7)):
        writer.write(f"{value}|record-{value}")
        writer.flush()

    assert not output.exists()
    assert len(writer._run_paths) <= writer.merge_fan_in
    writer.close()
    assert output.read_text(encoding="utf-8").splitlines() == [
        f"{value}|record-{value}" for value in range(7)
    ]


def test_checkpoint_mode_restores_immutable_runs_into_fresh_writer(tmp_path: Path) -> None:
    source = ExternalSortedLineWriter(
        tmp_path / "source.log",
        sort_key=_key,
        checkpoint_mode=True,
    )
    source.write("3|third")
    source.write("1|first")
    source.flush()
    event_count, run_sequence, source_runs = source.checkpoint_snapshot()

    restored_output = tmp_path / "restored.log"
    restored = ExternalSortedLineWriter(
        restored_output,
        sort_key=_key,
        checkpoint_mode=True,
    )
    restored_spool = tmp_path / "restored-runs"
    restored_spool.mkdir()
    restored_runs = tuple(restored_spool / path.name for path in source_runs)
    for source_path, restored_path in zip(source_runs, restored_runs, strict=True):
        shutil.copyfile(source_path, restored_path)
    restored.restore_checkpoint_runs(
        paths=restored_runs,
        event_count=event_count,
        run_sequence=run_sequence,
    )
    restored.write("2|second")
    restored.close()

    assert restored_output.read_text(encoding="utf-8").splitlines() == [
        "1|first",
        "2|second",
        "3|third",
    ]
    source.close()


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

    original_merge = writer._merge_runs_unlocked
    fail_once = True

    def fail_merge(paths: object, destination: object) -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise OSError("injected merge failure")
        original_merge(paths, destination)

    monkeypatch.setattr(writer, "_merge_runs_unlocked", fail_merge)

    with pytest.raises(OSError, match="injected merge failure"):
        writer.close()

    assert output.read_text(encoding="utf-8") == "previous\n"
    assert list(tmp_path.glob(".zeek.json.sort-*"))
    assert not list(tmp_path.glob(".zeek.json.*.merging"))

    writer.close()

    assert output.read_text(encoding="utf-8").splitlines() == ["1|new", "2|new"]
    assert not list(tmp_path.glob(".zeek.json.sort-*"))
    assert not list(tmp_path.glob(".zeek.json.*.merging"))


def test_exact_sorted_admission_reconciles_lost_return_and_export_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Journal admission and final export each resume without duplicating one exact row."""

    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(output, sort_key=_key, buffer_size=1)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    original_commit = writer._commit_exact_row
    fail_after_admission = True

    def admit_then_raise(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal fail_after_admission
        original_commit(key, digest, frozen)
        if fail_after_admission:
            fail_after_admission = False
            raise RuntimeError("journal admitted before lost return")

    monkeypatch.setattr(writer, "_commit_exact_row", admit_then_raise)
    batch.prepare(lambda: writer.write("2|exact"))
    census = writer.exact_journal_census()
    assert census.reserved_rows == 1
    assert census.pending_export_rows == 0
    assert not output.exists()

    with pytest.raises(RuntimeError, match="lost return"):
        batch.commit()
    assert writer.exact_journal_census().pending_export_rows == 1
    batch.commit()
    batch.release_no_fail()
    assert writer.exact_journal_census().live_receipts == 0

    original_export = writer._publish_runs_unlocked
    fail_after_export = True

    def export_then_raise() -> None:
        nonlocal fail_after_export
        original_export()
        if fail_after_export:
            fail_after_export = False
            raise RuntimeError("output replaced before lost return")

    monkeypatch.setattr(writer, "_publish_runs_unlocked", export_then_raise)
    with pytest.raises(RuntimeError, match="output replaced"):
        writer.flush()
    assert output.read_text(encoding="utf-8").splitlines() == ["2|exact"]
    assert writer.exact_journal_census().pending_export_rows == 1

    writer.flush()
    assert output.read_text(encoding="utf-8").splitlines() == ["2|exact"]
    assert writer.exact_journal_census().pending_export_rows == 0
    writer.close()


def test_exact_sorted_capacity_retires_only_after_receipt_and_export(
    tmp_path: Path,
) -> None:
    """Pending/exported metadata remains charged until both terminal conditions hold."""

    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(
        output,
        sort_key=_key,
        exact_journal_row_capacity=1,
    )
    authority = ExactPublicationAuthority(capacity=2)
    first = authority.issue_batch()
    second = authority.issue_batch()

    first.prepare(lambda: writer.write("2|first"))
    first.commit()
    # Receipt release alone cannot retire a row whose export journal is pending.
    first.release_no_fail()
    with pytest.raises(ExactPublicationError, match="row capacity"):
        second.prepare(lambda: writer.write("1|second"))
    assert not output.exists()
    assert writer.exact_journal_census().pending_export_rows == 1

    with pytest.raises(ExactPublicationError, match="row capacity"):
        second.prepare(lambda: writer.write("1|second"))

    writer.flush()
    exported = writer.exact_journal_census()
    assert exported.pending_export_rows == 0
    assert exported.admitted_rows == exported.admitted_bytes == 0
    assert exported.high_water_rows == 1
    assert exported.high_water_bytes > len("2|first\n")

    second.prepare(lambda: writer.write("1|second"))
    second.commit()
    second.release_no_fail()
    writer.close()
    assert output.read_text(encoding="utf-8").splitlines() == ["1|second", "2|first"]


def test_exact_sorted_exported_metadata_returns_to_baseline_across_cycles(
    tmp_path: Path,
) -> None:
    """Repeated exact cycles retain one baseline run and no per-row metadata growth."""

    writer = ExternalSortedLineWriter(
        tmp_path / "bounded.log",
        sort_key=_key,
        exact_journal_row_capacity=1,
    )
    authority = ExactPublicationAuthority(capacity=1)
    for value in range(200):
        batch = authority.issue_batch()
        batch.publish(lambda value=value: writer.write(f"{value}|row-{value}"))
        batch.release_no_fail()
        writer.flush()
        census = writer.exact_journal_census()
        assert census.admitted_rows == 0
        assert census.admitted_bytes == 0
        assert census.pending_export_rows == 0
        assert census.reserved_rows == 0
        assert census.live_receipts == 0

    census = writer.exact_journal_census()
    assert census.high_water_rows == 1
    assert census.high_water_bytes > len("0|row-0\n")
    assert len(writer._exact_journal) == 0
    assert writer._run_paths == [writer.output_path]
    writer.close()


def test_exact_sorted_export_stays_charged_until_live_receipt_releases(
    tmp_path: Path,
) -> None:
    """Export alone cannot hide a still-live exact key/receipt from capacity."""

    writer = ExternalSortedLineWriter(
        tmp_path / "receipt.log",
        sort_key=_key,
        exact_journal_row_capacity=1,
    )
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: writer.write("1|row"))
    writer.flush()
    exported = writer.exact_journal_census()
    assert exported.pending_export_rows == 0
    assert exported.admitted_rows == exported.live_receipts == 1
    assert exported.admitted_bytes > len("1|row\n")

    batch.release_no_fail()
    released = writer.exact_journal_census()
    assert released.admitted_rows == released.admitted_bytes == 0
    assert released.live_receipts == 0
    writer.close()


def test_exact_sorted_reservation_is_charged_before_allocation_and_rolls_back(
    tmp_path: Path,
) -> None:
    """A reservation allocation fault sees its charge and leaves no active capacity."""

    writer = ExternalSortedLineWriter(tmp_path / "allocation.log", sort_key=_key)
    observed: list[tuple[int, int]] = []

    class FailingReservations(dict[ExactPublicationKey, tuple[str, int, int]]):
        def __setitem__(
            self,
            key: ExactPublicationKey,
            value: tuple[str, int, int],
        ) -> None:
            del key, value
            observed.append((writer._exact_reserved_rows, writer._exact_reserved_bytes))
            raise MemoryError("reservation allocation failed")

    writer._exact_capacity_reservations = FailingReservations()
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    with pytest.raises(MemoryError, match="reservation allocation failed"):
        batch.prepare(lambda: writer.write("1|row"))

    assert observed and observed[0][0] == 1 and observed[0][1] > len("1|row\n")
    census = writer.exact_journal_census()
    assert census.reserved_rows == census.reserved_bytes == 0
    assert census.admitted_rows == census.admitted_bytes == 0
    assert not writer._active_exact_publication_keys
    batch.cancel()
    writer.close()


def test_exact_sorted_close_waits_for_prepared_admission(tmp_path: Path) -> None:
    """Sorted close cannot delete journal state while a prepared batch is unresolved."""

    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(output, sort_key=_key)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.prepare(lambda: writer.write("1|exact"))
    close_returned = Event()

    def close() -> None:
        writer.close()
        close_returned.set()

    thread = Thread(target=close)
    thread.start()
    assert not close_returned.wait(timeout=0.05)
    batch.commit()
    assert close_returned.wait(timeout=1)
    thread.join(timeout=1)
    batch.release_no_fail()
    assert output.read_text(encoding="utf-8").splitlines() == ["1|exact"]


def test_exact_sorted_atomic_rename_lost_return_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A destination rename that succeeds then raises is reconciled by identical export."""

    output = tmp_path / "zeek.json"
    writer = ExternalSortedLineWriter(output, sort_key=_key)
    batch = ExactPublicationAuthority(capacity=1).issue_batch()
    batch.publish(lambda: writer.write("1|exact"))
    batch.release_no_fail()
    original_replace = os.replace
    fail_after_destination = True

    def replace_then_raise(source: str | Path, destination: str | Path) -> None:
        nonlocal fail_after_destination
        original_replace(source, destination)
        if Path(destination) == output and fail_after_destination:
            fail_after_destination = False
            raise OSError("rename completed before lost return")

    monkeypatch.setattr(
        "evidenceforge.generation.emitters.sorted_writer.os.replace",
        replace_then_raise,
    )
    with pytest.raises(OSError, match="rename completed"):
        writer.flush()
    assert output.read_text(encoding="utf-8").splitlines() == ["1|exact"]
    assert writer.exact_journal_census().pending_export_rows == 1

    writer.flush()
    assert output.read_text(encoding="utf-8").splitlines() == ["1|exact"]
    assert writer.exact_journal_census().pending_export_rows == 0
    writer.close()


def test_external_sorted_output_is_stable_across_hash_seeds(tmp_path: Path) -> None:
    """Hash-dependent input iteration cannot change deterministic final bytes."""

    script = """
from pathlib import Path
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
output = Path(__import__('sys').argv[1])
writer = ExternalSortedLineWriter(
    output,
    sort_key=lambda line: (int(line.partition('|')[0]), line),
    buffer_size=2,
)
for line in {'2|beta', '1|alpha', '1|gamma', '3|delta'}:
    writer.write(line)
writer.close()
"""
    outputs: list[bytes] = []
    project_root = Path(__file__).resolve().parents[2]
    for seed in ("1", "777"):
        output = tmp_path / f"seed-{seed}.log"
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(project_root / "src")
        subprocess.run(
            [sys.executable, "-c", script, str(output)],
            check=True,
            cwd=project_root,
            env=environment,
        )
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]
