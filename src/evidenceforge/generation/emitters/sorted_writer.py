# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded external sorting for immutable newline-delimited output."""

from __future__ import annotations

import heapq
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Condition, Lock, get_ident
from typing import Any, TextIO

from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationKey,
    ExactPublicationParticipantKey,
    fsync_directory,
    stage_exact_publication_row,
)


@dataclass(frozen=True, slots=True)
class ExternalSortedJournalCensus:
    """Bounded exact-row journal admission and export counts."""

    admitted_rows: int
    admitted_bytes: int
    pending_export_rows: int
    pending_export_bytes: int
    reserved_rows: int
    reserved_bytes: int
    live_receipts: int
    row_capacity: int
    byte_capacity: int
    high_water_rows: int
    high_water_bytes: int
    export_generation: int


@dataclass(slots=True)
class _ExternalSortedExactRow:
    """One immutable journal run retained independently from its live receipt."""

    digest: str
    path: Path
    payload_bytes: int
    capacity_bytes: int
    exported_generation: int = 0
    receipt_released: bool = False


class ExternalSortedLineWriter:
    """Write lines in deterministic global order with bounded resident memory."""

    # Conservative charge for the reservation entry, exact key/digest, journal
    # record, Path/list slot, receipt entry, integer fields, and allocator slack.
    _EXACT_ROW_METADATA_BYTES = 1_024

    def __init__(
        self,
        output_path: Path,
        *,
        sort_key: Callable[[str], Any],
        buffer_size: int = 10_000,
        buffer_bytes: int = 16 * 1024 * 1024,
        merge_fan_in: int = 64,
        exact_journal_row_capacity: int = 1_000_000,
        exact_journal_byte_capacity: int = 4 * 1024 * 1024 * 1024,
        checkpoint_mode: bool = False,
    ) -> None:
        if buffer_size <= 0:
            raise ValueError("buffer_size must be positive")
        if buffer_bytes <= 0:
            raise ValueError("buffer_bytes must be positive")
        if merge_fan_in < 2:
            raise ValueError("merge_fan_in must be at least 2")
        if type(exact_journal_row_capacity) is not int or exact_journal_row_capacity <= 0:
            raise ValueError("exact_journal_row_capacity must be a positive exact int")
        if type(exact_journal_byte_capacity) is not int or exact_journal_byte_capacity <= 0:
            raise ValueError("exact_journal_byte_capacity must be a positive exact int")

        self.output_path = output_path
        self.buffer_size = buffer_size
        self.buffer_bytes = buffer_bytes
        self.merge_fan_in = merge_fan_in
        self.event_count = 0
        self._sort_key = sort_key
        self._buffer: list[str] = []
        self._buffer_bytes = 0
        self._run_paths: list[Path] = []
        self._spool_dir: Path | None = None
        self._run_sequence = 0
        self._closed = False
        self._lock = Lock()
        self._exact_publication_receipts: dict[ExactPublicationKey, str] = {}
        self._exact_journal: dict[ExactPublicationKey, _ExternalSortedExactRow] = {}
        self._exact_capacity_reservations: dict[ExactPublicationKey, tuple[str, int, int]] = {}
        self._exact_journal_row_capacity = exact_journal_row_capacity
        self._exact_journal_byte_capacity = exact_journal_byte_capacity
        self._exact_admitted_bytes = 0
        self._exact_admitted_rows = 0
        self._exact_pending_rows = 0
        self._exact_pending_bytes = 0
        self._exact_reserved_rows = 0
        self._exact_reserved_bytes = 0
        self._exact_high_water_rows = 0
        self._exact_high_water_bytes = 0
        self._exact_export_generation = 0
        self._checkpoint_mode = checkpoint_mode
        self._exact_publication_condition = Condition(Lock())
        self._active_exact_publication_keys: set[ExactPublicationParticipantKey] = set()
        self._close_state = "open"
        self._close_thread: int | None = None
        self._exported_run_count = 0

    def write(self, rendered: str) -> None:
        """Buffer one record and spill when either memory cap is reached."""

        if stage_exact_publication_row(
            self,
            rendered,
            publish=self._commit_exact_row,
            release=self._release_exact_row,
        ):
            return
        normalized = rendered[:-1] if rendered.endswith("\n") else rendered
        encoded_size = len(normalized.encode("utf-8")) + 1
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
            self._require_open_locked()
            with self._lock:
                self._buffer.append(normalized)
                self._buffer_bytes += encoded_size
                self.event_count += 1
                if len(self._buffer) >= self.buffer_size or self._buffer_bytes >= self.buffer_bytes:
                    self._spill_unlocked()

    def _commit_exact_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        if type(frozen) is not str:
            raise ExactPublicationError("Exact sorted row must retain one exact str")
        rendered = frozen
        normalized = rendered[:-1] if rendered.endswith("\n") else rendered
        payload = f"{normalized}\n".encode()
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact sorted row lost its writer fence")
            with self._lock:
                retained = self._exact_publication_receipts.get(key)
                if retained is not None:
                    if retained != digest:
                        raise ExactPublicationError("Exact sorted publication row changed on retry")
                    return
                journal_row = self._exact_journal.get(key)
                if journal_row is not None:
                    if journal_row.digest != digest or journal_row.path.read_bytes() != payload:
                        raise ExactPublicationError(
                            "Exact sorted publication journal changed content"
                        )
                    self._exact_publication_receipts[key] = digest
                    self._consume_exact_capacity_reservation_unlocked(
                        key,
                        digest,
                        admit=True,
                    )
                    return
                reservation = self._exact_capacity_reservations.get(key)
                if reservation is None or reservation[0] != digest:
                    raise ExactPublicationError(
                        "Exact sorted row lost its prepared journal capacity"
                    )
                _reserved_digest, _payload_bytes, capacity_bytes = reservation
                spool_dir = self._ensure_spool_dir_unlocked()
                namespace, ordinal, cursor = key
                run_path = spool_dir / (f"exact-{namespace}-{ordinal:016x}-{cursor:08x}.ndjson")
                if run_path.exists():
                    if run_path.read_bytes() != payload:
                        raise ExactPublicationError(
                            "Exact sorted publication journal changed content"
                        )
                else:
                    descriptor, raw_pending = tempfile.mkstemp(
                        prefix=f".{run_path.name}.",
                        suffix=".pending",
                        dir=spool_dir,
                    )
                    pending = Path(raw_pending)
                    try:
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(payload)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(pending, run_path)
                        fsync_directory(spool_dir)
                    except BaseException:
                        pending.unlink(missing_ok=True)
                        raise
                if run_path not in self._run_paths:
                    self._run_paths.append(run_path)
                self.event_count += 1
                self._exact_journal[key] = _ExternalSortedExactRow(
                    digest=digest,
                    path=run_path,
                    payload_bytes=len(payload),
                    capacity_bytes=capacity_bytes,
                )
                self._exact_pending_rows += 1
                self._exact_pending_bytes += len(payload)
                self._exact_publication_receipts[key] = digest
                self._consume_exact_capacity_reservation_unlocked(
                    key,
                    digest,
                    admit=True,
                )

    def _release_exact_row(self, key: ExactPublicationKey) -> None:
        with self._lock:
            self._exact_publication_receipts.pop(key, None)
            journal_row = self._exact_journal.get(key)
            if journal_row is None:
                return
            journal_row.receipt_released = True
            if journal_row.exported_generation:
                self._retire_exact_row_unlocked(key, journal_row)

    def _reserve_exact_publication_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Reserve journal capacity during render, before canonical owner mutation."""

        capacity_bytes = self._exact_row_capacity_bytes(key, digest, retained_bytes)
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact sorted reservation lost its writer fence")
            with self._lock:
                retained = self._exact_capacity_reservations.get(key)
                if retained is not None:
                    if retained != (digest, retained_bytes, capacity_bytes):
                        raise ExactPublicationError(
                            "Exact sorted prepared row changed before admission"
                        )
                    return
                if (
                    self._exact_admitted_rows + self._exact_reserved_rows + 1
                    > self._exact_journal_row_capacity
                ):
                    raise ExactPublicationError("Exact sorted journal row capacity is exhausted")
                if (
                    self._exact_admitted_bytes + self._exact_reserved_bytes + capacity_bytes
                    > self._exact_journal_byte_capacity
                ):
                    raise ExactPublicationError("Exact sorted journal byte capacity is exhausted")
                # Charge the reservation and every future retained structure before
                # allocating the reservation dictionary entry.
                self._exact_reserved_rows += 1
                self._exact_reserved_bytes += capacity_bytes
                self._update_exact_high_water_unlocked()
                try:
                    self._exact_capacity_reservations[key] = (
                        digest,
                        retained_bytes,
                        capacity_bytes,
                    )
                except BaseException:
                    self._exact_reserved_rows -= 1
                    self._exact_reserved_bytes -= capacity_bytes
                    raise

    def _exact_row_capacity_bytes(
        self,
        key: ExactPublicationKey,
        digest: str,
        payload_bytes: int,
    ) -> int:
        """Return a conservative deterministic charge for all retained row state."""

        namespace, ordinal, cursor = key
        identity_bytes = len(namespace.encode("utf-8")) + len(digest.encode("ascii"))
        path_bytes = len(os.fsencode(self.output_path)) + len(
            f"exact-{namespace}-{ordinal:016x}-{cursor:08x}.ndjson".encode()
        )
        return payload_bytes + identity_bytes + path_bytes + self._EXACT_ROW_METADATA_BYTES

    def _update_exact_high_water_unlocked(self) -> None:
        retained_rows = self._exact_admitted_rows + self._exact_reserved_rows
        retained_bytes = self._exact_admitted_bytes + self._exact_reserved_bytes
        self._exact_high_water_rows = max(self._exact_high_water_rows, retained_rows)
        self._exact_high_water_bytes = max(self._exact_high_water_bytes, retained_bytes)

    def _consume_exact_capacity_reservation_unlocked(
        self,
        key: ExactPublicationKey,
        digest: str,
        *,
        admit: bool = False,
    ) -> None:
        reservation = self._exact_capacity_reservations.pop(key, None)
        if reservation is None:
            return
        reserved_digest, _payload_bytes, capacity_bytes = reservation
        if reserved_digest != digest:
            raise ExactPublicationError("Exact sorted capacity reservation changed")
        self._exact_reserved_rows -= 1
        self._exact_reserved_bytes -= capacity_bytes
        if admit:
            self._exact_admitted_rows += 1
            self._exact_admitted_bytes += capacity_bytes
        self._update_exact_high_water_unlocked()

    def _clear_exact_capacity_reservations_unlocked(
        self,
        participant_key: ExactPublicationParticipantKey,
    ) -> None:
        keys = [key for key in self._exact_capacity_reservations if key[:2] == participant_key]
        for key in keys:
            _digest, _payload_bytes, capacity_bytes = self._exact_capacity_reservations.pop(key)
            self._exact_reserved_rows -= 1
            self._exact_reserved_bytes -= capacity_bytes

    def flush(self) -> None:
        """Seal the pending buffer as one immutable sorted run."""

        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
            self._require_open_locked()
            with self._lock:
                self._spill_unlocked()
                if self._checkpoint_mode:
                    return
                self._publish_runs_unlocked()
                self._mark_exact_rows_exported_unlocked()
                self._normalize_exported_runs_unlocked()

    def close(self) -> None:
        """Merge all runs and atomically publish the destination."""

        owner_thread = get_ident()
        with self._exact_publication_condition:
            while self._close_state == "closing":
                if self._close_thread == owner_thread:
                    raise RuntimeError("External sorted writer close cannot be re-entered")
                self._exact_publication_condition.wait()
            if self._close_state == "closed":
                return
            self._close_state = "closing"
            self._close_thread = owner_thread
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()
        try:
            with self._lock:
                self._spill_unlocked()
                if self._run_paths:
                    self._compact_runs_unlocked()
                    self._publish_runs_unlocked()
                    self._mark_exact_rows_exported_unlocked()
                    self._normalize_exported_runs_unlocked()
                self._cleanup_spool_unlocked()
        except BaseException:
            with self._exact_publication_condition:
                self._close_state = "open"
                self._close_thread = None
                self._exact_publication_condition.notify_all()
            raise
        with self._exact_publication_condition:
            if self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "External sorted writer cannot close with unresolved exact rows"
                )
            self._closed = True
            self._close_state = "closed"
            self._close_thread = None
            self._exact_publication_condition.notify_all()

    def checkpoint_snapshot(self) -> tuple[int, int, tuple[Path, ...]]:
        """Return the immutable run set after a checkpoint-mode barrier."""

        if not self._checkpoint_mode:
            raise RuntimeError("external sorted writer is not in checkpoint mode")
        with self._exact_publication_condition:
            if self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "External sorted checkpoint retains an exact publication"
                )
            with self._lock:
                if self._buffer:
                    raise RuntimeError("external sorted checkpoint retains an unsealed buffer")
                return self.event_count, self._run_sequence, tuple(self._run_paths)

    def checkpoint_committed(self) -> None:
        """Retire exact row journals after their immutable runs become durable."""

        if not self._checkpoint_mode:
            raise RuntimeError("external sorted writer is not in checkpoint mode")
        with self._lock:
            self._mark_exact_rows_exported_unlocked()

    def restore_checkpoint_runs(
        self,
        *,
        paths: tuple[Path, ...],
        event_count: int,
        run_sequence: int,
    ) -> None:
        """Install validated immutable runs into a fresh checkpoint-mode writer."""

        if not self._checkpoint_mode:
            raise RuntimeError("external sorted writer is not in checkpoint mode")
        if event_count < 0 or run_sequence < 0:
            raise ValueError("external sorted checkpoint counters cannot be negative")
        with self._exact_publication_condition:
            with self._lock:
                if self._buffer or self._run_paths or self.event_count or self._run_sequence:
                    raise RuntimeError("external sorted writer is not fresh during recovery")
                self._run_paths = list(paths)
                self.event_count = event_count
                self._run_sequence = run_sequence
                self._spool_dir = paths[0].parent if paths else None

    def _publish_runs_unlocked(self) -> None:
        """Atomically export every admitted run without consuming journal truth."""

        if not self._run_paths:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_merge_path = tempfile.mkstemp(
            prefix=f".{self.output_path.name}.",
            suffix=".merging",
            dir=self.output_path.parent,
        )
        os.close(descriptor)
        merge_path = Path(raw_merge_path)
        try:
            self._merge_runs_unlocked(self._run_paths, merge_path)
            with merge_path.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(merge_path, self.output_path)
            fsync_directory(self.output_path.parent)
            self._exported_run_count = len(self._run_paths)
        except BaseException:
            merge_path.unlink(missing_ok=True)
            raise

    def _mark_exact_rows_exported_unlocked(self) -> None:
        """Advance export receipts only after the atomic destination replacement returns."""

        self._exact_export_generation += 1
        released: list[tuple[ExactPublicationKey, _ExternalSortedExactRow]] = []
        for key, journal_row in self._exact_journal.items():
            if journal_row.exported_generation:
                continue
            journal_row.exported_generation = self._exact_export_generation
            self._exact_pending_rows -= 1
            self._exact_pending_bytes -= journal_row.payload_bytes
            if journal_row.receipt_released:
                released.append((key, journal_row))
        for key, journal_row in released:
            self._retire_exact_row_unlocked(key, journal_row)

    def _retire_exact_row_unlocked(
        self,
        key: ExactPublicationKey,
        journal_row: _ExternalSortedExactRow,
    ) -> None:
        """Uncharge one row only after both exact receipt and export are terminal."""

        if self._exact_journal.get(key) is not journal_row:
            raise ExactPublicationError("Exact sorted journal changed during retirement")
        self._exact_journal.pop(key)
        self._exact_admitted_rows -= 1
        self._exact_admitted_bytes -= journal_row.capacity_bytes

    def _normalize_exported_runs_unlocked(self) -> None:
        """Collapse exported inputs to the destination as one bounded baseline run."""

        if not self._run_paths or not self.output_path.exists():
            return
        for path in self._run_paths:
            if path != self.output_path:
                path.unlink(missing_ok=True)
        self._run_paths = [self.output_path]

    def exact_journal_census(self) -> ExternalSortedJournalCensus:
        """Return O(1) admission/export capacity counts."""

        with self._lock:
            return ExternalSortedJournalCensus(
                admitted_rows=self._exact_admitted_rows,
                admitted_bytes=self._exact_admitted_bytes,
                pending_export_rows=self._exact_pending_rows,
                pending_export_bytes=self._exact_pending_bytes,
                reserved_rows=self._exact_reserved_rows,
                reserved_bytes=self._exact_reserved_bytes,
                live_receipts=len(self._exact_publication_receipts),
                row_capacity=self._exact_journal_row_capacity,
                byte_capacity=self._exact_journal_byte_capacity,
                high_water_rows=self._exact_high_water_rows,
                high_water_bytes=self._exact_high_water_bytes,
                export_generation=self._exact_export_generation,
            )

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("cannot write to a closed external sorted writer")

    def _require_open_locked(self) -> None:
        if self._close_state != "open":
            raise RuntimeError("cannot write to a closed external sorted writer")

    def _register_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        with self._exact_publication_condition:
            foreign = self._active_exact_publication_keys - {key}
            if foreign:
                raise ExactPublicationError(
                    "External sorted writer already has an unresolved exact publication"
                )
            if self._close_state != "open" and key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "External sorted writer is closing or closed during exact publication"
                )
            self._active_exact_publication_keys.add(key)

    def _complete_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        with self._exact_publication_condition:
            with self._lock:
                self._clear_exact_capacity_reservations_unlocked(key)
            self._active_exact_publication_keys.discard(key)
            self._exact_publication_condition.notify_all()

    def _abort_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        self._complete_exact_publication_batch(key)

    def _wait_for_exact_publications(self) -> None:
        with self._exact_publication_condition:
            while self._active_exact_publication_keys:
                self._exact_publication_condition.wait()

    def _ensure_spool_dir_unlocked(self) -> Path:
        if self._spool_dir is None:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self._spool_dir = Path(
                tempfile.mkdtemp(
                    prefix=f".{self.output_path.name}.sort-",
                    dir=self.output_path.parent,
                )
            )
        return self._spool_dir

    def _next_run_path_unlocked(self) -> Path:
        path = self._ensure_spool_dir_unlocked() / f"run-{self._run_sequence:08d}.ndjson"
        self._run_sequence += 1
        return path

    def _spill_unlocked(self) -> None:
        if not self._buffer:
            return
        self._buffer.sort(key=self._sort_key)
        run_path = self._next_run_path_unlocked()
        with run_path.open("w", encoding="utf-8", newline="\n") as stream:
            for line in self._buffer:
                stream.write(line)
                stream.write("\n")
        self._run_paths.append(run_path)
        self._buffer.clear()
        self._buffer_bytes = 0
        if not self._checkpoint_mode:
            self._compact_runs_unlocked()

    def _compact_runs_unlocked(self) -> None:
        while len(self._run_paths) > self.merge_fan_in:
            group = self._run_paths[: self.merge_fan_in]
            merged = self._next_run_path_unlocked()
            self._merge_runs_unlocked(group, merged)
            for path in group:
                if path != self.output_path:
                    path.unlink(missing_ok=True)
            self._run_paths = [merged, *self._run_paths[self.merge_fan_in :]]

    @staticmethod
    def _read_line(stream: TextIO) -> str | None:
        line = stream.readline()
        if not line:
            return None
        return line[:-1] if line.endswith("\n") else line

    def _iter_merged_lines(self, paths: Sequence[Path]) -> Iterator[str]:
        streams: list[TextIO] = []
        heap: list[tuple[Any, int, str]] = []
        try:
            for index, path in enumerate(paths):
                stream = path.open("r", encoding="utf-8")
                streams.append(stream)
                line = self._read_line(stream)
                if line is not None:
                    heapq.heappush(heap, (self._sort_key(line), index, line))
            while heap:
                _key, index, line = heapq.heappop(heap)
                yield line
                next_line = self._read_line(streams[index])
                if next_line is not None:
                    heapq.heappush(heap, (self._sort_key(next_line), index, next_line))
        finally:
            for stream in streams:
                stream.close()

    def _merge_runs_unlocked(self, paths: Sequence[Path], destination: Path) -> None:
        with destination.open("w", encoding="utf-8", newline="\n") as stream:
            for line in self._iter_merged_lines(paths):
                stream.write(line)
                stream.write("\n")

    def _cleanup_spool_unlocked(self) -> None:
        self._run_paths.clear()
        self._exact_journal.clear()
        self._exact_admitted_bytes = 0
        self._exact_admitted_rows = 0
        self._exact_pending_rows = 0
        self._exact_pending_bytes = 0
        self._exact_capacity_reservations.clear()
        self._exact_reserved_rows = 0
        self._exact_reserved_bytes = 0
        if self._spool_dir is not None:
            shutil.rmtree(self._spool_dir, ignore_errors=True)
            self._spool_dir = None
