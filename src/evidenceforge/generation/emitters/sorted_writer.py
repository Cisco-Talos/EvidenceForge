# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded external sorting for immutable newline-delimited output."""

from __future__ import annotations

import heapq
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from threading import Lock
from typing import Any, TextIO


class ExternalSortedLineWriter:
    """Write lines in deterministic global order with bounded resident memory."""

    def __init__(
        self,
        output_path: Path,
        *,
        sort_key: Callable[[str], Any],
        buffer_size: int = 10_000,
        buffer_bytes: int = 16 * 1024 * 1024,
        merge_fan_in: int = 64,
    ) -> None:
        if buffer_size <= 0:
            raise ValueError("buffer_size must be positive")
        if buffer_bytes <= 0:
            raise ValueError("buffer_bytes must be positive")
        if merge_fan_in < 2:
            raise ValueError("merge_fan_in must be at least 2")

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

    def write(self, rendered: str) -> None:
        """Buffer one record and spill when either memory cap is reached."""

        normalized = rendered[:-1] if rendered.endswith("\n") else rendered
        encoded_size = len(normalized.encode("utf-8")) + 1
        with self._lock:
            self._require_open()
            self._buffer.append(normalized)
            self._buffer_bytes += encoded_size
            self.event_count += 1
            if len(self._buffer) >= self.buffer_size or self._buffer_bytes >= self.buffer_bytes:
                self._spill_unlocked()

    def flush(self) -> None:
        """Seal the pending buffer as one immutable sorted run."""

        with self._lock:
            self._require_open()
            self._spill_unlocked()
            if len(self._run_paths) == 1 and not self.output_path.exists():
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                preview_path = self.output_path.with_name(f".{self.output_path.name}.preview")
                preview_path.unlink(missing_ok=True)
                os.link(self._run_paths[0], preview_path)
                os.replace(preview_path, self.output_path)

    def close(self) -> None:
        """Merge all runs and atomically publish the destination."""

        with self._lock:
            if self._closed:
                return
            merge_path: Path | None = None
            try:
                self._spill_unlocked()
                if not self._run_paths:
                    self._closed = True
                    return
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                descriptor, raw_merge_path = tempfile.mkstemp(
                    prefix=f".{self.output_path.name}.",
                    suffix=".merging",
                    dir=self.output_path.parent,
                )
                os.close(descriptor)
                merge_path = Path(raw_merge_path)
                self._merge_runs_unlocked(self._run_paths, merge_path)
                os.replace(merge_path, self.output_path)
                merge_path = None
                self._closed = True
            finally:
                if merge_path is not None:
                    merge_path.unlink(missing_ok=True)
                self._cleanup_spool_unlocked()

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("cannot write to a closed external sorted writer")

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
        self._compact_runs_unlocked()

    def _compact_runs_unlocked(self) -> None:
        while len(self._run_paths) > self.merge_fan_in:
            group = self._run_paths[: self.merge_fan_in]
            merged = self._next_run_path_unlocked()
            self._merge_runs_unlocked(group, merged)
            for path in group:
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
        if self._spool_dir is not None:
            shutil.rmtree(self._spool_dir, ignore_errors=True)
            self._spool_dir = None
