# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Base class for host-based emitters with per-host FQDN directory multiplexing.

Host-based logs (Windows events, eCAR, syslog) are organized by the originating
host's FQDN. Each host gets its own subdirectory:

    base_dir/<host-fqdn>/windows_event_security.xml
    base_dir/<host-fqdn>/ecar.json
    base_dir/<host-fqdn>/<year>/syslog.log
"""

import logging
from collections.abc import Callable
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)


# Backward-compat alias so existing imports (tests, etc.) still work.
sanitize_host_routing_key = sanitize_path_component


class _SingleHostWriter:
    """Writes log output for one host. Thread-safe via lock."""

    def __init__(
        self,
        output_path: Path,
        buffer_size: int = 10000,
        sort_on_flush: bool = False,
        sort_key: Callable[[str], Any] | None = None,
        defer_sorted_flush_until_close: bool = False,
    ):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()
        self._header_written = False
        self._sort_on_flush = sort_on_flush
        self._sort_key = sort_key or (lambda line: line[:15])
        self._defer_sorted_flush_until_close = defer_sorted_flush_until_close

    def write(self, rendered: str) -> None:
        with self._lock:
            self.buffer.append(rendered)
            self.event_count += 1
            if not self._sort_on_flush and len(self.buffer) >= self.buffer_size:
                self._flush_unlocked()

    def write_header(self, header: str) -> None:
        """Write a header (e.g., XML root opening tag) before any events."""
        with self._lock:
            if not self._header_written:
                self.output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.output_path, "w", encoding="utf-8") as f:
                    f.write(header)
                    if not header.endswith("\n"):
                        f.write("\n")
                self._header_written = True

    def flush(self, force: bool = False) -> None:
        with self._lock:
            if self._sort_on_flush and self._defer_sorted_flush_until_close and not force:
                return
            self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        if not self.buffer:
            return
        if self._sort_on_flush:
            self.buffer.sort(key=self._sort_key)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()

    def write_footer(self, footer: str) -> None:
        """Write a footer (e.g., XML root closing tag) after all events."""
        self.flush(force=True)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(footer)
            if not footer.endswith("\n"):
                f.write("\n")


class HostMultiplexEmitter(LogEmitter):
    """Base class for host-based emitters with per-FQDN directory routing.

    Subclasses implement:
    - _render_event(): Convert event data to formatted string
    - can_handle(): Filter SecurityEvents
    - emit(): Extract host FQDN and call emit_to_host()
    """

    _log_filename: str = "output.log"
    _flat_filename: str = ""
    _supported_types: set[str] = set()
    _sort_flat_file: bool = False
    _sort_key: Callable[[str], Any] | None = None
    _defer_sorted_flush_until_close: bool = False

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        # Detect direct file mode (backward compat for tests)
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._writers: dict[str, _SingleHostWriter] = {}
        self._writers_lock = Lock()
        self._buffer_size = buffer_size
        super().__init__(format_def, output_path, buffer_size, threaded)

    def _safe_writer_key(self, host_fqdn: str) -> str:
        """Return the writer key for a routed host value."""
        return sanitize_path_component(host_fqdn)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        """Return the output path for a writer key."""
        if safe_writer_key and not self._direct_file_mode:
            return self._base_dir / safe_writer_key / self._log_filename
        if self._direct_file_path:
            return self._direct_file_path
        flat_name = self._flat_filename or self._log_filename
        return self._base_dir / flat_name

    def _get_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host_fqdn = self._safe_writer_key(host_fqdn)
        writer = self._writers.get(safe_host_fqdn)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(safe_host_fqdn)
            if writer is not None:
                return writer
            path = self._writer_path_for_key(safe_host_fqdn)
            sort = self._sort_flat_file
            writer = _SingleHostWriter(
                path,
                self._buffer_size,
                sort_on_flush=sort,
                sort_key=self._sort_key,
                defer_sorted_flush_until_close=self._defer_sorted_flush_until_close,
            )
            self._writers[safe_host_fqdn] = writer
            logger.debug(f"Created host writer: {path}")
            return writer

    def emit_to_host(self, rendered: str, host_fqdn: str = "") -> None:
        """Route a rendered line to the appropriate host writer."""
        self._get_writer(host_fqdn).write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _run(self) -> None:
        logger.debug(f"Emitter thread started for {self.format_def.name}")
        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                self._dispatch(event_data)
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    self.flush()
                    self._flush_barrier.clear()
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _buffer_event(self, rendered: str) -> None:
        """Override base class to route through default writer."""
        self._get_writer("").write(rendered)

    def flush(self, force: bool = False) -> None:
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush(force=force)

    def _flush_unlocked(self) -> None:
        pass

    def close(self) -> None:
        if self.threaded:
            self.stop_thread()
        self.flush(force=True)

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
