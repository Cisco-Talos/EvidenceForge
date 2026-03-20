"""Base class for host-based emitters with per-host FQDN directory multiplexing.

Host-based logs (Windows events, eCAR, syslog) are organized by the originating
host's FQDN. Each host gets its own subdirectory:

    base_dir/<host-fqdn>/windows_event_security.xml
    base_dir/<host-fqdn>/ecar.json
    base_dir/<host-fqdn>/syslog.log
"""

import logging
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter

logger = logging.getLogger(__name__)


class _SingleHostWriter:
    """Writes log output for one host. Thread-safe via lock."""

    def __init__(self, output_path: Path, buffer_size: int = 10000):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()
        self._header_written = False

    def write(self, rendered: str) -> None:
        with self._lock:
            self.buffer.append(rendered)
            self.event_count += 1
            if len(self.buffer) >= self.buffer_size:
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

    def flush(self) -> None:
        with self._lock:
            self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        if not self.buffer:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()

    def write_footer(self, footer: str) -> None:
        """Write a footer (e.g., XML root closing tag) after all events."""
        self.flush()
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

    def _get_writer(self, host_fqdn: str) -> _SingleHostWriter:
        writer = self._writers.get(host_fqdn)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(host_fqdn)
            if writer is not None:
                return writer
            if host_fqdn and not self._direct_file_mode:
                path = self._base_dir / host_fqdn / self._log_filename
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                flat_name = self._flat_filename or self._log_filename
                path = self._base_dir / flat_name
            writer = _SingleHostWriter(path, self._buffer_size)
            self._writers[host_fqdn] = writer
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
        host_fqdn = event_data.pop('_host_fqdn', '')
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

    def flush(self) -> None:
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush()

    def _flush_unlocked(self) -> None:
        pass

    def close(self) -> None:
        if self.threaded:
            self.stop_thread()
        self.flush()

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
