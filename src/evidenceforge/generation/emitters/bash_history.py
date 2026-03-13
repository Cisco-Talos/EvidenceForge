"""Bash history emitter — writes per-user-per-host history files.

Real bash_history files are per-user-per-host with no metadata identifying
which user or host a command came from. This emitter multiplexes events
into separate files organized as: bash_history/<hostname>/<username>.bash_history
"""

import logging
from pathlib import Path
from threading import Lock
from typing import Any

from jinja2 import Template

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter

logger = logging.getLogger(__name__)


class _SingleHistoryWriter:
    """Writes bash history for one (user, host) pair. Not threaded."""

    def __init__(self, output_path: Path, template: Template, buffer_size: int = 10000):
        self.output_path = output_path
        self._template = template
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0

    def write(self, event_data: dict[str, Any]) -> None:
        context = {
            'timestamp': event_data.get('timestamp'),
            'command': event_data.get('command'),
        }
        rendered = self._template.render(**context).strip()
        self.buffer.append(rendered)
        self.event_count += 1
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()


class BashHistoryEmitter(LogEmitter):
    """Multiplexing emitter that writes per-user-per-host bash history files.

    Maintains a dict of _SingleHistoryWriter instances keyed by (username, hostname).
    The parent thread consumes from the queue; dispatch happens in _run().
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        # output_path is the base directory (e.g., output_dir/bash_history)
        self._base_dir = output_path
        self._writers: dict[tuple[str, str], _SingleHistoryWriter] = {}
        self._writers_lock = Lock()
        self._buffer_size = buffer_size
        super().__init__(format_def, output_path, buffer_size, threaded)

    def _get_writer(self, username: str, hostname: str) -> _SingleHistoryWriter:
        key = (username, hostname)
        writer = self._writers.get(key)
        if writer is not None:
            return writer
        with self._writers_lock:
            # Double-check after acquiring lock
            writer = self._writers.get(key)
            if writer is not None:
                return writer
            path = self._base_dir / hostname / f"{username}.bash_history"
            writer = _SingleHistoryWriter(path, self._template, self._buffer_size)
            self._writers[key] = writer
            logger.debug(f"Created bash_history writer: {path}")
            return writer

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            self._dispatch(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Not used directly — dispatch handles rendering via sub-writers."""
        # Required by ABC but we override _run() to use _dispatch instead
        raise NotImplementedError("BashHistoryEmitter uses _dispatch, not _render_event")

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        username = event_data.get('username', 'unknown')
        hostname = event_data.get('hostname', 'unknown')
        writer = self._get_writer(username, hostname)
        writer.write(event_data)

    def _run(self) -> None:
        """Thread run loop — dispatch events to per-user-per-host writers."""
        from queue import Empty

        logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                self._dispatch(event_data)
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    logger.debug(f"Flushing {self.format_def.name} emitter at barrier")
                    self.flush()
                    self._flush_barrier.clear()

        logger.debug(f"Emitter thread stopping for {self.format_def.name}, final flush")
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def flush(self) -> None:
        """Flush all sub-writers."""
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush()

    def _flush_unlocked(self) -> None:
        """Override to prevent base class from writing to the single output_path."""
        pass

    def close(self) -> None:
        """Close emitter and flush all sub-writers."""
        if self.threaded:
            self.stop_thread()
        self.flush()

    @property
    def event_count(self) -> int:
        """Total events across all writers."""
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        # Base class sets this to 0 in __init__; ignore it
        pass
