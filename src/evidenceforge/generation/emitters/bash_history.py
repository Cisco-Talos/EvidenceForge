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

"""Bash history emitter — writes per-user-per-host history files.

Real bash_history files are per-user-per-host with no metadata identifying
which user or host a command came from. This emitter multiplexes events
into separate files organized as: bash_history/<hostname>/<username>.bash_history
"""

import logging
import re
from pathlib import Path
from threading import Lock
from typing import Any

from jinja2 import Template

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.utils.paths import sanitize_path_component

logger = logging.getLogger(__name__)

# Patterns that indicate bash history was cleared by the user/attacker.
# If any entry matches, all prior entries (and the clearing command itself)
# should be discarded — they would not survive the clearing operation.
_CLEAR_PATTERNS = [
    re.compile(r"history\s+-c"),
    re.compile(r">\s*~/\.bash_history"),
    re.compile(r"cat\s+/dev/null\s*>\s*~/\.bash_history"),
    re.compile(r"truncate\s+-s\s+0\s+.*\.bash_history"),
    re.compile(r"rm\s+((-[rf]+\s+)?.*)?\.bash_history"),
]


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
            "timestamp": event_data.get("timestamp"),
            "command": event_data.get("command"),
        }
        rendered = self._template.render(**context).strip()
        self.buffer.append(rendered)
        self.event_count += 1
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        # Sort entries by timestamp to ensure monotonic ordering
        # Bash history format: #<epoch>\n<command>\n — sort by epoch line
        self._sort_by_timestamp()
        cleared = self._apply_history_clearing()
        if not self.buffer:
            # Clearing command was the last thing — truncate file
            if cleared and self.output_path.exists():
                self.output_path.write_text("")
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        # If history was cleared, truncate file (discard prior flushes)
        mode = "w" if cleared else "a"
        with open(self.output_path, mode, encoding="utf-8") as f:
            for entry in self.buffer:
                f.write(entry)
                if not entry.endswith("\n"):
                    f.write("\n")
        self.buffer.clear()

    def _sort_by_timestamp(self) -> None:
        """Sort buffer entries by embedded epoch timestamps."""

        def _extract_ts(entry: str) -> int:
            for line in entry.split("\n"):
                if line.startswith("#") and line[1:].strip().isdigit():
                    return int(line[1:].strip())
            return 0

        self.buffer.sort(key=_extract_ts)

    def _apply_history_clearing(self) -> bool:
        """Remove entries that would have been cleared by a history-clearing command.

        Scans for commands matching _CLEAR_PATTERNS. If found, discards all
        entries at or before the last clearing command (including the command
        itself), keeping only entries that came after.

        Returns:
            True if a clearing command was found (caller should truncate file).
        """
        last_clear_idx = -1
        for i, entry in enumerate(self.buffer):
            # Extract command text (lines after the #epoch line)
            lines = entry.split("\n")
            cmd_lines = [ln for ln in lines if not ln.startswith("#")]
            cmd_text = " ".join(cmd_lines).strip()
            for pattern in _CLEAR_PATTERNS:
                if pattern.search(cmd_text):
                    last_clear_idx = i
                    break

        if last_clear_idx >= 0:
            # Discard everything up to and including the clearing command
            self.buffer = self.buffer[last_clear_idx + 1 :]
            return True
        return False


class BashHistoryEmitter(LogEmitter):
    """Multiplexing emitter that writes per-user-per-host bash history files.

    Maintains a dict of _SingleHistoryWriter instances keyed by (username, hostname).
    The parent thread consumes from the queue; dispatch happens in _run().
    """

    _supported_types: set[str] = {"bash_command"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Bash history only for Linux hosts."""
        return event.event_type in self._supported_types and (
            event.src_host is not None and event.src_host.os_category == "linux"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Extract fields from SecurityEvent and delegate to existing dispatch."""
        host = event.src_host
        event_data = {
            "timestamp": event.timestamp,
            "username": event.auth.username if event.auth else "unknown",
            "hostname": host.hostname if host else "unknown",
            "host_fqdn": (host.fqdn or host.hostname) if host else "unknown",
            "command": event.shell.command if event.shell else "",
        }
        self.emit_event(event_data)

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

    def _get_writer(self, username: str, host_fqdn: str) -> _SingleHistoryWriter:
        safe_host = sanitize_path_component(host_fqdn)
        safe_user = sanitize_path_component(username)
        key = (safe_user or "unknown", safe_host or "unknown")
        writer = self._writers.get(key)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(key)
            if writer is not None:
                return writer
            # Nest under host FQDN dir: <base>/<fqdn>/bash_history/<user>.bash_history
            path = self._base_dir / key[1] / "bash_history" / f"{key[0]}.bash_history"
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
        username = event_data.get("username", "unknown")
        host_fqdn = event_data.get("host_fqdn", event_data.get("hostname", "unknown"))
        writer = self._get_writer(username, host_fqdn)
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
