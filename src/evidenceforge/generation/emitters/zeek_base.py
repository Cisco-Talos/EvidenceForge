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

"""Base class for network sensor emitters with per-sensor directory multiplexing.

Network sensors each get their own output directory. This base class follows
the BashHistoryEmitter multiplexing pattern: a single emitter instance per
format, with internal routing to per-sensor subdirectories.

Output structure:
    base_dir/<sensor_hostname>/conn.json
    base_dir/<sensor_hostname>/dns.json
    base_dir/<sensor_hostname>/ssl.json
    ...

When no sensors are configured (backward compat), writes directly to:
    base_dir/<log_filename>
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter

logger = logging.getLogger(__name__)


class _SingleZeekWriter:
    """Writes Zeek NDJSON for one sensor. Thread-safe via lock."""

    def __init__(self, output_path: Path, buffer_size: int = 10000):
        self.output_path = output_path
        self.buffer: list[str] = []
        self.buffer_size = buffer_size
        self.event_count = 0
        self._lock = Lock()

    def write(self, rendered: str) -> None:
        with self._lock:
            self.buffer.append(rendered)
            self.event_count += 1
            if len(self.buffer) >= self.buffer_size:
                self._flush_unlocked()

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


class SensorMultiplexEmitter(LogEmitter):
    """Base class for network sensor emitters with per-sensor directory routing.

    Subclasses implement:
    - _render_event(): Convert event data dict to NDJSON string
    - can_handle(): Filter SecurityEvents by type + required contexts
    - emit(): Extract fields from SecurityEvent and call emit_to_sensors()
    """

    _log_filename: str = "output.json"  # Override in subclasses (e.g., "conn.json")
    _flat_filename: str = ""  # Override for backward-compat flat output (e.g., "zeek_conn.json")
    _supported_types: set[str] = set()

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        sensor_hostnames: list[str] | None = None,
    ):
        # If no sensor_hostnames provided AND output_path has a file extension,
        # treat it as a direct file path (backward compat for tests and simple usage)
        self._direct_file_mode = not sensor_hostnames and output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._sensor_hostnames = sensor_hostnames or []
        self._writers: dict[str, _SingleZeekWriter] = {}
        self._writers_lock = Lock()
        self._buffer_size = buffer_size
        super().__init__(format_def, output_path, buffer_size, threaded)

    def _get_writer(self, sensor_hostname: str) -> _SingleZeekWriter:
        writer = self._writers.get(sensor_hostname)
        if writer is not None:
            return writer
        with self._writers_lock:
            writer = self._writers.get(sensor_hostname)
            if writer is not None:
                return writer
            if sensor_hostname:
                path = self._base_dir / sensor_hostname / self._log_filename
            elif self._direct_file_path:
                # Direct file mode (test/simple usage): output_path was a file
                path = self._direct_file_path
            else:
                # No sensors configured → flat output using format name
                flat_name = self._flat_filename or self._log_filename
                path = self._base_dir / flat_name
            writer = _SingleZeekWriter(path, self._buffer_size)
            self._writers[sensor_hostname] = writer
            logger.debug(f"Created Zeek writer: {path}")
            return writer

    def _get_default_writer(self) -> _SingleZeekWriter:
        """Get the backward-compat flat writer (no sensor subdirectory)."""
        return self._get_writer("")

    def emit_to_sensors(self, rendered: str, sensor_hostnames: list[str] | None = None) -> None:
        """Route a rendered NDJSON line to the appropriate sensor writers.

        Args:
            rendered: Pre-rendered NDJSON line
            sensor_hostnames: List of sensor hostnames to write to.
                If None/empty, writes to all configured sensors (or flat output).
        """
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames
        if not targets:
            # No sensors configured → backward compat flat output
            self._get_default_writer().write(rendered)
            return
        for hostname in targets:
            self._get_writer(hostname).write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            self._dispatch(event_data)

    @staticmethod
    def _derive_sensor_uid(original_uid: str, sensor_hostname: str) -> str:
        """Derive a deterministic per-sensor UID from the original UID.

        All emitters processing the same event for the same sensor will derive
        the same UID, preserving cross-log correlation (conn↔dns↔http↔ssl)
        within a sensor. Different sensors get different UIDs.

        Uses HMAC-like hashing to produce a base62 UID of the same length
        and prefix as the original.
        """
        import hashlib
        import string

        base62 = string.ascii_uppercase + string.ascii_lowercase + string.digits
        prefix = original_uid[0] if original_uid else "C"
        target_len = len(original_uid) - 1  # Exclude prefix

        h = hashlib.sha256(f"{original_uid}:{sensor_hostname}".encode()).digest()
        chars = []
        for byte in h[:target_len]:
            chars.append(base62[byte % 62])
        return prefix + "".join(chars)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Render and route to sensor writers.

        When multiple sensors observe the same connection, each sensor gets a
        deterministic unique Zeek UID derived from hash(original_uid, sensor).
        All emitters for the same event+sensor produce the same derived UID,
        preserving cross-log correlation within each sensor.
        Skips events where _render_event returns None (e.g., SnortEmitter
        filters out non-IDS connection events).
        """
        sensor_hostnames = event_data.pop("_sensor_hostnames", None)
        targets = sensor_hostnames if sensor_hostnames else self._sensor_hostnames

        if not targets or len(targets) <= 1:
            # Single sensor or no sensors — render once
            rendered = self._render_event(event_data)
            if rendered is None:
                return
            self.emit_to_sensors(rendered, sensor_hostnames)
        else:
            # Multiple sensors: each gets a deterministic unique UID
            original_uid = event_data.get("uid")
            for i, hostname in enumerate(targets):
                if i > 0 and original_uid:
                    # Derive a deterministic UID for this sensor
                    event_data["uid"] = self._derive_sensor_uid(original_uid, hostname)
                rendered = self._render_event(event_data)
                if rendered is None:
                    return
                self._get_writer(hostname).write(rendered)
            # Restore original UID so downstream code isn't affected
            if original_uid:
                event_data["uid"] = original_uid

    def _render_zeek_json(self, event_data: dict[str, Any]) -> str:
        """Common Zeek NDJSON rendering: timestamp conversion, dotted fields, compact JSON.

        Subclasses can call this for standard Zeek JSON rendering, or override
        _render_event() entirely for custom behavior.
        """
        # Convert timestamp to epoch float with microsecond precision
        if "ts" in event_data:
            ts = event_data["ts"]
            if isinstance(ts, datetime):
                event_data["ts"] = round(ts.timestamp(), 6)
            elif isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                event_data["ts"] = round(dt.timestamp(), 6)

        # Handle dotted field names (id.orig_h → data dict for template)
        data_fields = {}
        regular_fields = {}
        for key, value in event_data.items():
            if key.startswith("_"):
                continue  # Skip internal metadata fields
            if "." in key:
                data_fields[key] = value
            else:
                regular_fields[key] = value

        template_context = regular_fields.copy()
        if data_fields:
            template_context["data"] = data_fields

        # Render Jinja2 template and compact to NDJSON
        rendered = self._template.render(**template_context)
        try:
            data = json.loads(rendered)
            # Round timestamp to 6 decimal places (Zeek standard)
            if "ts" in data and isinstance(data["ts"], float):
                data["ts"] = round(data["ts"], 6)
            return json.dumps(data, separators=(",", ":"))
        except json.JSONDecodeError:
            return rendered.strip()

    def _run(self) -> None:
        """Thread run loop — dispatch events to per-sensor writers."""
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

    def flush(self) -> None:
        """Flush all sensor writers."""
        with self._writers_lock:
            for writer in self._writers.values():
                writer.flush()

    def _buffer_event(self, rendered: str) -> None:
        """Override base class _buffer_event to route through multiplexer."""
        self._get_default_writer().write(rendered)

    def _flush_unlocked(self) -> None:
        """Override to prevent base class from writing to single output_path."""
        pass

    def close(self) -> None:
        """Close emitter and flush all sensor writers."""
        if self.threaded:
            self.stop_thread()
        self.flush()

    @property
    def event_count(self) -> int:
        """Total events across all sensor writers."""
        return sum(w.event_count for w in self._writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        # Base class sets this to 0 in __init__; ignore it
        pass
