"""Windows Event Log emitter.

Buffers raw event dicts, sorts by timestamp on flush, assigns per-computer
EventRecordIDs in sorted order (ensuring monotonic IDs match chronological
order), then renders to XML and writes to disk.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class WindowsEventEmitter(LogEmitter):
    """Emitter for Windows Event Log format (XML).

    Unlike other emitters that buffer rendered strings, this emitter buffers
    raw event dicts and defers rendering until flush time. This allows
    EventRecordIDs to be assigned after chronological sorting, ensuring
    higher RecordID always corresponds to same-or-later timestamp (matching
    real Windows Event Log behavior).
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded)
        # Buffer raw event dicts instead of rendered strings
        self._event_dicts: list[dict[str, Any]] = []
        # Per-computer RecordID counters persist across flushes
        self._record_id_counters: dict[str, int] = {}

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Buffer a Windows Event dict for deferred rendering.

        In threaded mode, posts dict to the queue. In non-threaded mode,
        adds to the local dict buffer directly.
        """
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            with self._file_lock:
                self._event_dicts.append(event_data)
                if len(self._event_dicts) >= self.buffer_size:
                    self._flush_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event dict to XML format."""
        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return self._template.render(**event_data)

    def _run(self) -> None:
        """Thread run loop — buffers dicts from queue instead of rendering.

        Overrides base class to route events through the dict buffer
        for deferred rendering with correct RecordID assignment.
        """
        from queue import Empty
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                with self._file_lock:
                    self._event_dicts.append(event_data)
                    if len(self._event_dicts) >= self.buffer_size:
                        self._flush_unlocked()
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    logger.debug(f"Flushing {self.format_def.name} emitter at barrier")
                    self.flush()
                    self._flush_barrier.clear()

        # Final flush before thread exits
        logger.debug(f"Emitter thread stopping for {self.format_def.name}, final flush")
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _flush_unlocked(self) -> None:
        """Sort events chronologically, assign RecordIDs, render, and write.

        1. Sort buffered dicts by TimeCreated
        2. Assign per-computer EventRecordIDs in sorted order
           (counters persist across flushes for continuity)
        3. Render each event to XML via Jinja2 template
        4. Write to disk via parent class machinery
        """
        if not self._event_dicts:
            return

        # Sort by timestamp (datetime objects sort naturally)
        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            if isinstance(ts, datetime):
                return ts
            return ts  # string timestamps sort lexicographically (ISO 8601)

        self._event_dicts.sort(key=_sort_key)

        # Assign per-computer EventRecordIDs in sorted order
        for event in self._event_dicts:
            computer = event.get("Computer", "")
            # Strip FQDN for counter key (bare hostname)
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                # Initialize with deterministic offset from hostname hash
                self._record_id_counters[counter_key] = (hash(counter_key) % 40000) + 1000
            self._record_id_counters[counter_key] += 1
            event["EventRecordID"] = self._record_id_counters[counter_key]

        # Render to XML strings and transfer to parent's string buffer
        for event in self._event_dicts:
            rendered = self._render_event(event)
            self.buffer.append(rendered)
            self.event_count += 1

        self._event_dicts.clear()

        # Delegate actual file writing to parent
        super()._flush_unlocked()
