"""Windows Event Log emitter."""

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter

# Regex to extract SystemTime from rendered XML for chronological sorting
_SYSTEMTIME_RE = re.compile(r'SystemTime="([^"]+)"')


class WindowsEventEmitter(LogEmitter):
    """Emitter for Windows Event Log format (XML).

    Generates Windows Security Event Logs in XML format.
    Events are sorted chronologically on flush to interleave records from
    different computers (matching real centralized log collection behavior).
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a Windows Event Log event."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event to XML format."""
        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return self._template.render(**event_data)

    def _flush_unlocked(self) -> None:
        """Flush with chronological sorting.

        Overrides base to sort events by SystemTime before writing,
        ensuring events from different computers are interleaved
        chronologically (as a SIEM/forwarder would produce).
        """
        if not self.buffer:
            return

        # Sort by SystemTime extracted from rendered XML
        def _sort_key(event_str: str) -> str:
            m = _SYSTEMTIME_RE.search(event_str)
            return m.group(1) if m else ""

        self.buffer.sort(key=_sort_key)

        # Delegate to parent for actual file writing
        super()._flush_unlocked()
