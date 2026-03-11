"""Windows Event Log emitter."""

from datetime import datetime
from pathlib import Path
from typing import Any

from log_generator.formats.format_def import FormatDefinition
from log_generator.generation.emitters.base import LogEmitter


class WindowsEventEmitter(LogEmitter):
    """Emitter for Windows Event Log format (XML).

    Generates Windows Security Event Logs in XML format.
    Supports variants: logon (4624), logoff (4634), process (4688).
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
    ):
        """Initialize Windows Event emitter.

        Args:
            format_def: Windows Event format definition
            output_path: Path to write XML log file
            buffer_size: Number of events to buffer before flushing
        """
        super().__init__(format_def, output_path, buffer_size)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a Windows Event Log event.

        Args:
            event_data: Event data with all required fields for the variant
        """
        # Render the event
        rendered = self._render_event(event_data)

        # Buffer it
        self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event to XML format.

        Args:
            event_data: Event data dictionary

        Returns:
            Formatted XML event
        """
        # Ensure timestamp is formatted properly
        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                # Format as ISO 8601 with microseconds
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Render using Jinja2 template from format definition
        rendered = self._template.render(**event_data)

        return rendered
