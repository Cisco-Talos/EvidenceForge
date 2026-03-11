"""Base emitter class for log generation."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from jinja2 import Template

from log_generator.formats.format_def import FormatDefinition


class LogEmitter(ABC):
    """Abstract base class for log emitters.

    Emitters write log events to files in specific formats. Each emitter:
    - Buffers events (default 10K) before flushing to disk
    - Uses format definitions to render events
    - Writes to a specific output file

    Subclasses must implement:
    - emit_event(): Process and buffer a single event
    - _render_event(): Convert event data to formatted string
    """

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
    ):
        """Initialize emitter.

        Args:
            format_def: Format definition for this log type
            output_path: Path to write log file
            buffer_size: Number of events to buffer before flushing (default: 10K)
        """
        self.format_def = format_def
        self.output_path = output_path
        self.buffer_size = buffer_size
        self.buffer: list[str] = []
        self.event_count = 0
        self._template = Template(format_def.output.template)
        self._header_written = False

    @abstractmethod
    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a single log event.

        Args:
            event_data: Event data dictionary with field values
        """
        pass

    @abstractmethod
    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render event data to formatted log string.

        Args:
            event_data: Event data dictionary

        Returns:
            Formatted log entry as string
        """
        pass

    def _write_header(self) -> None:
        """Write header to output file if format has one."""
        if self.format_def.output.header_template and not self._header_written:
            header_template = Template(self.format_def.output.header_template)
            header = header_template.render()

            # Write header to file
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w", encoding=self.format_def.output.encoding) as f:
                f.write(header)
                if not header.endswith("\n"):
                    f.write("\n")

            self._header_written = True

    def _buffer_event(self, rendered: str) -> None:
        """Add rendered event to buffer and flush if needed.

        Args:
            rendered: Rendered event string
        """
        self.buffer.append(rendered)
        self.event_count += 1

        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        """Flush buffered events to disk."""
        if not self.buffer:
            return

        # Ensure header is written first
        if not self._header_written:
            self._write_header()

        # Ensure output directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Append buffered events to file
        mode = "a" if self._header_written else "w"
        with open(self.output_path, mode, encoding=self.format_def.output.encoding) as f:
            for event in self.buffer:
                f.write(event)
                if not event.endswith("\n"):
                    f.write("\n")

        self.buffer.clear()

    def close(self) -> None:
        """Close emitter and flush any remaining events."""
        self.flush()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
