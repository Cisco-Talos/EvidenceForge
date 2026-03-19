"""Syslog emitter for Linux system logs."""

from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class SyslogEmitter(LogEmitter):
    """Emitter for Linux syslog format."""

    _supported_types: set[str] = set()

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def flush(self) -> None:
        """Flush with chronological sorting (syslog is append-only/ordered)."""
        with self._file_lock:
            self.buffer.sort()  # ISO timestamp prefix → lexicographic sort works
            self._flush_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render syslog event to text format.

        Format: <timestamp> <hostname> <app>[<pid>]: <message>
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'hostname': event_data.get('hostname'),
            'facility': event_data.get('facility'),
            'severity': event_data.get('severity'),
            'app_name': event_data.get('app_name'),
            'pid': event_data.get('pid'),
            'message': event_data.get('message')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
