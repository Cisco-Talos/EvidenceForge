"""Bash history emitter for command history logs."""

from pathlib import Path
from typing import Any

from log_generator.formats.format_def import FormatDefinition
from log_generator.generation.emitters.base import LogEmitter


class BashHistoryEmitter(LogEmitter):
    """Emitter for bash command history format."""

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render bash history entry.

        Format:
        #<timestamp>
        <command>
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'username': event_data.get('username'),
            'hostname': event_data.get('hostname'),
            'command': event_data.get('command'),
            'exit_code': event_data.get('exit_code')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
