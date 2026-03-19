"""Web server access log emitter."""

from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class WebEmitter(LogEmitter):
    """Emitter for W3C web server access logs (Apache/Nginx Combined Log Format)."""

    _supported_types: set[str] = set()

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render web access log entry.

        Format: <client_ip> - <username> [<timestamp>] "<method> <path> <protocol>" <status> <bytes> "<referer>" "<user_agent>"
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'client_ip': event_data.get('client_ip'),
            'username': event_data.get('username'),
            'method': event_data.get('method'),
            'path': event_data.get('path'),
            'protocol': event_data.get('protocol'),
            'status_code': event_data.get('status_code'),
            'bytes_sent': event_data.get('bytes_sent'),
            'referer': event_data.get('referer'),
            'user_agent': event_data.get('user_agent')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
