"""Snort/Suricata alert emitter."""

from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class SnortEmitter(LogEmitter):
    """Emitter for Snort/Suricata fast alert format."""

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Snort/Suricata alert to fast alert format.

        Format: <timestamp> [**] [<sid>:1:1] <message> [**] [Classification: <class>] [Priority: <pri>] {<proto>} <src_ip>:<src_port> -> <dst_ip>:<dst_port>
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'sid': event_data.get('sid'),
            'classification': event_data.get('classification'),
            'priority': event_data.get('priority'),
            'protocol': event_data.get('protocol'),
            'src_ip': event_data.get('src_ip'),
            'src_port': event_data.get('src_port'),
            'dst_ip': event_data.get('dst_ip'),
            'dst_port': event_data.get('dst_port'),
            'message': event_data.get('message')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
