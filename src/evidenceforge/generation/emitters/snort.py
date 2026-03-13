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
            if rendered is not None:
                self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render Snort/Suricata alert to fast alert format.

        Returns None if the event lacks required IDS alert fields (sid, message,
        classification), which means it's a plain connection event that should
        not generate an IDS alert.

        Format: <timestamp> [**] [<sid>:1:1] <message> [**] [Classification: <class>] [Priority: <pri>] {<proto>} <src_ip>:<src_port> -> <dst_ip>:<dst_port>
        """
        # Skip events that lack IDS-specific fields — normal network connections
        # routed here by network_visibility should not produce alerts
        if not event_data.get('sid') and not event_data.get('message'):
            return None

        # Map Zeek field names to Snort field names as fallbacks
        proto = event_data.get('protocol') or event_data.get('proto')

        context = {
            'timestamp': event_data.get('timestamp') or event_data.get('ts'),
            'sid': event_data.get('sid'),
            'classification': event_data.get('classification'),
            'priority': event_data.get('priority'),
            'protocol': proto.upper() if proto else None,
            'src_ip': event_data.get('src_ip') or event_data.get('id.orig_h'),
            'src_port': event_data.get('src_port') or event_data.get('id.orig_p'),
            'dst_ip': event_data.get('dst_ip') or event_data.get('id.resp_h'),
            'dst_port': event_data.get('dst_port') or event_data.get('id.resp_p'),
            'message': event_data.get('message'),
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
