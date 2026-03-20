"""Snort/Suricata alert emitter."""

from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class SnortEmitter(SensorMultiplexEmitter):
    """Emitter for Snort/Suricata fast alert format.

    Per-sensor directory routing: each IDS sensor gets its own alert file.
    """

    _log_filename = "snort_alert.log"
    _flat_filename = "snort_alert.log"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render Snort/Suricata alert to fast alert format.

        Returns None if the event lacks required IDS alert fields (sid, message,
        classification), which means it's a plain connection event that should
        not generate an IDS alert.
        """
        if not event_data.get('sid') and not event_data.get('message'):
            return None

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

        rendered = self._template.render(**context)
        return rendered.strip()
