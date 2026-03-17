"""Zeek dns.log emitter."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class ZeekDnsEmitter(LogEmitter):
    """Emitter for Zeek dns.log format (NDJSON).

    Generates Zeek DNS query/response logs. Each record represents a DNS
    transaction with query name, type, response code, and answers.
    """

    def emit_event(self, event_data: dict[str, Any]) -> None:
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Zeek DNS record to NDJSON format."""
        # Convert timestamp to epoch with microsecond precision
        if "ts" in event_data:
            ts = event_data["ts"]
            if isinstance(ts, datetime):
                event_data["ts"] = f"{ts.timestamp():.6f}"
            elif isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                event_data["ts"] = f"{dt.timestamp():.6f}"

        # Handle dotted field names (id.orig_h → id_orig_h for template)
        template_context = {}
        for key, value in event_data.items():
            template_key = key.replace(".", "_")
            template_context[template_key] = value

        # Render template and compact to single line
        rendered = self._template.render(**template_context)
        try:
            data = json.loads(rendered)
            return json.dumps(data, separators=(',', ':'))
        except json.JSONDecodeError:
            return rendered.strip()
