"""Zeek conn.log emitter."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class ZeekEmitter(LogEmitter):
    """Emitter for Zeek conn.log format (JSON).

    Generates Zeek connection logs in JSON format (one JSON object per line).
    Each connection includes source/dest IPs, ports, protocol, and connection state.
    """

    _supported_types: set[str] = {"connection", "ssh_session"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Zeek conn emitter handles connection and session events with network context."""
        return event.event_type in self._supported_types and event.network is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render SecurityEvent to Zeek conn.log format."""
        net = event.network
        event_data = {
            'ts': event.timestamp,
            'uid': net.zeek_uid,
            'id.orig_h': net.src_ip,
            'id.orig_p': net.src_port,
            'id.resp_h': net.dst_ip,
            'id.resp_p': net.dst_port,
            'proto': net.protocol,
            'service': net.service or None,
            'duration': net.duration,
            'orig_bytes': net.orig_bytes,
            'resp_bytes': net.resp_bytes,
            'conn_state': net.conn_state,
            'local_orig': net.local_orig,
            'local_resp': net.local_resp,
            'missed_bytes': net.missed_bytes,
            'history': net.history,
            'orig_pkts': net.orig_pkts,
            'orig_ip_bytes': net.orig_ip_bytes,
            'resp_pkts': net.resp_pkts,
            'resp_ip_bytes': net.resp_ip_bytes,
            'ip_proto': net.ip_proto,
        }
        self.emit_event(event_data)

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        """Initialize Zeek emitter.

        Args:
            format_def: Zeek format definition
            output_path: Path to write JSON log file
            buffer_size: Number of events to buffer before flushing
            threaded: Enable threaded mode with queue-based processing (Phase 2.1)
        """
        super().__init__(format_def, output_path, buffer_size, threaded)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Emit a Zeek connection event.

        In threaded mode, posts to queue. In non-threaded mode, renders immediately.

        Args:
            event_data: Event data with connection fields
        """
        if self.threaded:
            # Threaded mode: post to queue
            self._emit_threaded(event_data)
        else:
            # Non-threaded mode: render and buffer immediately
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Zeek connection to JSON format.

        Args:
            event_data: Event data dictionary

        Returns:
            Formatted JSON event (single line)
        """
        # Ensure timestamp is in epoch format with microsecond precision
        # Zeek timestamps are float values with 6 decimal places (microseconds)
        # e.g., 1427846411.876987
        if "ts" in event_data:
            ts = event_data["ts"]
            if isinstance(ts, datetime):
                # Convert to epoch float with microsecond precision
                # Zeek JSON logs use bare numeric timestamps (not strings)
                event_data["ts"] = round(ts.timestamp(), 6)
            elif isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                event_data["ts"] = round(dt.timestamp(), 6)

        # Handle dotted field names (id.orig_h, etc.)
        # Zeek template expects 'data' dict for dotted fields
        data_fields = {}
        regular_fields = {}

        for key, value in event_data.items():
            if "." in key:
                data_fields[key] = value
            else:
                regular_fields[key] = value

        # Merge for template rendering
        template_context = regular_fields.copy()
        if data_fields:
            template_context["data"] = data_fields

        # Ensure all optional fields exist with None if not provided
        # This prevents Jinja2 Undefined errors in the template
        optional_fields = [
            "service", "duration", "orig_bytes", "resp_bytes",
            "local_orig", "local_resp", "missed_bytes", "history",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
            "ip_proto", "tunnel_parents"
        ]
        for field in optional_fields:
            if field not in template_context:
                template_context[field] = None

        # Render using Jinja2 template from format definition
        rendered = self._template.render(**template_context)

        # Parse and compact the JSON to ensure single-line format (NDJSON)
        # The template may have pretty-printing for readability
        try:
            data = json.loads(rendered)
            # Re-serialize as compact JSON (no whitespace, single line)
            rendered = json.dumps(data, separators=(',', ':'))
        except json.JSONDecodeError:
            # If template didn't produce valid JSON, use it as-is (shouldn't happen)
            rendered = rendered.strip()

        return rendered
