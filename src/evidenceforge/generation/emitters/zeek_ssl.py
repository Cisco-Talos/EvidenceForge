"""Zeek ssl.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import ZeekMultiplexEmitter


class ZeekSslEmitter(ZeekMultiplexEmitter):
    """Emitter for Zeek ssl.log format (NDJSON).

    Generates SSL/TLS handshake logs. Requires both NetworkContext and SslContext.
    Shares conn.log UID via event.network.zeek_uid.
    """

    _log_filename = "ssl.json"
    _flat_filename = "zeek_ssl.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.ssl is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        ssl = event.ssl
        event_data: dict[str, Any] = {
            'ts': event.timestamp,
            'uid': net.zeek_uid,
            'id.orig_h': net.src_ip,
            'id.orig_p': net.src_port,
            'id.resp_h': net.dst_ip,
            'id.resp_p': net.dst_port,
            'version': ssl.version or None,
            'cipher': ssl.cipher or None,
            'server_name': ssl.server_name or None,
            'resumed': ssl.resumed,
            'established': ssl.established,
            'ssl_history': ssl.ssl_history or None,
            '_sensor_hostnames': event._observing_sensor_hostnames,
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "version", "cipher", "server_name", "resumed",
            "established", "ssl_history",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
