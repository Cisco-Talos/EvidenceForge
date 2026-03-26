"""Zeek http.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekHttpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek http.log format (NDJSON).

    Generates HTTP request/response logs. Requires both NetworkContext and HttpContext.
    Shares conn.log UID via event.network.zeek_uid.
    """

    _log_filename = "http.json"
    _flat_filename = "zeek_http.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.http is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        http = event.http
        event_data: dict[str, Any] = {
            "ts": event.timestamp,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "trans_depth": http.trans_depth,
            "method": http.method,
            "host": http.host,
            "uri": http.uri,
            "version": http.version or None,
            "user_agent": http.user_agent or None,
            "request_body_len": http.request_body_len,
            "response_body_len": http.response_body_len,
            "status_code": http.status_code,
            "status_msg": http.status_msg,
            "tags": http.tags if http.tags else None,
            "referrer": http.referrer or None,
            "resp_fuids": http.resp_fuids if http.resp_fuids else None,
            "resp_mime_types": http.resp_mime_types if http.resp_mime_types else None,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "version",
            "user_agent",
            "tags",
            "referrer",
            "resp_fuids",
            "resp_mime_types",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
