"""Zeek files.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import ZeekMultiplexEmitter


class ZeekFilesEmitter(ZeekMultiplexEmitter):
    """Emitter for Zeek files.log format (NDJSON).

    Generates file transfer metadata logs. Requires both NetworkContext and
    FileTransferContext. Uses own fuid (F-prefix) alongside conn.log uid.
    """

    _log_filename = "files.json"
    _flat_filename = "zeek_files.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.file_transfer is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        ft = event.file_transfer
        event_data: dict[str, Any] = {
            'ts': event.timestamp,
            'fuid': ft.fuid,
            'uid': net.zeek_uid,
            'id.orig_h': net.src_ip,
            'id.orig_p': net.src_port,
            'id.resp_h': net.dst_ip,
            'id.resp_p': net.dst_port,
            'source': ft.source,
            'depth': ft.depth,
            'analyzers': ft.analyzers if ft.analyzers else None,
            'mime_type': ft.mime_type or None,
            'duration': ft.duration,
            'local_orig': ft.local_orig,
            'is_orig': ft.is_orig,
            'seen_bytes': ft.seen_bytes,
            'total_bytes': ft.total_bytes,
            'missing_bytes': ft.missing_bytes,
            'overflow_bytes': ft.overflow_bytes,
            'timedout': ft.timedout,
            '_sensor_hostnames': event._observing_sensor_hostnames,
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "analyzers", "mime_type", "duration", "local_orig", "total_bytes",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
