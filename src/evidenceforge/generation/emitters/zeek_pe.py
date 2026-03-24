"""Zeek pe.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekPeEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek pe.log format (NDJSON).

    Generates Portable Executable analysis logs.
    Uses dispatch_raw since PE analysis is a side-effect of file transfers.
    """

    _log_filename = "pe.json"
    _flat_filename = "zeek_pe.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.pe is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        pe = event.pe
        event_data: dict[str, Any] = {
            'ts': event.timestamp,
            'id': pe.id,
            'machine': pe.machine,
            'compile_ts': pe.compile_ts,
            'os': pe.os,
            'subsystem': pe.subsystem,
            'is_exe': pe.is_exe,
            'is_64bit': pe.is_64bit,
            'uses_aslr': pe.uses_aslr,
            'uses_dep': pe.uses_dep,
            'uses_code_integrity': pe.uses_code_integrity,
            'uses_seh': pe.uses_seh,
            'has_import_table': pe.has_import_table,
            'has_export_table': pe.has_export_table,
            'has_cert_table': pe.has_cert_table,
            'has_debug_data': pe.has_debug_data,
            'section_names': pe.section_names,
            '_sensor_hostnames': event._sensor_hostnames_by_format.get(
                self.format_def.name if self.format_def else 'zeek_pe', []),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["section_names"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
