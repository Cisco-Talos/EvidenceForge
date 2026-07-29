# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Zeek pe.log emitter."""

from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_files import (
    _bounded_file_transfer_observation,
    _related_http_analyzer_timestamp,
)
from evidenceforge.utils.rng import _stable_seed


class ZeekPeEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek pe.log format (NDJSON).

    Generates Portable Executable analysis logs.
    Uses dispatch_raw since PE analysis is a side-effect of file transfers.
    """

    _log_filename = "pe.json"
    _flat_filename = "zeek_pe.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return event.event_type in self._supported_types and event.pe is not None

    def emit(self, event: SecurityEvent) -> None:
        pe = event.pe
        event_data: dict[str, Any] = {
            "ts": _pe_analyzer_timestamp(event),
            "id": pe.id,
            "machine": pe.machine,
            "compile_ts": pe.compile_ts,
            "os": pe.os,
            "subsystem": pe.subsystem,
            "is_exe": pe.is_exe,
            "is_64bit": pe.is_64bit,
            "uses_aslr": pe.uses_aslr,
            "uses_dep": pe.uses_dep,
            "uses_code_integrity": pe.uses_code_integrity,
            "uses_seh": pe.uses_seh,
            "has_import_table": pe.has_import_table,
            "has_export_table": pe.has_export_table,
            "has_cert_table": pe.has_cert_table,
            "has_debug_data": pe.has_debug_data,
            "section_names": pe.section_names,
            **self._sensor_metadata(
                event,
                self.format_def.name if self.format_def else "zeek_pe",
            ),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["section_names"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)


def _pe_analyzer_timestamp(event: SecurityEvent) -> datetime:
    """Return a PE analyzer time after the owning files.log artifact."""
    pe = event.pe
    if pe is None:
        return event.timestamp
    if event.network is not None and event.file_transfer is not None:
        file_ts, file_duration = _bounded_file_transfer_observation(
            event,
            min_start=_related_http_analyzer_timestamp(event),
        )
        duration_us = max(0, int(file_duration * 1_000_000))
        if duration_us <= 1:
            return file_ts
        max_offset_us = min(duration_us - 1, 250_000)
        offset_us = 1 + (
            _stable_seed(f"zeek_pe_ts:{pe.id}:{event.network.zeek_uid}") % max_offset_us
        )
        return file_ts + timedelta(microseconds=offset_us)
    return event.timestamp + timedelta(milliseconds=1)
