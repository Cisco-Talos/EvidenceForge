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

"""Zeek files.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekFilesEmitter(SensorMultiplexEmitter):
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
            "ts": event.timestamp,
            "fuid": ft.fuid,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "source": ft.source,
            "depth": ft.depth,
            "analyzers": ft.analyzers if ft.analyzers else None,
            "mime_type": ft.mime_type or None,
            "duration": ft.duration,
            "local_orig": ft.local_orig,
            "is_orig": ft.is_orig,
            "seen_bytes": ft.seen_bytes,
            "total_bytes": ft.total_bytes,
            "missing_bytes": ft.missing_bytes,
            "overflow_bytes": ft.overflow_bytes,
            "timedout": ft.timedout,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "analyzers",
            "mime_type",
            "duration",
            "local_orig",
            "total_bytes",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
