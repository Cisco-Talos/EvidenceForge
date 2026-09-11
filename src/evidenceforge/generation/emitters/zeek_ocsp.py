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

"""Zeek ocsp.log emitter."""

from datetime import datetime
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_files import _frozen_source_time
from evidenceforge.generation.network_observation import network_source_timing_key


class ZeekOcspEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ocsp.log format (NDJSON).

    Generates OCSP certificate status response logs.
    Uses dispatch_raw since OCSP responses are side-effects of SSL connections.
    """

    _log_filename = "ocsp.json"
    _flat_filename = "zeek_ocsp.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        return event.event_type in self._supported_types and event.protocol.ocsp is not None

    def emit(self, event: CanonicalOccurrence) -> None:
        ocsp = event.protocol.ocsp
        event_data: dict[str, Any] = {
            "ts": _ocsp_analyzer_timestamp(event),
            "id": ocsp.id,
            "hashAlgorithm": ocsp.hash_algorithm,
            "issuerNameHash": ocsp.issuer_name_hash,
            "issuerKeyHash": ocsp.issuer_key_hash,
            "serialNumber": ocsp.serial_number,
            "certStatus": ocsp.cert_status,
            "thisUpdate": ocsp.this_update,
            "nextUpdate": ocsp.next_update,
            "revoketime": ocsp.revoketime,
            "revokereason": ocsp.revokereason,
            "_source_timing_key": network_source_timing_key("zeek_ocsp", ocsp.id),
            **self._sensor_metadata(
                event,
                self.format_def.name if self.format_def else "zeek_ocsp",
                analyzer_file_id=ocsp.id,
            ),
        }
        if event.network is not None and event.network.zeek_uid:
            event_data["conn_uids"] = [event.network.zeek_uid]
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        render_data = dict(event_data)
        render_data.setdefault("revoketime", None)
        render_data.setdefault("revokereason", None)
        return self._render_zeek_json(render_data)


def _ocsp_analyzer_timestamp(event: CanonicalOccurrence) -> datetime | float:
    """Return a planner-frozen OCSP analyzer timestamp."""

    ocsp = event.protocol.ocsp
    if ocsp is None:
        return event.timestamp
    fallback = event.network.started_at if event.network is not None else event.timestamp
    return _frozen_source_time(
        event,
        network_source_timing_key("zeek_ocsp", ocsp.id),
        fallback,
    )
