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

from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_files import (
    _bounded_file_transfer_observation,
    _related_http_analyzer_timestamp,
)
from evidenceforge.utils.rng import _stable_seed


class ZeekOcspEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ocsp.log format (NDJSON).

    Generates OCSP certificate status response logs.
    Uses dispatch_raw since OCSP responses are side-effects of SSL connections.
    """

    _log_filename = "ocsp.json"
    _flat_filename = "zeek_ocsp.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return event.event_type in self._supported_types and event.ocsp is not None

    def emit(self, event: SecurityEvent) -> None:
        ocsp = event.ocsp
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
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(
                self.format_def.name if self.format_def else "zeek_ocsp", []
            ),
        }
        if event.network is not None and event.network.zeek_uid:
            event_data["conn_uids"] = [event.network.zeek_uid]
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        render_data = dict(event_data)
        render_data.setdefault("revoketime", None)
        render_data.setdefault("revokereason", None)
        return self._render_zeek_json(render_data)


def _ocsp_analyzer_timestamp(event: SecurityEvent) -> datetime | float:
    """Return an OCSP analyzer time inside the owning HTTP response file window."""
    ocsp = event.ocsp
    if ocsp is None:
        return event.timestamp
    if event.network is not None and event.file_transfer is not None:
        file_ts, file_duration = _bounded_file_transfer_observation(
            event,
            min_start=_related_http_analyzer_timestamp(event),
        )
        duration_us = max(0, int(file_duration * 1_000_000))
        if duration_us <= 1:
            return file_ts
        offset_us = 1 + (
            _stable_seed(f"zeek_ocsp_ts:{ocsp.id}:{event.network.zeek_uid}") % (duration_us - 1)
        )
        return file_ts + timedelta(microseconds=offset_us)

    analyzer_delay_ms = 1 + (_stable_seed(f"zeek_ocsp_ts:{ocsp.id}") % 8)
    return event.timestamp + timedelta(milliseconds=analyzer_delay_ms)
