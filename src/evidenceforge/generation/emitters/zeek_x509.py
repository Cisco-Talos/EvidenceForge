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

"""Zeek x509.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed


class ZeekX509Emitter(SensorMultiplexEmitter):
    """Emitter for Zeek x509.log format (NDJSON).

    Generates X.509 certificate logs. No conn UID — keyed by fingerprint.
    Uses dispatch_raw since certificates are side-effects of SSL connections.
    """

    _log_filename = "x509.json"
    _flat_filename = "zeek_x509.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return event.event_type in self._supported_types and event.x509 is not None

    def emit(self, event: SecurityEvent) -> None:
        x509 = event.x509
        x509_sensor_hostnames = event._sensor_hostnames_by_format.get(
            self.format_def.name if self.format_def else "zeek_x509", []
        )
        ssl_sensor_hostnames = event._sensor_hostnames_by_format.get("zeek_ssl", [])
        sensor_hostnames = list(dict.fromkeys([*x509_sensor_hostnames, *ssl_sensor_hostnames]))
        targets = sensor_hostnames or self._sensor_hostnames
        new_targets = targets
        analyzer_delay_ms = 120 + (_stable_seed(f"zeek_x509_ts:{x509.fuid}") % 531)

        event_data: dict[str, Any] = {
            "ts": self._offset_timestamp(event.timestamp, analyzer_delay_ms),
            "id": x509.fuid,
            "fingerprint": x509.fingerprint,
            "certificate.version": x509.certificate_version,
            "certificate.serial": x509.certificate_serial,
            "certificate.subject": x509.certificate_subject,
            "certificate.issuer": x509.certificate_issuer,
            "certificate.not_valid_before": x509.certificate_not_valid_before,
            "certificate.not_valid_after": x509.certificate_not_valid_after,
            "certificate.key_alg": x509.certificate_key_alg,
            "certificate.sig_alg": x509.certificate_sig_alg,
            "certificate.key_type": x509.certificate_key_type,
            "certificate.key_length": x509.certificate_key_length,
            "certificate.exponent": x509.certificate_exponent,
            "san_dns": x509.san_dns,
            "basic_constraints_ca": x509.basic_constraints_ca,
            "host_cert": x509.host_cert,
            "client_cert": x509.client_cert,
            "_sensor_hostnames": new_targets,
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["san_dns", "basic_constraints_ca"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
