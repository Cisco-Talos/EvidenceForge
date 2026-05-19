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

from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_files import _bounded_in_connection_timestamp
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.utils.rng import _stable_seed

_SOURCE_TIMING = SourceTimingPlanner()


def _certificate_chain_gap(event: SecurityEvent, x509: Any, position: int) -> timedelta:
    """Return deterministic non-uniform spacing between x509 chain rows."""
    seed = _stable_seed(
        "zeek-x509-chain-gap:"
        f"{getattr(event.network, 'zeek_uid', '')}:"
        f"{getattr(x509, 'fuid', '')}:{position}:{event.timestamp.isoformat()}"
    )
    return timedelta(milliseconds=1 + (seed % 9), microseconds=97 + ((seed >> 8) % 811))


class ZeekX509Emitter(SensorMultiplexEmitter):
    """Emitter for Zeek x509.log format (NDJSON).

    Generates X.509 certificate logs. No conn UID — keyed by fingerprint.
    Uses dispatch_raw since certificates are side-effects of SSL connections.
    """

    _log_filename = "x509.json"
    _flat_filename = "zeek_x509.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.network.conn_state == "SF"
            and (event.x509 is not None or bool(event.x509_chain))
        )

    def emit(self, event: SecurityEvent) -> None:
        certificates = event.x509_chain or ([event.x509] if event.x509 is not None else [])
        previous_timestamp: datetime | None = None
        for position, x509 in enumerate(certificates):
            previous_timestamp = self._emit_certificate(
                event,
                x509,
                position=position,
                chain_not_before=previous_timestamp,
            )

    def _emit_certificate(
        self,
        event: SecurityEvent,
        x509: Any,
        *,
        position: int,
        chain_not_before: datetime | None,
    ) -> datetime:
        x509_sensor_hostnames = event._sensor_hostnames_by_format.get(
            self.format_def.name if self.format_def else "zeek_x509", []
        )
        ssl_sensor_hostnames = event._sensor_hostnames_by_format.get("zeek_ssl", [])
        sensor_hostnames = list(dict.fromkeys([*x509_sensor_hostnames, *ssl_sensor_hostnames]))
        targets = sensor_hostnames or self._sensor_hostnames
        new_targets = targets
        timestamp = event.timestamp
        if event.network is not None:
            conn_ts = _SOURCE_TIMING.source_time(
                event,
                "source.zeek_conn_start",
                seed_parts=(
                    event.network.zeek_uid,
                    event.network.src_ip,
                    event.network.src_port,
                    event.network.dst_ip,
                    event.network.dst_port,
                    event.timestamp,
                ),
                not_before=event.timestamp,
            )
            within = None
            if event.network.duration is not None and event.network.duration > 0:
                latest = conn_ts + timedelta(seconds=max(0.0, event.network.duration - 0.000001))
                within = (conn_ts, latest)
            ssl_timestamp = _SOURCE_TIMING.source_time(
                event,
                "source.zeek_ssl_analyzer",
                seed_parts=(
                    event.network.zeek_uid,
                    event.network.src_ip,
                    event.network.src_port,
                    event.network.dst_ip,
                    event.network.dst_port,
                    event.timestamp,
                ),
                not_before=conn_ts,
                within=within,
            )
            chain_gap = _certificate_chain_gap(event, x509, position)
            lower_bound = ssl_timestamp + chain_gap
            if chain_not_before is not None:
                lower_bound = max(lower_bound, chain_not_before + chain_gap)
            if within is not None and lower_bound > within[1]:
                lower_bound = within[1]
            preferred = _SOURCE_TIMING.source_time(
                event,
                "source.zeek_x509_analyzer",
                seed_parts=(
                    event.network.zeek_uid,
                    x509.fuid,
                    position,
                    event.timestamp,
                ),
                not_before=lower_bound,
                within=within,
            )
            timestamp = _bounded_in_connection_timestamp(
                conn_ts,
                event.network.duration,
                preferred,
            )
        else:
            lower_bound = (
                event.timestamp
                if chain_not_before is None
                else chain_not_before + _certificate_chain_gap(event, x509, position)
            )
            timestamp = _SOURCE_TIMING.source_time(
                event,
                "source.zeek_x509_analyzer",
                seed_parts=(x509.fuid, position, event.timestamp),
                not_before=lower_bound,
            )
        event_data: dict[str, Any] = {
            "ts": timestamp,
            "id": x509.fuid,
            # Keep the parent connection UID as non-rendered correlation metadata so
            # SensorMultiplexEmitter applies the same per-flow timestamp offset to
            # x509.log as ssl.log and files.log for this TLS flow.
            "conn_uids": [event.network.zeek_uid]
            if event.network and event.network.zeek_uid
            else [],
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
        return timestamp

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["san_dns", "basic_constraints_ca"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
