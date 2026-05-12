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

import hashlib
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.activity.tls_realism import (
    certificate_analyzer_delay_ms,
    certificate_file_size,
    ssl_analyzer_delay_ms,
)
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed


class ZeekFilesEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek files.log format (NDJSON).

    Generates file transfer metadata logs. Requires NetworkContext plus either
    FileTransferContext or TLS X.509 certificate contexts. Uses own fuid
    (F-prefix) alongside conn.log uid.
    """

    _log_filename = "files.json"
    _flat_filename = "zeek_files.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and (
                event.file_transfer is not None or bool(event.x509_chain) or event.x509 is not None
            )
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        ft = event.file_transfer
        sensor_hostnames = event._sensor_hostnames_by_format.get(self.format_def.name, [])
        if ft is not None:
            file_ts, file_duration = _bounded_file_transfer_observation(
                event.timestamp,
                net.duration,
                net.zeek_uid,
                ft.fuid,
                ft.duration,
                min_start=_related_http_analyzer_timestamp(event),
            )
            event_data: dict[str, Any] = {
                "ts": file_ts,
                "fuid": ft.fuid,
                "tx_hosts": [net.src_ip] if ft.is_orig else [net.dst_ip],
                "rx_hosts": [net.dst_ip] if ft.is_orig else [net.src_ip],
                "_id.orig_h": net.src_ip,
                "_id.resp_h": net.dst_ip,
                "conn_uids": [net.zeek_uid] if net.zeek_uid else [],
                "source": ft.source,
                "depth": ft.depth,
                "filename": ft.filename or None,
                "analyzers": ft.analyzers if ft.analyzers else None,
                "mime_type": ft.mime_type or None,
                "duration": file_duration,
                "local_orig": ft.local_orig,
                "is_orig": ft.is_orig,
                "seen_bytes": ft.seen_bytes,
                "total_bytes": ft.total_bytes,
                "missing_bytes": ft.missing_bytes,
                "overflow_bytes": ft.overflow_bytes,
                "timedout": ft.timedout,
                "md5": ft.md5 or None,
                "sha1": ft.sha1 or None,
                "sha256": ft.sha256 or None,
                "_sensor_hostnames": sensor_hostnames,
            }
            if event._nat_swaps_by_sensor:
                event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
            self.emit_event(event_data)

        certificates = event.x509_chain or ([event.x509] if event.x509 is not None else [])
        for depth, cert in enumerate(certificates):
            size = certificate_file_size(cert)
            cert_hashes = _certificate_file_hashes(cert.fingerprint)
            analyzer_delay_ms = certificate_analyzer_delay_ms(
                zeek_uid=net.zeek_uid,
                event_timestamp=event.timestamp,
                fuid=cert.fuid,
                position=depth,
            )
            event_data = {
                "ts": self._offset_timestamp(
                    event.timestamp,
                    max(
                        analyzer_delay_ms,
                        ssl_analyzer_delay_ms(
                            zeek_uid=net.zeek_uid,
                            event_timestamp=event.timestamp,
                        )
                        + 1,
                    ),
                ),
                "fuid": cert.fuid,
                "tx_hosts": [net.dst_ip],
                "rx_hosts": [net.src_ip],
                "_id.orig_h": net.src_ip,
                "_id.resp_h": net.dst_ip,
                "conn_uids": [net.zeek_uid] if net.zeek_uid else [],
                "source": "SSL",
                "depth": depth,
                "filename": None,
                "analyzers": ["X509"],
                "mime_type": "application/pkix-cert",
                "duration": None,
                "local_orig": _is_private_ip(net.dst_ip),
                "is_orig": False,
                "seen_bytes": size,
                "total_bytes": size,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "md5": cert_hashes["md5"],
                "sha1": cert_hashes["sha1"],
                "sha256": cert_hashes["sha256"],
                "_sensor_hostnames": sensor_hostnames,
            }
            if event._nat_swaps_by_sensor:
                event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
            self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "analyzers",
            "mime_type",
            "filename",
            "duration",
            "local_orig",
            "total_bytes",
            "md5",
            "sha1",
            "sha256",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        tx_hosts = event_data.get("tx_hosts")
        if isinstance(tx_hosts, list) and tx_hosts:
            event_data["local_orig"] = any(
                isinstance(host, str) and _is_private_ip(host) for host in tx_hosts
            )
        return self._render_zeek_json(event_data)


def _certificate_file_hashes(fingerprint: str) -> dict[str, str | None]:
    """Return independent file hashes for a certificate body.

    ``x509.fingerprint`` is the certificate SHA1 fingerprint. Zeek files.log
    hashes represent the same certificate bytes, so files.log ``sha1`` must match
    x509.log ``fingerprint`` for the same certificate fuid. Repeated observations
    of the same fingerprint must keep the same file hashes.
    """
    if not fingerprint:
        return {"md5": None, "sha1": None, "sha256": None}
    seed = f"zeek-cert-file:{fingerprint}"
    return {
        "md5": hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest(),
        "sha1": fingerprint,
        "sha256": hashlib.sha256(seed.encode()).hexdigest(),
    }


def _file_transfer_analyzer_timestamp(ts: datetime, zeek_uid: str, fuid: str) -> datetime:
    """Return a deterministic files.log analysis time after the conn start."""
    delay_ms = 25 + (_stable_seed(f"zeek-file-delay:{zeek_uid}:{fuid}") % 225)
    return ts + timedelta(milliseconds=delay_ms)


def _bounded_file_transfer_observation(
    conn_ts: datetime,
    conn_duration: float | None,
    zeek_uid: str,
    fuid: str,
    file_duration: float,
    min_start: datetime | None = None,
) -> tuple[datetime, float]:
    """Keep files.log observation timing inside the owning conn.log interval."""
    file_ts = _file_transfer_analyzer_timestamp(conn_ts, zeek_uid, fuid)
    if min_start is not None and file_ts < min_start:
        file_ts = min_start
    if conn_duration is None or conn_duration <= 0:
        return file_ts, file_duration

    epsilon = 0.001
    conn_end = conn_ts + timedelta(seconds=conn_duration)
    max_duration = max(0.0, conn_duration - epsilon)
    bounded_duration = min(max(0.0, file_duration), max_duration)
    latest_start = conn_end - timedelta(seconds=bounded_duration + epsilon)
    if file_ts > latest_start:
        file_ts = latest_start
    if file_ts < conn_ts:
        file_ts = conn_ts
    if file_ts + timedelta(seconds=bounded_duration) > conn_end:
        bounded_duration = max(0.0, (conn_end - file_ts).total_seconds() - epsilon)
    return file_ts, bounded_duration


def _related_http_analyzer_timestamp(event: SecurityEvent) -> datetime | None:
    """Return the owning HTTP analyzer timestamp when this file belongs to http.log."""
    net = event.network
    ft = event.file_transfer
    http = event.http
    if net is None or ft is None or http is None or ft.fuid not in http.resp_fuids:
        return None
    return (
        event.timestamp
        + sample_timing_delta(
            "source.zeek_http_request",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
        )
        + timedelta(milliseconds=1)
    )
