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
from datetime import datetime
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.generation.activity.tls_realism import certificate_file_size
from evidenceforge.generation.emitters.zeek_base import (
    SensorMultiplexEmitter,
    direct_zeek_source_duration,
    direct_zeek_source_time,
)
from evidenceforge.generation.network_observation import network_source_timing_key


class ZeekFilesEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek files.log format (NDJSON).

    Generates file transfer metadata logs. Requires NetworkTransactionPlan plus either
    FileTransferContext or TLS X.509 certificate contexts. Uses own fuid
    (F-prefix) alongside conn.log uid.
    """

    _log_filename = "files.json"
    _flat_filename = "zeek_files.json"
    _supported_types: set[str] = {"connection", "smb_file_read", "smb_file_write"}

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and not (event.smb is not None and event.smb.encrypted)
            and (
                event.protocol.primary_file_transfer is not None
                or bool(event.protocol.file_transfers)
                or bool(event.protocol.x509_chain)
                or event.protocol.leaf_certificate is not None
            )
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        net = event.network
        file_transfers = sorted(
            event.protocol.file_transfers, key=lambda transfer: not transfer.is_orig
        )
        sensor_metadata = self._sensor_metadata(event, self.format_def.name)
        for ft in file_transfers:
            file_ts, file_duration = _bounded_file_transfer_observation(
                event,
                file_transfer=ft,
            )
            timing_key = network_source_timing_key("zeek_files", ft.fuid)
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
                "local_orig": net.local_orig,
                "is_orig": ft.is_orig,
                "seen_bytes": ft.seen_bytes,
                "total_bytes": ft.total_bytes,
                "missing_bytes": ft.missing_bytes,
                "overflow_bytes": ft.overflow_bytes,
                "timedout": ft.timedout,
                "md5": ft.md5 or None,
                "sha1": ft.sha1 or None,
                "sha256": ft.sha256 or None,
                "_source_timing_key": timing_key,
                "_source_duration_key": timing_key,
                **sensor_metadata,
            }
            self.emit_event(event_data)

        certificates = event.protocol.x509_chain
        previous_cert_ts: datetime | None = None
        for depth, cert in enumerate(certificates):
            size = certificate_file_size(cert)
            cert_hashes = _certificate_file_hashes(cert.fingerprint)
            cert_ts = _tls_certificate_file_timestamp(
                event,
                cert,
                depth,
                previous_file_timestamp=previous_cert_ts,
            )
            previous_cert_ts = cert_ts
            timing_key = network_source_timing_key("zeek_files", cert.fuid)
            event_data = {
                "ts": cert_ts,
                "fuid": cert.fuid,
                "tx_hosts": [net.dst_ip],
                "rx_hosts": [net.src_ip],
                "_id.orig_h": net.src_ip,
                "_id.resp_h": net.dst_ip,
                "conn_uids": [net.zeek_uid] if net.zeek_uid else [],
                "source": "SSL",
                "depth": depth,
                "filename": None,
                "analyzers": ["X509", "MD5", "SHA1", "SHA256"],
                "mime_type": "application/pkix-cert",
                "duration": None,
                "local_orig": net.local_orig,
                "is_orig": False,
                "seen_bytes": size,
                "total_bytes": size,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "md5": cert_hashes["md5"],
                "sha1": cert_hashes["sha1"],
                "sha256": cert_hashes["sha256"],
                "_source_timing_key": timing_key,
                **sensor_metadata,
            }
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


def _tls_certificate_file_timestamp(
    event: CanonicalOccurrence,
    cert: Any,
    position: int,
    *,
    previous_file_timestamp: datetime | None,
) -> datetime:
    """Return one planner-frozen TLS certificate files.log timestamp."""

    del position, previous_file_timestamp
    return _frozen_source_time(
        event,
        network_source_timing_key("zeek_files", cert.fuid),
        _canonical_network_anchor(event),
    )


def _tls_certificate_x509_timestamp(
    event: CanonicalOccurrence,
    cert: Any,
    position: int,
    *,
    file_timestamp: datetime,
    previous_x509_timestamp: datetime | None,
) -> datetime:
    """Return one planner-frozen x509.log timestamp."""

    del position, file_timestamp, previous_x509_timestamp
    return _frozen_source_time(
        event,
        network_source_timing_key("zeek_x509", cert.fuid),
        _canonical_network_anchor(event),
    )


def _bounded_file_transfer_observation(
    event: CanonicalOccurrence,
    min_start: datetime | None = None,
    file_transfer: Any | None = None,
) -> tuple[datetime, float]:
    """Return planner-frozen files.log timing for compatibility callers."""

    ft = file_transfer or event.protocol.primary_file_transfer
    if ft is None:
        return event.timestamp, 0.0
    key = network_source_timing_key("zeek_files", ft.fuid)
    candidates = [
        candidate
        for candidate in (
            _canonical_network_anchor(event),
            min_start,
            ft.observation_not_before,
        )
        if candidate is not None
    ]
    timestamp = _frozen_source_time(event, key, max(candidates))
    duration = _frozen_source_duration(event, key)
    return timestamp, ft.duration if duration is None else duration


def _related_http_analyzer_timestamp(
    event: CanonicalOccurrence, ft: Any | None = None
) -> datetime | None:
    """Return the planner-frozen owning HTTP analyzer timestamp."""

    net = event.network
    if ft is None:
        ft = event.protocol.primary_file_transfer
    http = event.protocol.http
    if net is None or ft is None or http is None:
        return None
    if ft.fuid not in (*http.orig_fuids, *http.resp_fuids):
        return None
    return _frozen_source_time(
        event,
        network_source_timing_key("zeek_http"),
        http.canonical_request_time or net.started_at,
    )


def _canonical_network_anchor(event: CanonicalOccurrence) -> datetime:
    """Return the immutable canonical network start for direct emitter callers."""

    return event.network.started_at if event.network is not None else event.timestamp


def _frozen_source_time(
    event: CanonicalOccurrence,
    key: str,
    fallback: datetime,
) -> datetime:
    """Read one source-native timestamp without planning or repairing it."""

    for observation in event.network_observations:
        timestamp = observation.source_time(key)
        if timestamp is not None:
            return timestamp
    if event.network_observations_planned:
        return fallback
    timestamp = direct_zeek_source_time(event, key)
    return timestamp if timestamp is not None else fallback


def _frozen_source_duration(event: CanonicalOccurrence, key: str) -> float | None:
    """Read one source-native duration without emitter-side bounding."""

    for observation in event.network_observations:
        duration = observation.source_duration(key)
        if duration is not None:
            return duration
    if event.network_observations_planned:
        return None
    return direct_zeek_source_duration(event, key)
