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
from evidenceforge.generation.activity.tls_realism import certificate_file_size
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.utils.rng import _stable_seed

_SOURCE_TIMING = SourceTimingPlanner()


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
                event.file_transfer is not None
                or bool(event.file_transfers)
                or bool(event.x509_chain)
                or event.x509 is not None
            )
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        file_transfers = list(event.file_transfers)
        if event.file_transfer is not None:
            file_transfers.insert(0, event.file_transfer)
        sensor_hostnames = event._sensor_hostnames_by_format.get(self.format_def.name, [])
        previous_file_ts: datetime | None = None
        for ft in file_transfers:
            min_start = _related_http_analyzer_timestamp(event)
            if previous_file_ts is not None:
                next_min_start = previous_file_ts + timedelta(microseconds=100)
                min_start = (
                    max(min_start, next_min_start) if min_start is not None else next_min_start
                )
            file_ts, file_duration = _bounded_file_transfer_observation(
                event,
                min_start=min_start,
                file_transfer=ft,
            )
            previous_file_ts = file_ts
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
                "local_orig": net.local_orig if ft.is_orig else net.local_resp,
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
                "local_orig": net.local_resp,
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


def _tls_connection_analysis_times(
    event: SecurityEvent,
) -> tuple[datetime, tuple[datetime, datetime] | None, datetime]:
    """Return conn bounds and the owning ssl.log analyzer timestamp."""
    net = event.network
    if net is None:
        return event.timestamp, None, event.timestamp
    conn_ts = _SOURCE_TIMING.source_time(
        event,
        "source.zeek_conn_start",
        seed_parts=(
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        ),
        not_before=event.timestamp,
    )
    within = None
    if net.duration is not None and net.duration > 0:
        latest = conn_ts + timedelta(seconds=max(0.0, net.duration - 0.000001))
        within = (conn_ts, latest)
    ssl_ts = _SOURCE_TIMING.source_time(
        event,
        "source.zeek_ssl_analyzer",
        seed_parts=(
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        ),
        not_before=conn_ts,
        within=within,
    )
    return conn_ts, within, ssl_ts


def _tls_certificate_gap(event: SecurityEvent, fuid: str, position: int, label: str) -> timedelta:
    """Return deterministic non-uniform spacing for certificate analyzer rows."""
    seed = _stable_seed(
        "zeek-tls-cert-gap:"
        f"{label}:{getattr(event.network, 'zeek_uid', '')}:{fuid}:"
        f"{position}:{event.timestamp.isoformat()}"
    )
    return timedelta(milliseconds=2 + (seed % 23), microseconds=103 + ((seed >> 8) % 853))


def _constrained_tls_timestamp(
    event: SecurityEvent,
    source_key: str,
    seed_parts: tuple[Any, ...],
    lower_bound: datetime,
    conn_ts: datetime,
    within: tuple[datetime, datetime] | None,
) -> datetime:
    """Return a bounded source timestamp without violating TLS row ordering."""
    net = event.network
    if within is not None and lower_bound > within[1]:
        lower_bound = within[1]
    preferred = _SOURCE_TIMING.source_time(
        event,
        source_key,
        seed_parts=seed_parts,
        not_before=lower_bound,
        within=within,
    )
    timestamp = _bounded_in_connection_timestamp(
        conn_ts,
        net.duration if net is not None else None,
        preferred,
    )
    return lower_bound if timestamp < lower_bound else timestamp


def _tls_certificate_file_timestamp(
    event: SecurityEvent,
    cert: Any,
    position: int,
    *,
    previous_file_timestamp: datetime | None,
) -> datetime:
    """Return the source-native files.log timestamp for one TLS certificate."""
    net = event.network
    if net is None:
        lower_bound = (
            event.timestamp
            if previous_file_timestamp is None
            else previous_file_timestamp + _tls_certificate_gap(event, cert.fuid, position, "file")
        )
        return _SOURCE_TIMING.source_time(
            event,
            "source.zeek_file_analyzer",
            seed_parts=("tls-cert-file", cert.fuid, position, event.timestamp),
            not_before=lower_bound,
        )
    conn_ts, within, ssl_ts = _tls_connection_analysis_times(event)
    gap = _tls_certificate_gap(event, cert.fuid, position, "file")
    lower_bound = ssl_ts + gap
    if previous_file_timestamp is not None:
        lower_bound = max(lower_bound, previous_file_timestamp + gap)
    return _constrained_tls_timestamp(
        event,
        "source.zeek_file_analyzer",
        (net.zeek_uid, "tls-cert-file", cert.fuid, position, event.timestamp),
        lower_bound,
        conn_ts,
        within,
    )


def _tls_certificate_x509_timestamp(
    event: SecurityEvent,
    cert: Any,
    position: int,
    *,
    file_timestamp: datetime,
    previous_x509_timestamp: datetime | None,
) -> datetime:
    """Return the source-native x509.log timestamp after its files.log object."""
    net = event.network
    gap = _tls_certificate_gap(event, cert.fuid, position, "x509")
    lower_bound = file_timestamp + gap
    if previous_x509_timestamp is not None:
        lower_bound = max(lower_bound, previous_x509_timestamp + gap)
    if net is None:
        return _SOURCE_TIMING.source_time(
            event,
            "source.zeek_x509_analyzer",
            seed_parts=("tls-cert-x509", cert.fuid, position, event.timestamp),
            not_before=lower_bound,
        )
    conn_ts, within, _ssl_ts = _tls_connection_analysis_times(event)
    return _constrained_tls_timestamp(
        event,
        "source.zeek_x509_analyzer",
        (net.zeek_uid, "tls-cert-x509", cert.fuid, position, event.timestamp),
        lower_bound,
        conn_ts,
        within,
    )


def _file_transfer_analyzer_timestamp(
    event: SecurityEvent,
    zeek_uid: str,
    fuid: str,
    conn_ts: datetime,
) -> datetime:
    """Return a deterministic files.log analysis time after the conn start."""
    net = event.network
    if event.http is not None and net is not None:
        http_seed_parts = (
            zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        )
        return _SOURCE_TIMING.source_time_after_source(
            event,
            "source.zeek_file_analyzer",
            after_source_key="source.zeek_http_request",
            gap_key="source.zeek_file_analyzer",
            seed_parts=(zeek_uid, fuid, event.timestamp),
            after_seed_parts=http_seed_parts,
            after_not_before=conn_ts,
            not_before=conn_ts + timedelta(milliseconds=1),
        )
    return _SOURCE_TIMING.source_time(
        event,
        "source.zeek_file_analyzer",
        seed_parts=(zeek_uid, fuid, event.timestamp),
        not_before=conn_ts + timedelta(milliseconds=1),
    )


def _bounded_file_transfer_observation(
    event: SecurityEvent,
    min_start: datetime | None = None,
    file_transfer: Any | None = None,
) -> tuple[datetime, float]:
    """Keep files.log observation timing inside the owning conn.log interval."""
    net = event.network
    ft = file_transfer or event.file_transfer
    if net is None or ft is None:
        return event.timestamp, 0.0
    conn_ts = _SOURCE_TIMING.source_time(
        event,
        "source.zeek_conn_start",
        seed_parts=(
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        ),
        not_before=event.timestamp,
    )
    conn_duration = net.duration
    file_duration = ft.duration
    file_ts = _file_transfer_analyzer_timestamp(event, net.zeek_uid, ft.fuid, conn_ts)
    lower_bound = max(conn_ts, min_start) if min_start is not None else conn_ts
    if ft.observation_not_before is not None:
        lower_bound = max(lower_bound, ft.observation_not_before)
    if file_ts < lower_bound:
        file_ts = lower_bound
    if conn_duration is None or conn_duration <= 0:
        return file_ts, file_duration

    epsilon = 0.001
    conn_end = conn_ts + timedelta(seconds=conn_duration)
    max_duration = max(0.0, conn_duration - epsilon)
    bounded_duration = min(max(0.0, file_duration), max_duration)
    latest_start = conn_end - timedelta(seconds=bounded_duration + epsilon)
    if lower_bound > latest_start:
        bounded_duration = max(0.0, (conn_end - lower_bound).total_seconds() - epsilon)
        latest_start = lower_bound
    if file_ts > latest_start and lower_bound <= latest_start:
        file_ts = latest_start
    if file_ts < lower_bound:
        file_ts = lower_bound
    if file_ts + timedelta(seconds=bounded_duration) > conn_end:
        bounded_duration = max(0.0, (conn_end - file_ts).total_seconds() - epsilon)
    return file_ts, bounded_duration


def _bounded_in_connection_timestamp(
    conn_ts: datetime,
    conn_duration: float | None,
    preferred_ts: datetime,
) -> datetime:
    """Keep source-side analyzer rows inside the owning conn.log lifetime."""
    if conn_duration is None or conn_duration <= 0:
        return max(conn_ts, preferred_ts)

    epsilon = 0.001
    conn_end = conn_ts + timedelta(seconds=conn_duration)
    latest_ts = conn_end - timedelta(seconds=epsilon)
    if preferred_ts > latest_ts:
        return latest_ts if latest_ts > conn_ts else conn_ts
    if preferred_ts < conn_ts:
        return conn_ts
    return preferred_ts


def _related_http_analyzer_timestamp(event: SecurityEvent) -> datetime | None:
    """Return the owning HTTP analyzer timestamp when this file belongs to http.log."""
    net = event.network
    ft = event.file_transfer
    http = event.http
    if net is None or ft is None or http is None or ft.fuid not in http.resp_fuids:
        return None
    conn_ts = _SOURCE_TIMING.source_time(
        event,
        "source.zeek_conn_start",
        seed_parts=(
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        ),
        not_before=event.timestamp,
    )
    return _SOURCE_TIMING.source_time(
        event,
        "source.zeek_http_request",
        seed_parts=(
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        ),
        not_before=conn_ts,
    ) + timedelta(milliseconds=1)
