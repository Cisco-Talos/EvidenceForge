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
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.tls_realism import certificate_analyzer_delay_ms
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
            event_data: dict[str, Any] = {
                "ts": event.timestamp,
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
                "duration": ft.duration,
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
            size = _certificate_file_size(cert)
            cert_hashes = _certificate_file_hashes(cert.fingerprint)
            analyzer_delay_ms = certificate_analyzer_delay_ms(
                zeek_uid=net.zeek_uid,
                event_timestamp=event.timestamp,
                fuid=cert.fuid,
                position=depth,
            )
            event_data = {
                "ts": self._offset_timestamp(event.timestamp, analyzer_delay_ms),
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
    hashes represent the file-analysis bytes for the same certificate. Repeated
    observations of the same fingerprint must therefore keep the same file hashes.
    """
    if not fingerprint:
        return {"md5": None, "sha1": None, "sha256": None}
    seed = f"zeek-cert-file:{fingerprint}"
    return {
        "md5": hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(seed.encode(), usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(seed.encode()).hexdigest(),
    }


def _certificate_file_size(cert: Any) -> int:
    """Return a stable file-analysis byte size for a rendered certificate."""
    identity = "|".join(
        [
            str(getattr(cert, "fingerprint", "")),
            str(getattr(cert, "certificate_subject", "")),
            str(getattr(cert, "certificate_issuer", "")),
            ",".join(str(name) for name in getattr(cert, "san_dns", []) or []),
        ]
    )
    rng = hashlib.sha256(identity.encode()).digest()
    key_overhead = int(getattr(cert, "certificate_key_length", 2048)) // 8
    san_overhead = 18 * len(getattr(cert, "san_dns", []) or [])
    ca_overhead = 220 if not getattr(cert, "host_cert", False) else 0
    subject_overhead = min(180, len(str(getattr(cert, "certificate_subject", ""))) * 2)
    issuer_overhead = min(220, len(str(getattr(cert, "certificate_issuer", ""))) * 2)
    jitter = _stable_seed(f"zeek-cert-size:{identity}:{rng.hex()}") % 420
    return (
        720
        + key_overhead
        + san_overhead
        + ca_overhead
        + subject_overhead
        + issuer_overhead
        + jitter
    )
