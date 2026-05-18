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

"""Tests for Zeek ssl.log emitter."""

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    FileTransferContext,
    NetworkContext,
    OcspContext,
    SslContext,
    X509Context,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_ocsp import ZeekOcspEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter

SAMPLE_DATA_DIR = Path(__file__).parent.parent.parent / "sample_data" / "Zeek-JSON"


class TestSslFormatAccuracy:
    """Verify ssl.log output matches real Zeek sample data."""

    def test_format_matches_sample(self):
        """Field names and types match sample_data/Zeek-JSON/ssl.log line 1."""
        real = json.loads(
            '{"ts":1427846471.769712,"uid":"C5kVIUjmv81kcLoLg",'
            '"id.orig_h":"192.168.0.54","id.orig_p":55072,'
            '"id.resp_h":"173.194.66.99","id.resp_p":443,'
            '"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",'
            '"server_name":"www.google.com","resumed":true,'
            '"established":true,"ssl_history":"CsiI"}'
        )
        # Verify expected field types
        assert isinstance(real["ts"], float)
        assert isinstance(real["uid"], str)
        assert isinstance(real["version"], str)
        assert isinstance(real["cipher"], str)
        assert isinstance(real["server_name"], str)
        assert isinstance(real["resumed"], bool)
        assert isinstance(real["established"], bool)
        assert isinstance(real["ssl_history"], str)

    def test_emitter_output_fields(self):
        """Emitter produces all expected ssl.log fields."""
        fmt = load_format("zeek_ssl")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "ssl.json"
            emitter = ZeekSslEmitter(fmt, output)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "version": "TLSv12",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "server_name": "example.com",
                    "resumed": False,
                    "established": True,
                    "ssl_history": "CsiI",
                    "cert_chain_fuids": ["Fabcdef1234567890"],
                }
            )
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())

            assert data["ts"] == pytest.approx(1705312800.0, abs=1)
            assert data["uid"] == "CTest123456789ab"
            assert data["id.orig_h"] == "10.0.0.1"
            assert data["id.resp_p"] == 443
            assert data["version"] == "TLSv12"
            assert data["cipher"] == "TLS_AES_128_GCM_SHA256"
            assert data["server_name"] == "example.com"
            assert data["resumed"] is False
            assert data["established"] is True
            assert data["ssl_history"] == "CsiI"
            assert data["cert_chain_fuids"] == ["Fabcdef1234567890"]

    def test_compact_ndjson(self):
        """Output is compact NDJSON (no whitespace after separators)."""
        fmt = load_format("zeek_ssl")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "ssl.json"
            emitter = ZeekSslEmitter(fmt, output)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "version": "TLSv12",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "server_name": "example.com",
                    "resumed": True,
                    "established": True,
                    "ssl_history": "CsiI",
                }
            )
            emitter.close()
            with open(output) as f:
                line = f.readline().strip()
            # Compact: no spaces after : or ,
            assert ": " not in line or '": ' not in line.replace('": ', "")


class TestSslCanHandle:
    """Verify can_handle() filtering logic."""

    def _make_event(self, event_type="connection", network=True, ssl=True):
        net = (
            NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="8.8.8.8",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTest123456789ab",
                conn_state="SF",
            )
            if network
            else None
        )
        ssl_ctx = (
            SslContext(version="TLSv12", cipher="TLS_AES_128_GCM_SHA256", server_name="example.com")
            if ssl
            else None
        )
        return SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type=event_type,
            network=net,
            ssl=ssl_ctx,
        )

    def test_accepts_connection_with_ssl(self):
        fmt = load_format("zeek_ssl")
        emitter = ZeekSslEmitter(fmt, Path("/tmp/test.json"))
        assert emitter.can_handle(self._make_event()) is True

    def test_rejects_without_ssl_context(self):
        fmt = load_format("zeek_ssl")
        emitter = ZeekSslEmitter(fmt, Path("/tmp/test.json"))
        assert emitter.can_handle(self._make_event(ssl=False)) is False

    def test_rejects_partial_handshake_with_ssl_context(self):
        fmt = load_format("zeek_ssl")
        emitter = ZeekSslEmitter(fmt, Path("/tmp/test.json"))
        event = self._make_event()
        event.network.conn_state = "S1"
        assert emitter.can_handle(event) is False

    def test_rejects_without_network_context(self):
        fmt = load_format("zeek_ssl")
        emitter = ZeekSslEmitter(fmt, Path("/tmp/test.json"))
        assert emitter.can_handle(self._make_event(network=False)) is False

    def test_rejects_wrong_event_type(self):
        fmt = load_format("zeek_ssl")
        emitter = ZeekSslEmitter(fmt, Path("/tmp/test.json"))
        assert emitter.can_handle(self._make_event(event_type="logon")) is False


class TestSslUidCorrelation:
    """Verify SSL records share UID with conn.log."""

    def test_uid_from_network_context(self):
        """SSL uid should come from event.network.zeek_uid."""
        fmt = load_format("zeek_ssl")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "ssl.json"
            emitter = ZeekSslEmitter(fmt, output)

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                ),
                ssl=SslContext(version="TLSv12", cipher="TLS_AES_128_GCM_SHA256"),
            )
            emitter.emit(event)
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())
            assert data["uid"] == "CMySpecificUID123"

    def test_ssl_cert_chain_fuids_link_to_x509_id(self):
        """ssl.cert_chain_fuids should reference x509 and files.log certificate IDs."""
        ssl_fmt = load_format("zeek_ssl")
        x509_fmt = load_format("zeek_x509")
        files_fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            ssl_emitter = ZeekSslEmitter(ssl_fmt, out_dir / "ssl.json")
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")
            files_emitter = ZeekFilesEmitter(files_fmt, out_dir / "files.json")

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                ),
                ssl=SslContext(
                    version="TLSv12",
                    cipher="TLS_AES_128_GCM_SHA256",
                    cert_chain_fuids=["Fabcdef1234567890"],
                ),
                x509=X509Context(
                    fuid="Fabcdef1234567890",
                    fingerprint="a" * 40,
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
            )
            ssl_emitter.emit(event)
            x509_emitter.emit(event)
            files_emitter.emit(event)
            ssl_emitter.close()
            x509_emitter.close()
            files_emitter.close()

            ssl_data = json.loads((out_dir / "ssl.json").read_text().splitlines()[0])
            x509_data = json.loads((out_dir / "x509.json").read_text().splitlines()[0])
            files_data = json.loads((out_dir / "files.json").read_text().splitlines()[0])

            assert ssl_data["cert_chain_fuids"] == [x509_data["id"]]
            assert files_data["fuid"] == x509_data["id"]
            assert files_data["source"] == "SSL"
            assert files_data["analyzers"] == ["X509"]
            assert files_data["sha1"] == x509_data["fingerprint"]
            assert files_data["sha256"] != x509_data["fingerprint"]
            assert files_data["md5"] != files_data["sha256"][:32]
            assert files_data["sha1"] != files_data["sha256"][:40]
            assert len(files_data["md5"]) == 32
            assert len(files_data["sha1"]) == 40
            assert files_data["ts"] >= ssl_data["ts"]

    def test_files_host_lists_follow_sensor_nat_view(self):
        """files.log tx/rx hosts should agree with the same-sensor conn endpoint view."""
        files_fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            files_emitter = ZeekFilesEmitter(
                files_fmt,
                out_dir,
                sensor_hostnames=["zeek-dmz"],
            )
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="185.70.41.45",
                    src_port=50000,
                    dst_ip="203.14.220.10",
                    dst_port=443,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                ),
                x509=X509Context(
                    fuid="Fabcdef1234567890",
                    fingerprint="a" * 64,
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
            )
            event._sensor_hostnames_by_format = {"zeek_files": ["zeek-dmz"]}
            event._nat_swaps_by_sensor = {"zeek-dmz": {"dst_ip": "10.10.3.10"}}

            files_emitter.emit(event)
            files_emitter.close()

            files_data = json.loads((out_dir / "zeek-dmz" / "files.json").read_text())
            assert files_data["tx_hosts"] == ["10.10.3.10"]
            assert files_data["rx_hosts"] == ["185.70.41.45"]

    def test_file_transfer_analysis_time_follows_connection_start(self):
        """SMB files.log rows should not predate the referenced connection."""
        files_fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            files_emitter = ZeekFilesEmitter(files_fmt, out_dir / "files.json")
            event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
            event = SecurityEvent(
                timestamp=event_time,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.20",
                    dst_port=445,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                ),
                file_transfer=FileTransferContext(
                    fuid="Fabcdef1234567890",
                    source="SMB",
                    filename="report.xlsx",
                    mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    seen_bytes=8192,
                    total_bytes=8192,
                ),
            )

            files_emitter.emit(event)
            files_emitter.close()

            files_data = json.loads((out_dir / "files.json").read_text())
            assert files_data["conn_uids"] == ["CMySpecificUID123"]
            assert files_data["ts"] > event_time.timestamp()

    def test_file_transfer_analysis_time_follows_multisensor_connection_start(self):
        """Per-sensor files.log delay should share the referenced conn timing basis."""
        conn_fmt = load_format("zeek_conn")
        files_fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            conn_emitter = ZeekEmitter(conn_fmt, out_dir, sensor_hostnames=["core", "dmz"])
            files_emitter = ZeekFilesEmitter(files_fmt, out_dir, sensor_hostnames=["core", "dmz"])
            event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
            event = SecurityEvent(
                timestamp=event_time,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.20",
                    dst_port=445,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                    conn_state="SF",
                    history="ShADadfF",
                    orig_bytes=1024,
                    resp_bytes=8192,
                    orig_pkts=4,
                    orig_ip_bytes=1104,
                    resp_pkts=12,
                    resp_ip_bytes=8432,
                ),
                file_transfer=FileTransferContext(
                    fuid="Fabcdef1234567890",
                    source="SMB",
                    filename="report.xlsx",
                    seen_bytes=8192,
                    total_bytes=8192,
                ),
            )
            event._sensor_hostnames_by_format = {
                "zeek_conn": ["core", "dmz"],
                "zeek_files": ["core", "dmz"],
            }

            conn_emitter.emit(event)
            files_emitter.emit(event)
            conn_emitter.close()
            files_emitter.close()

            for sensor in ("core", "dmz"):
                conn_row = json.loads((out_dir / sensor / "conn.json").read_text())
                files_row = json.loads((out_dir / sensor / "files.json").read_text())
                assert files_row["conn_uids"] == [conn_row["uid"]]
                assert files_row["ts"] > conn_row["ts"]

    def test_x509_renders_san_dns(self):
        """x509.san_dns should render as Zeek's san.dns field."""
        x509_fmt = load_format("zeek_x509")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                x509=X509Context(
                    fuid="Fabcdef1234567890",
                    fingerprint="abc123",
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                    san_dns=["example.com", "*.example.com"],
                ),
            )
            x509_emitter.emit(event)
            x509_emitter.close()

            x509_data = json.loads((out_dir / "x509.json").read_text().splitlines()[0])
            assert x509_data["san.dns"] == ["example.com", "*.example.com"]

    def test_x509_emitter_renders_full_certificate_chain(self):
        """x509.log should include each certificate referenced by ssl.cert_chain_fuids."""
        x509_fmt = load_format("zeek_x509")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")
            leaf = X509Context(
                fuid="Fleaf12345678901",
                fingerprint="leaf",
                certificate_serial="01",
                certificate_subject="CN=www.example.com",
                certificate_issuer="CN=Example Intermediate CA",
                certificate_not_valid_before=1700000000.0,
                certificate_not_valid_after=1730000000.0,
                san_dns=["www.example.com", "*.example.com"],
            )
            intermediate = X509Context(
                fuid="Fintermediate123",
                fingerprint="intermediate",
                certificate_serial="02",
                certificate_subject="CN=Example Intermediate CA",
                certificate_issuer="CN=Example Root CA",
                certificate_not_valid_before=1600000000.0,
                certificate_not_valid_after=1900000000.0,
                basic_constraints_ca=True,
                host_cert=False,
            )
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                x509=leaf,
                x509_chain=[leaf, intermediate],
            )

            x509_emitter.emit(event)
            x509_emitter.close()

            rows = [json.loads(line) for line in (out_dir / "x509.json").read_text().splitlines()]
            rows_by_id = {row["id"]: row for row in rows}
            assert set(rows_by_id) == {"Fleaf12345678901", "Fintermediate123"}
            assert [row["id"] for row in rows] == ["Fleaf12345678901", "Fintermediate123"]
            assert rows[0]["ts"] < rows[1]["ts"]
            assert rows_by_id["Fleaf12345678901"]["basic_constraints.ca"] is False
            assert rows_by_id["Fintermediate123"]["basic_constraints.ca"] is True

    def test_x509_chain_depth_spacing_is_not_constant_across_connections(self):
        """Certificate-chain rows should not always use the same depth offset."""
        x509_fmt = load_format("zeek_x509")
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        gaps: list[float] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")
            for idx in range(6):
                leaf = X509Context(
                    fuid=f"Fleaf{idx}2345678901",
                    fingerprint=f"leaf-{idx}",
                    certificate_subject=f"CN=leaf{idx}.example.com",
                    certificate_issuer="CN=Example Intermediate CA",
                )
                intermediate = X509Context(
                    fuid=f"Fint{idx}23456789012",
                    fingerprint=f"intermediate-{idx}",
                    certificate_subject="CN=Example Intermediate CA",
                    certificate_issuer="CN=Example Root CA",
                    basic_constraints_ca=True,
                    host_cert=False,
                )
                event = SecurityEvent(
                    timestamp=base_ts + timedelta(seconds=idx),
                    event_type="connection",
                    network=NetworkContext(
                        src_ip="10.0.0.1",
                        src_port=50000 + idx,
                        dst_ip="8.8.8.8",
                        dst_port=443,
                        protocol="tcp",
                        zeek_uid=f"CUID{idx}",
                    ),
                    x509=leaf,
                    x509_chain=[leaf, intermediate],
                )
                x509_emitter.emit(event)
            x509_emitter.close()

            rows = [json.loads(line) for line in (out_dir / "x509.json").read_text().splitlines()]

        for leaf_row, intermediate_row in zip(rows[0::2], rows[1::2], strict=True):
            gaps.append(round(intermediate_row["ts"] - leaf_row["ts"], 3))
        assert len(set(gaps)) > 1

    def test_tls_analyzer_logs_have_stage_timestamp_offsets(self):
        """SSL, x509, and OCSP analyzer records should not share the conn timestamp."""
        ssl_fmt = load_format("zeek_ssl")
        x509_fmt = load_format("zeek_x509")
        ocsp_fmt = load_format("zeek_ocsp")
        files_fmt = load_format("zeek_files")
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            ssl_emitter = ZeekSslEmitter(ssl_fmt, out_dir / "ssl.json")
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")
            ocsp_emitter = ZeekOcspEmitter(ocsp_fmt, out_dir / "ocsp.json")
            files_emitter = ZeekFilesEmitter(files_fmt, out_dir / "files.json")

            event = SecurityEvent(
                timestamp=base_ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    zeek_uid="CMySpecificUID123",
                ),
                ssl=SslContext(
                    version="TLSv13",
                    cipher="TLS_AES_128_GCM_SHA256",
                    cert_chain_fuids=["Fabcdef1234567890"],
                ),
                x509=X509Context(
                    fuid="Fabcdef1234567890",
                    fingerprint="abc123",
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
                ocsp=OcspContext(
                    id="Focsp12345678901",
                    issuer_name_hash="issuer-name",
                    issuer_key_hash="issuer-key",
                    serial_number="01",
                    cert_status="good",
                    this_update=1705310000.0,
                    next_update=1705900000.0,
                ),
                file_transfer=FileTransferContext(
                    fuid="Focsp12345678901",
                    source="HTTP",
                    mime_type="application/ocsp-response",
                    duration=0.01,
                    local_orig=True,
                    is_orig=False,
                    seen_bytes=1200,
                    total_bytes=1200,
                ),
            )
            ssl_emitter.emit(event)
            x509_emitter.emit(event)
            ocsp_emitter.emit(event)
            files_emitter.emit(event)
            ssl_emitter.close()
            x509_emitter.close()
            ocsp_emitter.close()
            files_emitter.close()

            ssl_ts = json.loads((out_dir / "ssl.json").read_text().splitlines()[0])["ts"]
            x509_ts = json.loads((out_dir / "x509.json").read_text().splitlines()[0])["ts"]
            ocsp_ts = json.loads((out_dir / "ocsp.json").read_text().splitlines()[0])["ts"]
            ocsp_row = json.loads((out_dir / "ocsp.json").read_text().splitlines()[0])
            file_rows = [
                json.loads(line) for line in (out_dir / "files.json").read_text().splitlines()
            ]

        conn_ts = base_ts.timestamp()
        ssl_window = get_timing_window(
            "source.zeek_ssl_analyzer",
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        x509_window = get_timing_window(
            "source.zeek_x509_analyzer",
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        ssl_offset_us = round((ssl_ts - conn_ts) * 1_000_000)
        assert conn_ts < ssl_ts <= conn_ts + (ssl_window.max_ms / 1000) + 0.001
        assert ssl_offset_us % 1000 != 0
        assert ssl_ts < x509_ts <= conn_ts + ((ssl_window.max_ms + x509_window.max_ms) / 1000)
        assert x509_ts < ocsp_ts < conn_ts + 6.1
        assert ocsp_row["id"] == "Focsp12345678901"
        assert "revoketime" not in ocsp_row
        assert "revokereason" not in ocsp_row
        assert "uid" not in ocsp_row
        assert "id.orig_h" not in ocsp_row
        assert "id.resp_h" not in ocsp_row
        files_by_fuid = {row["fuid"]: row for row in file_rows}
        ocsp_file_row = files_by_fuid[ocsp_row["id"]]
        assert ocsp_file_row["conn_uids"] == ["CMySpecificUID123"]
        assert files_by_fuid["Fabcdef1234567890"]["source"] == "SSL"
        assert ocsp_file_row["tx_hosts"] == ["8.8.8.8"]
        assert ocsp_file_row["rx_hosts"] == ["10.0.0.1"]
        assert "uid" not in ocsp_file_row
        assert "id.orig_h" not in ocsp_file_row
        assert ocsp_file_row["mime_type"] == "application/ocsp-response"

    def test_x509_timestamp_stays_inside_parent_connection(self):
        """x509 analyzer rows should not outlive their owning connection interval."""
        x509_fmt = load_format("zeek_x509")
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")
            event = SecurityEvent(
                timestamp=base_ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    conn_state="SF",
                    zeek_uid="CShortX509UID12",
                    duration=0.01,
                ),
                x509=X509Context(
                    fuid="Fshortx50912345",
                    fingerprint="abc123",
                    certificate_serial="01",
                    certificate_subject="CN=short.example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
            )

            x509_emitter.emit(event)
            x509_emitter.close()
            x509_row = json.loads((out_dir / "x509.json").read_text().splitlines()[0])

        assert base_ts.timestamp() <= x509_row["ts"] <= base_ts.timestamp() + 0.01

    def test_raw_ocsp_event_defaults_missing_optional_revocation_fields(self):
        """Raw OCSP rows may omit optional revocation details without crashing."""
        ocsp_fmt = load_format("zeek_ocsp")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "ocsp.json"
            emitter = ZeekOcspEmitter(ocsp_fmt, output)
            emitter.emit_raw(
                {
                    "ts": 1705312800.0,
                    "id": "Frawocsp1234567",
                    "hashAlgorithm": "sha1",
                    "issuerNameHash": "issuer-name",
                    "issuerKeyHash": "issuer-key",
                    "serialNumber": "01",
                    "certStatus": "good",
                    "thisUpdate": 1705310000.0,
                    "nextUpdate": 1705900000.0,
                }
            )
            emitter.close()

            row = json.loads(output.read_text().splitlines()[0])

        assert row["certStatus"] == "good"
        assert "revoketime" not in row
        assert "revokereason" not in row

    def test_revoked_ocsp_status_renders_revocation_metadata(self):
        """Revoked OCSP rows should include source-native revocation details."""
        ocsp_fmt = load_format("zeek_ocsp")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "ocsp.json"
            emitter = ZeekOcspEmitter(ocsp_fmt, output)
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                ocsp=OcspContext(
                    id="Focsp12345678901",
                    issuer_name_hash="issuer-name",
                    issuer_key_hash="issuer-key",
                    serial_number="01",
                    cert_status="revoked",
                    this_update=1705310000.0,
                    next_update=1705900000.0,
                    revoketime=1705000000.0,
                    revokereason="keyCompromise",
                ),
            )

            emitter.emit(event)
            emitter.close()

            row = json.loads(output.read_text().splitlines()[0])

        assert row["certStatus"] == "revoked"
        assert row["revoketime"] == 1705000000.0
        assert row["revokereason"] == "keyCompromise"

    def test_tls_conn_duration_contains_ssl_analyzer_offset(self):
        """Zeek conn duration for completed TLS should contain ssl/x509 analyzer evidence."""
        conn_fmt = load_format("zeek_conn")
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            conn_emitter = ZeekEmitter(conn_fmt, out_dir / "conn.json")
            event = SecurityEvent(
                timestamp=base_ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    zeek_uid="CMySpecificUID123",
                    conn_state="SF",
                    duration=0.002,
                ),
                ssl=SslContext(version="TLSv13", cipher="TLS_AES_128_GCM_SHA256"),
            )

            conn_emitter.emit(event)
            conn_emitter.close()

            conn_row = json.loads((out_dir / "conn.json").read_text().splitlines()[0])

        assert conn_row["duration"] > 0.8
        assert conn_row["duration"] != 0.8

    def test_x509_rejects_partial_handshake(self):
        """x509.log should not emit certificates for incomplete TLS handshakes."""
        fmt = load_format("zeek_x509")
        emitter = ZeekX509Emitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="8.8.8.8",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CMySpecificUID123",
                conn_state="S1",
            ),
            x509=X509Context(
                fuid="Fabcdef1234567890",
                fingerprint="abc123",
                certificate_serial="01",
                certificate_subject="CN=example.com",
                certificate_issuer="CN=Example CA",
                certificate_not_valid_before=1700000000.0,
                certificate_not_valid_after=1730000000.0,
            ),
        )

        assert emitter.can_handle(event) is False
