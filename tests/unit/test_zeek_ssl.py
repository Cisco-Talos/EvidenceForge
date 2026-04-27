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
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext, SslContext, X509Context
from evidenceforge.formats import load_format
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
        """ssl.cert_chain_fuids should reference the x509 certificate id."""
        ssl_fmt = load_format("zeek_ssl")
        x509_fmt = load_format("zeek_x509")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            ssl_emitter = ZeekSslEmitter(ssl_fmt, out_dir / "ssl.json")
            x509_emitter = ZeekX509Emitter(x509_fmt, out_dir / "x509.json")

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
                    fingerprint="abc123",
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
            )
            ssl_emitter.emit(event)
            x509_emitter.emit(event)
            ssl_emitter.close()
            x509_emitter.close()

            ssl_data = json.loads((out_dir / "ssl.json").read_text().splitlines()[0])
            x509_data = json.loads((out_dir / "x509.json").read_text().splitlines()[0])

            assert ssl_data["cert_chain_fuids"] == [x509_data["id"]]

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
