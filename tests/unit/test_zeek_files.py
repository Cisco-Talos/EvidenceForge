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

"""Tests for Zeek files.log emitter."""

import json
import random
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    FileTransferContext,
    HttpContext,
    NetworkContext,
    SslContext,
    X509Context,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter


class TestFilesFormatAccuracy:
    """Verify files.log output matches real Zeek sample data."""

    def test_format_matches_sample(self):
        """Field names and types match sample_data/Zeek-JSON/files.log line 1."""
        real = json.loads(
            '{"ts":1427847434.287139,"fuid":"FheZAo1hKNan3xnZCd",'
            '"tx_hosts":["74.125.71.103"],"rx_hosts":["192.168.0.51"],'
            '"conn_uids":["Chs9FGiGqSvNnbrAk"],'
            '"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain",'
            '"duration":0.0,"local_orig":false,"is_orig":false,"seen_bytes":341,'
            '"missing_bytes":0,"overflow_bytes":0,"timedout":false}'
        )
        assert real["fuid"].startswith("F")
        assert real["conn_uids"][0].startswith("C")
        assert isinstance(real["tx_hosts"], list)
        assert isinstance(real["rx_hosts"], list)
        assert isinstance(real["analyzers"], list)
        assert isinstance(real["seen_bytes"], int)
        assert isinstance(real["is_orig"], bool)
        assert isinstance(real["timedout"], bool)

    def test_emitter_output_fields(self):
        """Emitter produces all files.log fields with correct types."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "fuid": "FTest12345678901",
                    "tx_hosts": ["93.184.216.34"],
                    "rx_hosts": ["10.0.0.1"],
                    "conn_uids": ["CTest123456789ab"],
                    "source": "HTTP",
                    "depth": 0,
                    "analyzers": [],
                    "mime_type": "text/html",
                    "duration": 0.005,
                    "local_orig": False,
                    "is_orig": False,
                    "seen_bytes": 1024,
                    "total_bytes": 1024,
                    "missing_bytes": 0,
                    "overflow_bytes": 0,
                    "timedout": False,
                }
            )
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())

            assert data["fuid"] == "FTest12345678901"
            assert data["conn_uids"] == ["CTest123456789ab"]
            assert data["tx_hosts"] == ["93.184.216.34"]
            assert data["rx_hosts"] == ["10.0.0.1"]
            assert data["source"] == "HTTP"
            assert data["analyzers"] == []
            assert data["seen_bytes"] == 1024
            assert data["is_orig"] is False
            assert data["timedout"] is False

    def test_local_orig_follows_transmitting_host(self):
        """Zeek files.local_orig describes the file transmitter, not the connection originator."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "fuid": "FExternalCert123",
                    "tx_hosts": ["91.189.91.39"],
                    "rx_hosts": ["10.10.3.20"],
                    "conn_uids": ["CExternalCert123"],
                    "source": "SSL",
                    "depth": 0,
                    "analyzers": ["X509"],
                    "mime_type": "application/pkix-cert",
                    "duration": None,
                    "local_orig": True,
                    "is_orig": False,
                    "seen_bytes": 1024,
                    "total_bytes": 1024,
                    "missing_bytes": 0,
                    "overflow_bytes": 0,
                    "timedout": False,
                }
            )
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
                    "fuid": "FLocalServerCert",
                    "tx_hosts": ["10.10.3.10"],
                    "rx_hosts": ["113.160.39.29"],
                    "conn_uids": ["CLocalServerCert"],
                    "source": "SSL",
                    "depth": 0,
                    "analyzers": ["X509"],
                    "mime_type": "application/pkix-cert",
                    "duration": None,
                    "local_orig": False,
                    "is_orig": False,
                    "seen_bytes": 1024,
                    "total_bytes": 1024,
                    "missing_bytes": 0,
                    "overflow_bytes": 0,
                    "timedout": False,
                }
            )
            emitter.close()

            rows = [json.loads(line) for line in output.read_text().splitlines()]
            assert rows[0]["local_orig"] is False
            assert rows[1]["local_orig"] is True

    def test_fuid_has_f_prefix(self):
        """fuid should start with 'F' prefix."""
        from evidenceforge.utils.ids import generate_zeek_uid

        fuid = generate_zeek_uid("F")
        assert fuid.startswith("F")
        assert 17 <= len(fuid) <= 19


class TestFilesCanHandle:
    """Verify can_handle() filtering."""

    def test_accepts_connection_with_file_transfer(self):
        fmt = load_format("zeek_files")
        emitter = ZeekFilesEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1", src_port=50000, dst_ip="8.8.8.8", dst_port=80, protocol="tcp"
            ),
            file_transfer=FileTransferContext(fuid="FTest12345678901", source="HTTP"),
        )
        assert emitter.can_handle(event) is True

    def test_accepts_smb_file_transfer_source(self):
        fmt = load_format("zeek_files")
        emitter = ZeekFilesEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="10.0.0.10",
                dst_port=445,
                protocol="tcp",
                zeek_uid="CConnUID12345678",
            ),
            file_transfer=FileTransferContext(
                fuid="FFileUID12345678",
                source="SMB",
                seen_bytes=4096,
            ),
        )
        assert emitter.can_handle(event) is True

    def test_rejects_without_file_transfer(self):
        fmt = load_format("zeek_files")
        emitter = ZeekFilesEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1", src_port=50000, dst_ip="8.8.8.8", dst_port=80, protocol="tcp"
            ),
        )
        assert emitter.can_handle(event) is False


class TestFilesUidCorrelation:
    """Verify files.log has conn_uids and fuid for cross-log correlation."""

    def test_conn_uids_present(self):
        """Output should have conn_uids (conn correlation) and fuid (file tracking)."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=80,
                    protocol="tcp",
                    zeek_uid="CConnUID12345678",
                ),
                file_transfer=FileTransferContext(
                    fuid="FFileUID12345678",
                    source="HTTP",
                    seen_bytes=100,
                ),
            )
            emitter.emit(event)
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())
            assert data["conn_uids"] == ["CConnUID12345678"]
            assert data["fuid"] == "FFileUID12345678"
            assert "uid" not in data
            assert "id.orig_h" not in data

    def test_file_transfer_timestamp_stays_within_parent_connection(self):
        """files.log observations should not begin after the owning conn closes."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=445,
                    protocol="tcp",
                    zeek_uid="CConnUID12345678",
                    duration=0.08,
                ),
                file_transfer=FileTransferContext(
                    fuid="FFileUID12345678",
                    source="SMB",
                    duration=0.06,
                    seen_bytes=4096,
                ),
            )

            emitter.emit(event)
            emitter.close()

            data = json.loads(output.read_text().splitlines()[0])

        assert data["ts"] >= event.timestamp.timestamp()
        assert data["ts"] + data["duration"] <= event.timestamp.timestamp() + 0.08

    def test_http_file_transfer_timestamp_follows_parent_http_record(self):
        """HTTP response files should not predate the owning http.log row."""
        files_fmt = load_format("zeek_files")
        http_fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            http_output = Path(tmpdir) / "http.json"
            files_output = Path(tmpdir) / "files.json"
            http_emitter = ZeekHttpEmitter(http_fmt, http_output)
            files_emitter = ZeekFilesEmitter(files_fmt, files_output)
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=80,
                    protocol="tcp",
                    service="http",
                    zeek_uid="CHttpUID1234567",
                    duration=2.0,
                ),
                http=HttpContext(
                    host="updates.example.test",
                    uri="/agent.dat",
                    resp_fuids=["FHttpFile1234567"],
                    resp_mime_types=["application/octet-stream"],
                ),
                file_transfer=FileTransferContext(
                    fuid="FHttpFile1234567",
                    source="HTTP",
                    duration=0.04,
                    seen_bytes=8192,
                ),
            )

            http_emitter.emit(event)
            files_emitter.emit(event)
            http_emitter.close()
            files_emitter.close()

            http_row = json.loads(http_output.read_text().splitlines()[0])
            file_row = json.loads(files_output.read_text().splitlines()[0])

        assert file_row["ts"] > http_row["ts"]

    def test_certificate_file_timestamp_follows_parent_ssl_record(self):
        """Certificate files should not predate the owning ssl.log row."""
        files_fmt = load_format("zeek_files")
        ssl_fmt = load_format("zeek_ssl")
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_output = Path(tmpdir) / "ssl.json"
            files_output = Path(tmpdir) / "files.json"
            ssl_emitter = ZeekSslEmitter(ssl_fmt, ssl_output)
            files_emitter = ZeekFilesEmitter(files_fmt, files_output)
            cert = X509Context(
                fuid="FCertFile123456",
                fingerprint="a" * 40,
                certificate_subject="CN=updates.example.test",
                certificate_issuer="CN=Example Issuer",
            )
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    conn_state="SF",
                    zeek_uid="CSslUID12345678",
                    duration=2.0,
                ),
                ssl=SslContext(
                    server_name="updates.example.test",
                    cert_chain_fuids=[cert.fuid],
                ),
                x509=cert,
            )

            ssl_emitter.emit(event)
            files_emitter.emit(event)
            ssl_emitter.close()
            files_emitter.close()

            ssl_row = json.loads(ssl_output.read_text().splitlines()[0])
            file_row = json.loads(files_output.read_text().splitlines()[0])

        assert file_row["ts"] > ssl_row["ts"]

    def test_certificate_file_timestamps_follow_chain_depth_order(self):
        """Certificate file observations should preserve TLS chain order."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            leaf = X509Context(
                fuid="FLeafCert123456",
                fingerprint="b" * 40,
                certificate_subject="CN=updates.example.test",
                certificate_issuer="CN=Example Intermediate",
                host_cert=True,
            )
            intermediate = X509Context(
                fuid="FInterCert12345",
                fingerprint="c" * 40,
                certificate_subject="CN=Example Intermediate",
                certificate_issuer="CN=Example Root",
                host_cert=False,
            )
            root = X509Context(
                fuid="FRootCert123456",
                fingerprint="d" * 40,
                certificate_subject="CN=Example Root",
                certificate_issuer="CN=Example Root",
                host_cert=False,
            )
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    conn_state="SF",
                    zeek_uid="CChainUID123456",
                    duration=2.0,
                ),
                ssl=SslContext(
                    server_name="updates.example.test",
                    cert_chain_fuids=[leaf.fuid, intermediate.fuid, root.fuid],
                ),
                x509=leaf,
                x509_chain=[leaf, intermediate, root],
            )

            emitter.emit(event)
            emitter.close()

            rows = [json.loads(line) for line in output.read_text().splitlines()]

        by_depth = {row["depth"]: row for row in rows}
        assert by_depth[0]["fuid"] == leaf.fuid
        assert by_depth[1]["fuid"] == intermediate.fuid
        assert by_depth[2]["fuid"] == root.fuid
        assert by_depth[0]["ts"] < by_depth[1]["ts"]
        assert by_depth[1]["ts"] < by_depth[2]["ts"]

    def test_same_certificate_fingerprint_keeps_file_hashes(self):
        """Repeated observations of the same cert bytes should keep all hashes stable."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            for idx, fuid in enumerate(("Fcert11111111111", "Fcert22222222222")):
                event = SecurityEvent(
                    timestamp=datetime(2024, 1, 15, 10, 0, idx, tzinfo=UTC),
                    event_type="connection",
                    network=NetworkContext(
                        src_ip="10.0.0.1",
                        src_port=50000 + idx,
                        dst_ip="8.8.8.8",
                        dst_port=443,
                        protocol="tcp",
                        zeek_uid=f"CConnUID{idx}",
                    ),
                    x509=X509Context(
                        fuid=fuid,
                        fingerprint="a" * 40,
                        certificate_serial="01",
                        certificate_subject="CN=example.com",
                        certificate_issuer="CN=Example CA",
                    ),
                )
                emitter.emit(event)
            emitter.close()

            rows = [json.loads(line) for line in output.read_text().splitlines()]

        assert len(rows) == 2
        assert rows[0]["sha256"] == rows[1]["sha256"]
        assert rows[0]["sha1"] == "a" * 40
        assert rows[0]["sha256"] != "a" * 40
        assert rows[0]["md5"] == rows[1]["md5"]
        assert rows[0]["sha1"] == rows[1]["sha1"]

    def test_certificate_file_sizes_vary_by_certificate_identity(self):
        """Certificate files should not collapse into a few fixed byte buckets."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)
            for idx, name in enumerate(("api.example.com", "cdn.example.net", "login.example.org")):
                event = SecurityEvent(
                    timestamp=datetime(2024, 1, 15, 10, 0, idx, tzinfo=UTC),
                    event_type="connection",
                    network=NetworkContext(
                        src_ip="10.0.0.1",
                        src_port=50000 + idx,
                        dst_ip="8.8.8.8",
                        dst_port=443,
                        protocol="tcp",
                        zeek_uid=f"CConnUID{idx}",
                    ),
                    x509=X509Context(
                        fuid=f"Fcert{idx}111111111",
                        fingerprint=f"{idx}" * 64,
                        certificate_subject=f"CN={name}",
                        certificate_issuer="CN=Example CA",
                        san_dns=[name],
                    ),
                )
                emitter.emit(event)
            emitter.close()

            rows = [json.loads(line) for line in output.read_text().splitlines()]

        assert len({row["seen_bytes"] for row in rows}) == len(rows)

    def test_hash_fields_render_when_analyzers_run(self):
        """files.log should include hash fields that correspond to analyzer names."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=445,
                    protocol="tcp",
                    zeek_uid="CConnUID12345678",
                ),
                file_transfer=FileTransferContext(
                    fuid="FFileUID12345678",
                    source="SMB",
                    analyzers=["MD5", "SHA1", "SHA256"],
                    seen_bytes=4096,
                    md5="0" * 32,
                    sha1="1" * 40,
                    sha256="2" * 64,
                ),
            )
            emitter.emit(event)
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())

            assert data["md5"] == "0" * 32
            assert data["sha1"] == "1" * 40
            assert data["sha256"] == "2" * 64

    def test_smb_filename_renders_when_present(self):
        """SMB files.log rows should include Zeek filename when the context has one."""
        fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "files.json"
            emitter = ZeekFilesEmitter(fmt, output)

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="10.0.0.10",
                    dst_port=445,
                    protocol="tcp",
                    zeek_uid="CConnUID12345678",
                ),
                file_transfer=FileTransferContext(
                    fuid="FFileUID12345678",
                    source="SMB",
                    filename=r"\\files01\Shared\Finance\budget-review.xlsx",
                    seen_bytes=4096,
                ),
            )
            emitter.emit(event)
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())

            assert data["filename"] == r"\\files01\Shared\Finance\budget-review.xlsx"


class TestSmbFileTransferConfig:
    """Verify SMB file-transfer realism config loading."""

    def test_overlay_updates_threshold_and_extends_mime_types(self, tmp_path, monkeypatch):
        from evidenceforge.generation.activity.smb_file_transfers import (
            load_smb_file_transfers,
            reset_smb_file_transfers_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "smb_file_transfers.yaml").write_text(
            yaml.safe_dump(
                {
                    "min_transfer_bytes": 8192,
                    "mime_types": [{"mime_type": "application/x-test", "weight": 1}],
                },
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_smb_file_transfers_cache()

        try:
            data = load_smb_file_transfers()
            assert data["min_transfer_bytes"] == 8192
            assert any(entry["mime_type"] == "application/x-test" for entry in data["mime_types"])
        finally:
            reset_smb_file_transfers_cache()

    def test_filename_picker_uses_overlay_templates(self):
        """Filename templates should be data-driven and support overlays."""
        from evidenceforge.generation.activity.smb_file_transfers import pick_smb_filename

        config = {
            "filename_templates": [
                {
                    "mime_types": ["application/pdf"],
                    "templates": [r"\\{server}\Evidence\{basename}.pdf"],
                    "weight": 1,
                }
            ]
        }

        filename = pick_smb_filename(
            random.Random(42),
            config,
            mime_type="application/pdf",
            server="files01.example.com",
            user="alice",
        )

        assert filename.startswith("\\\\files01\\Evidence\\")
        assert filename.endswith(".pdf")
