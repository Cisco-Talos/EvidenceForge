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
from evidenceforge.events.contexts import FileTransferContext, NetworkContext, X509Context
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter


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
                        fingerprint="a" * 64,
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
        assert rows[0]["sha256"] != "a" * 64
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
