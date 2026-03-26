"""Tests for Zeek files.log emitter."""

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FileTransferContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter


class TestFilesFormatAccuracy:
    """Verify files.log output matches real Zeek sample data."""

    def test_format_matches_sample(self):
        """Field names and types match sample_data/Zeek-JSON/files.log line 1."""
        real = json.loads(
            '{"ts":1427847434.287139,"fuid":"FheZAo1hKNan3xnZCd",'
            '"uid":"Chs9FGiGqSvNnbrAk","id.orig_h":"192.168.0.51",'
            '"id.orig_p":37959,"id.resp_h":"74.125.71.103","id.resp_p":80,'
            '"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain",'
            '"duration":0.0,"local_orig":false,"is_orig":false,"seen_bytes":341,'
            '"missing_bytes":0,"overflow_bytes":0,"timedout":false}'
        )
        assert real["fuid"].startswith("F")
        assert real["uid"].startswith("C")
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
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "93.184.216.34",
                    "id.resp_p": 80,
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
            assert data["uid"] == "CTest123456789ab"
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
    """Verify files.log has both uid and fuid for cross-log correlation."""

    def test_dual_uids_present(self):
        """Output should have both uid (conn correlation) and fuid (file tracking)."""
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
            assert data["uid"] == "CConnUID12345678"
            assert data["fuid"] == "FFileUID12345678"
