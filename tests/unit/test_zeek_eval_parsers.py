"""Tests for Zeek evaluation parsers and file discovery."""

import tempfile
from pathlib import Path

import pytest

from evidenceforge.evaluation.parsers import (
    _PARSER_CLASSES,
    discover_log_files,
    get_parser,
)

SAMPLE_DATA_DIR = Path(__file__).parent.parent.parent / "sample_data" / "Zeek-JSON"


class TestParserRegistration:
    """All 13 Zeek parsers should be registered."""

    ZEEK_FORMATS = {
        "zeek_conn",
        "zeek_dns",
        "zeek_http",
        "zeek_ssl",
        "zeek_files",
        "zeek_dhcp",
        "zeek_ntp",
        "zeek_weird",
        "zeek_x509",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_packet_filter",
        "zeek_reporter",
    }

    def test_all_zeek_parsers_registered(self):
        for fmt in self.ZEEK_FORMATS:
            assert fmt in _PARSER_CLASSES, f"Parser not registered: {fmt}"

    def test_parser_format_names_correct(self):
        for fmt in self.ZEEK_FORMATS:
            parser = get_parser(fmt)
            assert parser.format_name == fmt


class TestCanParseFlatPaths:
    """Parsers recognize flat-output filenames."""

    @pytest.mark.parametrize(
        "format_name,filename",
        [
            ("zeek_conn", "zeek_conn.json"),
            ("zeek_dns", "zeek_dns.json"),
            ("zeek_http", "zeek_http.json"),
            ("zeek_ssl", "zeek_ssl.json"),
            ("zeek_files", "zeek_files.json"),
            ("zeek_dhcp", "zeek_dhcp.json"),
            ("zeek_ntp", "zeek_ntp.json"),
            ("zeek_weird", "zeek_weird.json"),
            ("zeek_x509", "zeek_x509.json"),
            ("zeek_ocsp", "zeek_ocsp.json"),
            ("zeek_pe", "zeek_pe.json"),
            ("zeek_packet_filter", "zeek_packet_filter.json"),
            ("zeek_reporter", "zeek_reporter.json"),
        ],
    )
    def test_can_parse_flat(self, format_name, filename):
        parser = get_parser(format_name)
        assert parser.can_parse(Path(filename)) is True

    def test_rejects_wrong_filename(self):
        parser = get_parser("zeek_conn")
        assert parser.can_parse(Path("something_else.json")) is False


class TestCanParsePerSensorPaths:
    """Parsers recognize per-sensor subdirectory filenames."""

    @pytest.mark.parametrize(
        "format_name,filename",
        [
            ("zeek_conn", "conn.json"),
            ("zeek_dns", "dns.json"),
            ("zeek_http", "http.json"),
            ("zeek_ssl", "ssl.json"),
            ("zeek_files", "files.json"),
            ("zeek_dhcp", "dhcp.json"),
            ("zeek_ntp", "ntp.json"),
            ("zeek_weird", "weird.json"),
            ("zeek_x509", "x509.json"),
            ("zeek_ocsp", "ocsp.json"),
            ("zeek_pe", "pe.json"),
            ("zeek_packet_filter", "packet_filter.json"),
            ("zeek_reporter", "reporter.json"),
        ],
    )
    def test_can_parse_sensor_path(self, format_name, filename):
        parser = get_parser(format_name)
        # Simulate per-sensor path: zeek-fw01/conn.json
        assert parser.can_parse(Path(f"zeek-fw01/{filename}")) is True


@pytest.mark.skipif(not SAMPLE_DATA_DIR.exists(), reason="sample_data/ not available (gitignored)")
class TestParseSampleData:
    """Parse real Zeek sample data and verify correctness."""

    def test_parse_ssl_sample(self):
        parser = get_parser("zeek_ssl")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "ssl.log"))
        assert len(records) > 0
        r = records[0]
        assert r.source_format == "zeek_ssl"
        assert r.timestamp is not None
        assert "version" in r.fields
        assert "cipher" in r.fields
        assert r.parse_errors == []

    def test_parse_http_sample(self):
        parser = get_parser("zeek_http")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "http.log"))
        assert len(records) > 0
        r = records[0]
        assert "method" in r.fields
        assert "host" in r.fields
        assert "status_code" in r.fields
        assert r.parse_errors == []

    def test_parse_files_sample(self):
        parser = get_parser("zeek_files")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "files.log"))
        assert len(records) > 0
        r = records[0]
        assert "fuid" in r.fields
        assert r.fields["fuid"].startswith("F")
        assert r.parse_errors == []

    def test_parse_x509_sample(self):
        parser = get_parser("zeek_x509")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "x509.log"))
        assert len(records) > 0
        r = records[0]
        assert "fingerprint" in r.fields
        assert "certificate.subject" in r.fields
        assert r.parse_errors == []

    def test_parse_dhcp_sample(self):
        parser = get_parser("zeek_dhcp")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "dhcp.log"))
        assert len(records) > 0
        r = records[0]
        assert isinstance(r.fields["uids"], list)
        assert isinstance(r.fields["msg_types"], list)

    def test_parse_ntp_sample(self):
        parser = get_parser("zeek_ntp")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "ntp.log"))
        assert len(records) > 0
        assert "version" in records[0].fields

    def test_parse_weird_sample(self):
        parser = get_parser("zeek_weird")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "weird.log"))
        assert len(records) > 0
        assert "name" in records[0].fields

    def test_parse_packet_filter_sample(self):
        parser = get_parser("zeek_packet_filter")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "packet_filter.log"))
        assert len(records) > 0
        assert "node" in records[0].fields

    def test_parse_reporter_sample(self):
        parser = get_parser("zeek_reporter")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "reporter.log"))
        assert len(records) > 0
        assert "level" in records[0].fields

    def test_timestamps_are_utc(self):
        """All parsed timestamps should be timezone-aware UTC."""
        parser = get_parser("zeek_conn")
        records = list(parser.parse_file(SAMPLE_DATA_DIR / "conn.log"))
        for r in records[:5]:
            assert r.timestamp is not None
            assert r.timestamp.tzinfo is not None


class TestDiscoverLogFiles:
    """discover_log_files() finds files in flat and per-sensor layouts."""

    def test_finds_flat_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "zeek_conn.json").write_text('{"ts":1.0}\n')
            (base / "zeek_ssl.json").write_text('{"ts":1.0}\n')

            result = discover_log_files(base)
            assert "zeek_conn" in result
            assert "zeek_ssl" in result

    def test_finds_per_sensor_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "fw01").mkdir()
            (base / "fw01" / "conn.json").write_text('{"ts":1.0}\n')
            (base / "fw01" / "ssl.json").write_text('{"ts":1.0}\n')

            result = discover_log_files(base)
            assert "zeek_conn" in result
            assert "zeek_ssl" in result
            assert str(result["zeek_conn"][0]).endswith("conn.json")

    def test_finds_files_in_multiple_sensor_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            for sensor in ["fw01", "fw02"]:
                (base / sensor).mkdir()
                (base / sensor / "conn.json").write_text('{"ts":1.0}\n')

            result = discover_log_files(base)
            assert "zeek_conn" in result
            assert len(result["zeek_conn"]) == 2
