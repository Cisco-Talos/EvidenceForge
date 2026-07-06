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

"""Tests for Zeek evaluation parsers and file discovery."""

import tempfile
from pathlib import Path

import pytest

from evidenceforge.evaluation.parsers import (
    _PARSER_CLASSES,
    discover_log_files,
    get_parser,
)
from evidenceforge.evaluation.pillars.parseability import _normalize_for_validation
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event

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


class TestProxyParserRegistration:
    """Proxy access parser registration and discovery."""

    def test_proxy_access_parser_registered(self):
        assert "proxy_access" in _PARSER_CLASSES
        assert get_parser("proxy_access").format_name == "proxy_access"

    def test_proxy_access_discovered_in_host_directory(self, tmp_path):
        host_dir = tmp_path / "proxy01.example.org"
        host_dir.mkdir()
        (host_dir / "proxy_access.log").write_text(
            "10.0.0.1 - - [15/Jul/2024:10:00:00 +0000] "
            '"GET http://example.com/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        )

        discovered = discover_log_files(tmp_path)

        assert discovered["proxy_access"] == [host_dir / "proxy_access.log"]

    def test_web_access_parser_preserves_host_directory_as_metadata(self, tmp_path):
        host_dir = tmp_path / "web01.example.org"
        host_dir.mkdir()
        log_path = host_dir / "web_access.log"
        log_path.write_text(
            '192.0.2.45 - - [15/Jul/2024:12:00:00 +0000] "GET /admin HTTP/1.1" '
            '404 512 "-" "gobuster/3.6"\n'
        )

        parser = get_parser("web_access")
        records = list(parser.parse_file(log_path))

        assert records[0].source_host == "web01.example.org"
        assert "hostname" not in records[0].fields

    def test_web_access_parser_leaves_flat_output_without_source_host(self, tmp_path):
        log_path = tmp_path / "web_access.log"
        log_path.write_text(
            '192.0.2.45 - - [15/Jul/2024:12:00:00 +0000] "GET /admin HTTP/1.1" '
            '404 512 "-" "gobuster/3.6"\n'
        )
        (tmp_path / "GROUND_TRUTH.md").write_text("# Ground Truth\n")

        parser = get_parser("web_access")
        records = list(parser.parse_file(log_path))

        assert records[0].source_host is None

    def test_proxy_access_dash_fields_are_omitted(self):
        parser = get_parser("proxy_access")
        record = parser._parse_line(
            "10.0.0.1 - - [15/Jul/2024:10:00:00 +0000] "
            '"CONNECT example.com:443 HTTP/1.1" 200 - "-" "-"',
            1,
        )

        assert record.parse_errors == []
        assert "username" not in record.fields
        assert "user_agent" not in record.fields
        assert "referrer" not in record.fields
        assert "bytes_sent" not in record.fields
        assert record.fields["host"] == "example.com"

    def test_proxy_access_parser_reads_combined_columns(self):
        parser = get_parser("proxy_access")
        record = parser._parse_line(
            "10.0.0.1 - jsmith [15/Jul/2024:10:00:00 +0000] "
            '"GET http://example.com/download?q=1 HTTP/1.1" 200 1024 '
            '"https://intranet.example.com/" "Mozilla/5.0 (Windows NT 10.0)"',
            1,
        )

        assert record.parse_errors == []
        assert record.fields["username"] == "jsmith"
        assert record.fields["protocol"] == "HTTP/1.1"
        assert record.fields["url"] == "http://example.com/download?q=1"
        assert "path" not in record.fields
        assert "bytes_sent" not in record.fields
        assert record.fields["host"] == "example.com"
        assert record.fields["sc_bytes"] == 1024
        assert record.fields["user_agent"] == "Mozilla/5.0 (Windows NT 10.0)"
        assert record.fields["referrer"] == "https://intranet.example.com/"

    def test_proxy_access_parser_reads_optional_proxy_metadata(self):
        parser = get_parser("proxy_access")
        record = parser._parse_line(
            "10.0.0.1 - jsmith [15/Jul/2024:10:00:00 +0000] "
            '"GET https://example.com/download?q=1 HTTP/1.1" 200 1024 '
            '"-" "Mozilla/5.0 (Windows NT 10.0)" '
            '"cs_bytes=2048 sc_bytes=1024 proxy_action=ssl-inspect ssl_bump=bump"',
            1,
        )

        assert record.parse_errors == []
        assert record.fields["host"] == "example.com"
        assert record.fields["cs_bytes"] == 2048
        assert record.fields["sc_bytes"] == 1024
        assert record.fields["proxy_action"] == "ssl-inspect"
        assert record.fields["ssl_bump_action"] == "bump"

    def test_proxy_access_combined_columns_pass_format_validation(self):
        parser = get_parser("proxy_access")
        record = parser._parse_line(
            "10.0.0.1 - jsmith [15/Jul/2024:10:00:00 +0000] "
            '"GET https://example.com/download?q=1 HTTP/1.1" 200 1024 '
            '"https://intranet.example.com/" "Mozilla/5.0 (Windows NT 10.0)" '
            '"proxy_action=ssl-inspect ssl_bump=bump"',
            1,
        )
        normalized = _normalize_for_validation(
            "proxy_access",
            record.fields,
            record.timestamp,
        )

        result = validate_event(load_format("proxy_access"), normalized)

        assert record.parse_errors == []
        assert result.valid, result.errors

    def test_proxy_access_parser_rejects_legacy_w3c_rows(self):
        parser = get_parser("proxy_access")
        record = parser._parse_line(
            "2024-07-15 10:00:00 10.0.0.1 jsmith GET http://example.com/ HTTP/1.1 "
            "200 1024 350 42 example.com Mozilla/5.0+(Windows+NT+10.0) "
            "https://intranet.example.com/ text/html MISS forward",
            1,
        )

        assert record.fields == {}
        assert record.timestamp is None
        assert record.parse_errors == ["Line does not match proxy access combined log format"]


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
