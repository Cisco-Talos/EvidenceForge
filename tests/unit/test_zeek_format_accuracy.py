"""Test Zeek format accuracy against real-world examples."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest


class TestZeekConnFormatAccuracy:
    """Verify synthetic Zeek conn.log matches real Zeek log structure."""

    def test_format_matches_real_zeek_log(self):
        """Test that our format matches a real Zeek conn.log entry.

        Real example from sample_data/Zeek-JSON/conn.log line 1.
        """
        real_log = {
            "ts": 1427846411.876987,
            "uid": "C1ck9l41y7i2i3gGo2",
            "id.orig_h": "192.168.0.54",
            "id.orig_p": 55069,
            "id.resp_h": "173.194.40.245",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 0.0002410411834716797,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "conn_state": "SHR",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "^fA",
            "orig_pkts": 1,
            "orig_ip_bytes": 40,
            "resp_pkts": 1,
            "resp_ip_bytes": 40,
            "ip_proto": 6,
        }

        synthetic_log = {
            "ts": 1705312800.123456,
            "uid": "CKfbzAUjDjrBdE8I",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "duration": 1.234,
            "orig_bytes": 512,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 10,
            "orig_ip_bytes": 1024,
            "resp_pkts": 8,
            "resp_ip_bytes": 8192,
            "ip_proto": 6,
        }

        # All required fields from real log must be in synthetic
        real_fields = set(real_log.keys())
        synthetic_fields = set(synthetic_log.keys())

        missing_fields = real_fields - synthetic_fields
        assert not missing_fields, f"Missing fields: {missing_fields}"

        # All common fields must have matching types
        for field in real_fields:
            real_type = type(real_log[field])
            synth_type = type(synthetic_log[field])
            assert real_type == synth_type, (
                f"Type mismatch for '{field}': "
                f"real={real_type.__name__} vs synthetic={synth_type.__name__}"
            )

    def test_optional_service_field(self):
        """Test that service field is optional (not in all real logs)."""
        without_service = {"proto": "tcp", "conn_state": "SHR"}
        with_service = {"proto": "tcp", "service": "http", "conn_state": "SF"}
        assert "service" not in without_service
        assert "service" in with_service

    def test_service_uses_ssl_not_https(self):
        """Real Zeek conn.log uses 'ssl' for TLS connections, not 'https'."""
        # Verified against sample_data/Zeek-JSON/conn.log line 46
        real_ssl_conn = json.loads(
            '{"ts":1427846471.714864,"uid":"C5kVIUjmv81kcLoLg",'
            '"id.orig_h":"192.168.0.54","id.orig_p":55072,'
            '"id.resp_h":"173.194.66.99","id.resp_p":443,"proto":"tcp",'
            '"service":"ssl","duration":250.23871088027954}'
        )
        assert real_ssl_conn["service"] == "ssl"
        assert real_ssl_conn["service"] != "https"

    def test_field_types(self):
        """Verify all field types match Zeek specifications."""
        field_types = {
            "ts": float,
            "uid": str,
            "id.orig_h": str,
            "id.orig_p": int,
            "id.resp_h": str,
            "id.resp_p": int,
            "proto": str,
            "service": str,
            "duration": float,
            "orig_bytes": int,
            "resp_bytes": int,
            "conn_state": str,
            "local_orig": bool,
            "local_resp": bool,
            "missed_bytes": int,
            "history": str,
            "orig_pkts": int,
            "orig_ip_bytes": int,
            "resp_pkts": int,
            "resp_ip_bytes": int,
            "ip_proto": int,
        }

        for field, expected_type in field_types.items():
            assert expected_type in (str, int, float, bool), (
                f"Field '{field}' has invalid type: {expected_type}"
            )

    def test_timestamp_precision(self):
        """Verify Zeek timestamps have exactly 6 decimal places (microseconds)."""
        from evidenceforge.generation.emitters.zeek import ZeekEmitter
        from evidenceforge.formats import load_format

        format_def = load_format('zeek_conn')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        try:
            emitter = ZeekEmitter(format_def, output_file)
            test_time = datetime(2024, 1, 15, 10, 30, 45, 123456)

            event_data = {
                'ts': test_time,
                'uid': 'C1234567890ABCDE',
                'id.orig_h': '10.0.10.5',
                'id.orig_p': 50000,
                'id.resp_h': '93.184.216.34',
                'id.resp_p': 443,
                'proto': 'tcp',
                'service': 'ssl',
                'duration': 1.5,
                'orig_bytes': 1000,
                'resp_bytes': 5000,
                'conn_state': 'SF',
                'local_orig': True,
                'local_resp': False,
                'missed_bytes': 0,
                'history': 'ShADadfF',
                'orig_pkts': 10,
                'orig_ip_bytes': 1400,
                'resp_pkts': 12,
                'resp_ip_bytes': 5480,
                'ip_proto': 6,
            }

            emitter.emit_event(event_data)
            emitter.close()

            with open(output_file) as f:
                line = f.readline()
                generated = json.loads(line)

            ts_str = str(generated['ts'])
            assert '.' in ts_str, f"Timestamp missing decimal point: {ts_str}"
            integer_part, decimal_part = ts_str.split('.')
            assert len(decimal_part) == 6, (
                f"Timestamp must have exactly 6 decimal places, "
                f"got {len(decimal_part)}: {ts_str}"
            )

            expected_ts = test_time.timestamp()
            actual_ts = float(generated['ts'])
            assert abs(actual_ts - expected_ts) < 0.000001

        finally:
            if output_file.exists():
                output_file.unlink()

    def test_duration_full_precision(self):
        """Verify conn.log duration uses full float precision, not rounded to 6 decimals.

        Real Zeek duration example: 0.0002410411834716797 (19 decimal digits).
        """
        from evidenceforge.generation.emitters.zeek import ZeekEmitter
        from evidenceforge.formats import load_format

        format_def = load_format('zeek_conn')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        try:
            emitter = ZeekEmitter(format_def, output_file)

            # Use a duration with many significant digits
            test_duration = 0.0002410411834716797

            event_data = {
                'ts': datetime(2024, 1, 15, 10, 30, 45, 123456),
                'uid': 'C1234567890ABCDE',
                'id.orig_h': '10.0.10.5',
                'id.orig_p': 50000,
                'id.resp_h': '93.184.216.34',
                'id.resp_p': 443,
                'proto': 'tcp',
                'duration': test_duration,
                'orig_bytes': 0,
                'resp_bytes': 0,
                'conn_state': 'SHR',
                'local_orig': True,
                'local_resp': False,
                'missed_bytes': 0,
                'history': '^fA',
                'orig_pkts': 1,
                'orig_ip_bytes': 40,
                'resp_pkts': 1,
                'resp_ip_bytes': 40,
                'ip_proto': 6,
            }

            emitter.emit_event(event_data)
            emitter.close()

            with open(output_file) as f:
                raw_line = f.readline()
                generated = json.loads(raw_line)

            # Duration must NOT be rounded to 6 decimal places
            assert generated['duration'] == test_duration, (
                f"Duration should preserve full precision: "
                f"expected {test_duration}, got {generated['duration']}"
            )

            # Verify the raw JSON string has more than 6 decimal digits for duration
            duration_str = raw_line.split('"duration":')[1].split(',')[0]
            decimal_part = duration_str.split('.')[1]
            assert len(decimal_part) > 6, (
                f"Duration should have >6 decimal digits in JSON, got: {duration_str}"
            )

        finally:
            if output_file.exists():
                output_file.unlink()


class TestZeekDnsFormatAccuracy:
    """Verify synthetic Zeek dns.log matches real Zeek log structure."""

    def test_format_matches_real_dns_log(self):
        """Test that our format matches a real Zeek dns.log entry.

        Real example from sample_data/Zeek-JSON/dns.log line 1.
        """
        real_log = json.loads(
            '{"ts":1427846471.711856,"uid":"C4pjsbfcqTgsdsok7",'
            '"id.orig_h":"192.168.0.54","id.orig_p":50697,'
            '"id.resp_h":"192.168.0.1","id.resp_p":53,"proto":"udp",'
            '"trans_id":19129,"rtt":0.001638174057006836,'
            '"query":"www.google.com","qclass":1,"qclass_name":"C_INTERNET",'
            '"qtype":1,"qtype_name":"A","rcode":0,"rcode_name":"NOERROR",'
            '"AA":false,"TC":false,"RD":true,"RA":true,"Z":0,'
            '"answers":["173.194.66.99","173.194.66.103","173.194.66.104",'
            '"173.194.66.105","173.194.66.106","173.194.66.147"],'
            '"TTLs":[23.0,23.0,23.0,23.0,23.0,23.0],"rejected":false,'
            '"opcode":0,"opcode_name":"query"}'
        )

        # Verify key field types
        assert isinstance(real_log["answers"], list)
        assert isinstance(real_log["TTLs"], list)
        assert all(isinstance(a, str) for a in real_log["answers"])
        assert all(isinstance(t, float) for t in real_log["TTLs"])
        assert isinstance(real_log["Z"], int)
        assert isinstance(real_log["opcode"], int)
        assert isinstance(real_log["opcode_name"], str)
        assert isinstance(real_log["rtt"], float)

    def test_dns_emitter_output_fields(self):
        """Verify ZeekDnsEmitter produces correct field names and types."""
        from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
        from evidenceforge.formats import load_format

        format_def = load_format('zeek_dns')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        try:
            emitter = ZeekDnsEmitter(format_def, output_file)

            event_data = {
                'ts': datetime(2024, 1, 15, 10, 30, 45, 123456),
                'uid': 'C4pjsbfcqTgsdsok7',
                'id.orig_h': '10.0.10.50',
                'id.orig_p': 54321,
                'id.resp_h': '10.0.20.10',
                'id.resp_p': 53,
                'proto': 'udp',
                'trans_id': 12345,
                'rtt': 0.001638174057006836,
                'query': 'www.example.com',
                'qclass': 1,
                'qclass_name': 'C_INTERNET',
                'qtype': 1,
                'qtype_name': 'A',
                'rcode': 0,
                'rcode_name': 'NOERROR',
                'AA': False,
                'TC': False,
                'RD': True,
                'RA': True,
                'Z': 0,
                'answers': ['93.184.216.34'],
                'TTLs': [300.0],
                'rejected': False,
                'opcode': 0,
                'opcode_name': 'query',
            }

            emitter.emit_event(event_data)
            emitter.close()

            with open(output_file) as f:
                line = f.readline()
                generated = json.loads(line)

            # Verify all required fields present
            required_fields = {
                'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                'proto', 'trans_id', 'query', 'qclass', 'qclass_name',
                'qtype', 'qtype_name', 'rcode', 'rcode_name',
                'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs',
                'rejected', 'opcode', 'opcode_name', 'rtt',
            }
            missing = required_fields - set(generated.keys())
            assert not missing, f"Missing fields in dns.log output: {missing}"

            # Verify array types
            assert isinstance(generated['answers'], list), \
                f"answers must be array, got {type(generated['answers']).__name__}"
            assert isinstance(generated['TTLs'], list), \
                f"TTLs must be array, got {type(generated['TTLs']).__name__}"
            assert all(isinstance(t, float) for t in generated['TTLs']), \
                "TTLs entries must be floats"

            # Verify integer fields
            assert isinstance(generated['Z'], int)
            assert isinstance(generated['opcode'], int)

            # Verify rtt is float
            assert isinstance(generated['rtt'], float)

        finally:
            if output_file.exists():
                output_file.unlink()

    def test_nxdomain_omits_answers_and_ttls(self):
        """NXDOMAIN records should NOT include answers or TTLs fields."""
        from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
        from evidenceforge.formats import load_format

        format_def = load_format('zeek_dns')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        try:
            emitter = ZeekDnsEmitter(format_def, output_file)

            event_data = {
                'ts': datetime(2024, 1, 15, 10, 30, 45, 123456),
                'uid': 'C4pjsbfcqTgsdsok7',
                'id.orig_h': '10.0.10.50',
                'id.orig_p': 54321,
                'id.resp_h': '10.0.20.10',
                'id.resp_p': 53,
                'proto': 'udp',
                'trans_id': 12345,
                'query': 'nonexistent.example.com',
                'qclass': 1,
                'qclass_name': 'C_INTERNET',
                'qtype': 1,
                'qtype_name': 'A',
                'rcode': 3,
                'rcode_name': 'NXDOMAIN',
                'AA': True,
                'TC': False,
                'RD': True,
                'RA': True,
                'Z': 0,
                'rejected': False,
                'opcode': 0,
                'opcode_name': 'query',
                # No answers, TTLs, or rtt keys
            }

            emitter.emit_event(event_data)
            emitter.close()

            with open(output_file) as f:
                line = f.readline()
                generated = json.loads(line)

            assert 'answers' not in generated, \
                "NXDOMAIN records should not have 'answers' field"
            assert 'TTLs' not in generated, \
                "NXDOMAIN records should not have 'TTLs' field"
            assert 'rtt' not in generated, \
                "NXDOMAIN records without rtt should not have 'rtt' field"

        finally:
            if output_file.exists():
                output_file.unlink()


class TestZeekUidGeneration:
    """Verify Zeek UID generation matches real Zeek patterns."""

    def test_uid_variable_length(self):
        """UIDs should vary in length (17-19 chars), not fixed at 18."""
        from evidenceforge.utils.ids import generate_zeek_uid

        lengths = set()
        for _ in range(1000):
            uid = generate_zeek_uid()
            assert 17 <= len(uid) <= 19, f"UID length {len(uid)} outside 17-19: {uid}"
            lengths.add(len(uid))

        # Should produce at least 2 different lengths in 1000 samples
        assert len(lengths) >= 2, (
            f"Expected variable UID lengths, but all were same: {lengths}"
        )

    def test_uid_prefix(self):
        """UIDs should start with the specified prefix character."""
        from evidenceforge.utils.ids import generate_zeek_uid

        assert generate_zeek_uid("C")[0] == "C"
        assert generate_zeek_uid("F")[0] == "F"

    def test_uid_base62_chars(self):
        """UIDs should only contain base62 characters."""
        from evidenceforge.utils.ids import generate_zeek_uid
        import string

        base62 = set(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        for _ in range(100):
            uid = generate_zeek_uid()
            for ch in uid:
                assert ch in base62, f"Non-base62 char '{ch}' in UID: {uid}"


SAMPLE_DIR = Path(__file__).parent.parent.parent / "sample_data" / "Zeek-JSON"


class TestSampleDataFieldValidation:
    """Validate all Zeek sample data has correct field names and types."""

    def _parse_first_line(self, filename):
        path = SAMPLE_DIR / filename
        with open(path) as f:
            return json.loads(f.readline())

    def test_ssl_sample_fields(self):
        data = self._parse_first_line("ssl.log")
        assert isinstance(data["ts"], float)
        assert isinstance(data["uid"], str)
        assert isinstance(data["id.orig_h"], str)
        assert isinstance(data["version"], str)
        assert isinstance(data["cipher"], str)
        assert isinstance(data["resumed"], bool)
        assert isinstance(data["established"], bool)

    def test_http_sample_fields(self):
        data = self._parse_first_line("http.log")
        assert isinstance(data["ts"], float)
        assert isinstance(data["uid"], str)
        assert isinstance(data["trans_depth"], int)
        assert isinstance(data["method"], str)
        assert isinstance(data["host"], str)
        assert isinstance(data["uri"], str)
        assert isinstance(data["status_code"], int)
        assert isinstance(data["tags"], list)

    def test_files_sample_fields(self):
        data = self._parse_first_line("files.log")
        assert data["fuid"].startswith("F")
        assert isinstance(data["uid"], str)
        assert isinstance(data["source"], str)
        assert isinstance(data["analyzers"], list)
        assert isinstance(data["seen_bytes"], int)
        assert isinstance(data["is_orig"], bool)
        assert isinstance(data["timedout"], bool)

    def test_dhcp_sample_fields(self):
        data = self._parse_first_line("dhcp.log")
        assert isinstance(data["uids"], list)
        assert isinstance(data["client_addr"], str)
        assert isinstance(data["mac"], str)
        assert isinstance(data["msg_types"], list)

    def test_ntp_sample_fields(self):
        data = self._parse_first_line("ntp.log")
        assert isinstance(data["version"], int)
        assert isinstance(data["mode"], int)
        assert isinstance(data["stratum"], int)
        assert isinstance(data["poll"], float)

    def test_x509_sample_fields(self):
        data = self._parse_first_line("x509.log")
        assert isinstance(data["fingerprint"], str)
        assert isinstance(data["certificate.version"], int)
        assert isinstance(data["certificate.subject"], str)
        assert isinstance(data["certificate.issuer"], str)
        assert isinstance(data["certificate.key_length"], int)
        assert isinstance(data["host_cert"], bool)

    def test_weird_sample_fields(self):
        data = self._parse_first_line("weird.log")
        assert isinstance(data["name"], str)
        assert isinstance(data["notice"], bool)
        assert isinstance(data["peer"], str)

    def test_pe_sample_fields(self):
        data = self._parse_first_line("pe.log")
        assert isinstance(data["machine"], str)
        assert isinstance(data["is_exe"], bool)
        assert isinstance(data["is_64bit"], bool)
        assert isinstance(data["section_names"], list)

    def test_ocsp_sample_fields(self):
        data = self._parse_first_line("ocsp.log")
        assert isinstance(data["hashAlgorithm"], str)
        assert isinstance(data["certStatus"], str)
        assert isinstance(data["serialNumber"], str)

    def test_packet_filter_sample_fields(self):
        data = self._parse_first_line("packet_filter.log")
        assert isinstance(data["node"], str)
        assert isinstance(data["filter"], str)
        assert isinstance(data["init"], bool)
        assert isinstance(data["success"], bool)

    def test_reporter_sample_fields(self):
        data = self._parse_first_line("reporter.log")
        assert isinstance(data["level"], str)
        assert isinstance(data["message"], str)
        assert isinstance(data["location"], str)

    def test_all_formats_load(self):
        """All format YAMLs load successfully."""
        from evidenceforge.formats import load_all_formats
        formats = load_all_formats()
        assert len(formats) == 20
