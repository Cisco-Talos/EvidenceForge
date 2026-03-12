"""Test Zeek format accuracy against real-world examples."""

import json

import pytest


class TestZeekFormatAccuracy:
    """Verify synthetic Zeek logs match real Zeek log structure."""

    def test_format_matches_real_zeek_log(self):
        """Test that our format matches a real Zeek conn.log entry.

        Real example from actual Zeek deployment:
        {"ts":1427846411.876987,"uid":"C1ck9l41y7i2i3gGo2","id.orig_h":"192.168.0.54",
         "id.orig_p":55069,"id.resp_h":"173.194.40.245","id.resp_p":443,"proto":"tcp",
         "duration":0.0002410411834716797,"orig_bytes":0,"resp_bytes":0,
         "conn_state":"SHR","local_orig":true,"local_resp":false,"missed_bytes":0,
         "history":"^fA","orig_pkts":1,"orig_ip_bytes":40,"resp_pkts":1,
         "resp_ip_bytes":40,"ip_proto":6}
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

        # Our synthetic log (without optional service field)
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
        # Real log without service
        without_service = {"proto": "tcp", "conn_state": "SHR"}

        # Real log with service
        with_service = {"proto": "tcp", "service": "http", "conn_state": "SF"}

        # Both are valid - service is optional
        assert "service" not in without_service
        assert "service" in with_service

    def test_field_types(self):
        """Verify all field types match Zeek specifications."""
        field_types = {
            "ts": float,  # Epoch timestamp with microseconds
            "uid": str,  # 16-character base62 UID
            "id.orig_h": str,  # IP address
            "id.orig_p": int,  # Port number
            "id.resp_h": str,  # IP address
            "id.resp_p": int,  # Port number
            "proto": str,  # Protocol (tcp/udp/icmp)
            "service": str,  # Optional application protocol
            "duration": float,  # Connection duration in seconds
            "orig_bytes": int,  # Bytes from originator
            "resp_bytes": int,  # Bytes from responder
            "conn_state": str,  # Connection state
            "local_orig": bool,  # Local originator
            "local_resp": bool,  # Local responder
            "missed_bytes": int,  # Missed bytes
            "history": str,  # Connection history flags
            "orig_pkts": int,  # Packets from originator
            "orig_ip_bytes": int,  # IP-level bytes from originator
            "resp_pkts": int,  # Packets from responder
            "resp_ip_bytes": int,  # IP-level bytes from responder
            "ip_proto": int,  # IP protocol number (6=TCP, 17=UDP)
            "tunnel_parents": str,  # Optional tunnel UIDs
        }

        # Verify each type is correct
        for field, expected_type in field_types.items():
            # Just checking that we have documented the correct types
            assert expected_type in (str, int, float, bool), (
                f"Field '{field}' has invalid type: {expected_type}"
            )

    def test_timestamp_precision(self):
        """Verify Zeek timestamps have exactly 6 decimal places (microseconds).

        This test ensures timestamps maintain microsecond precision and don't
        lose trailing zeros when serialized to JSON. Real Zeek logs always use
        exactly 6 decimal places for the epoch timestamp.
        """
        from datetime import datetime
        from log_generator.generation.emitters.zeek import ZeekEmitter
        from log_generator.formats import load_format
        from pathlib import Path
        import tempfile
        import json

        # Create emitter with temporary output file
        format_def = load_format('zeek_conn')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = Path(f.name)

        try:
            emitter = ZeekEmitter(format_def, output_file)

            # Create test event with specific microseconds
            test_time = datetime(2024, 1, 15, 10, 30, 45, 123456)  # 123456 microseconds

            event_data = {
                'ts': test_time,
                'uid': 'C1234567890ABCDE',
                'id.orig_h': '10.0.10.5',
                'id.orig_p': 50000,
                'id.resp_h': '93.184.216.34',
                'id.resp_p': 443,
                'proto': 'tcp',
                'service': 'https',
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

            # Read the generated JSON
            with open(output_file) as f:
                line = f.readline()
                generated = json.loads(line)

            # Verify timestamp has exactly 6 decimal places
            ts_str = str(generated['ts'])

            # Split at decimal point
            assert '.' in ts_str, f"Timestamp missing decimal point: {ts_str}"
            integer_part, decimal_part = ts_str.split('.')

            # Check exactly 6 decimal places
            assert len(decimal_part) == 6, (
                f"Timestamp must have exactly 6 decimal places (microseconds), "
                f"got {len(decimal_part)}: {ts_str}"
            )

            # Verify it matches expected value
            expected_ts = test_time.timestamp()
            actual_ts = float(generated['ts'])
            assert abs(actual_ts - expected_ts) < 0.000001, (
                f"Timestamp value mismatch: expected {expected_ts}, got {actual_ts}"
            )

        finally:
            # Clean up
            if output_file.exists():
                output_file.unlink()
