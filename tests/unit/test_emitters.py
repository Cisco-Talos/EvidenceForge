"""Unit tests for log emitters."""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from log_generator.formats import load_format
from log_generator.generation.emitters import WindowsEventEmitter, ZeekEmitter
from log_generator.utils import generate_zeek_uid


class TestWindowsEventEmitter:
    """Tests for Windows Event Log emitter."""

    @pytest.fixture
    def format_def(self):
        """Load Windows Event format definition."""
        return load_format("windows_event_security")

    @pytest.fixture
    def temp_output(self, tmp_path):
        """Create temporary output file path."""
        return tmp_path / "windows_events.xml"

    def test_emit_logon_event(self, format_def, temp_output):
        """Test emitting a single logon event (4624)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=timezone.utc),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12345,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Logon variant fields
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "192.168.1.100",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4624</EventID>" in content
        assert "<TimeCreated" in content
        assert "2024-01-15T10:30:45.123Z" in content
        assert "<Computer>WIN-TEST-01.corp.local</Computer>" in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content
        assert '<Data Name="TargetDomainName">CORP</Data>' in content
        assert '<Data Name="LogonType">2</Data>' in content

        print(f"\n{'='*80}")
        print("WINDOWS EVENT LOG SAMPLE (4624 - Logon):")
        print(f"{'='*80}")
        print(content)
        print(f"{'='*80}\n")

    def test_emit_logoff_event(self, format_def, temp_output):
        """Test emitting a logoff event (4634)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4634,
            "TimeCreated": datetime(2024, 1, 15, 18, 15, 30, 0, tzinfo=timezone.utc),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12346,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Logoff variant fields
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
            "LogonType": 2,
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4634</EventID>" in content
        assert "2024-01-15T18:15:30.000Z" in content
        assert '<Data Name="TargetUserName">jsmith</Data>' in content

        print(f"\n{'='*80}")
        print("WINDOWS EVENT LOG SAMPLE (4634 - Logoff):")
        print(f"{'='*80}")
        print(content)
        print(f"{'='*80}\n")

    def test_emit_process_creation_event(self, format_def, temp_output):
        """Test emitting a process creation event (4688)."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=1)

        event_data = {
            "EventID": 4688,
            "TimeCreated": datetime(2024, 1, 15, 10, 31, 0, 0, tzinfo=timezone.utc),
            "Computer": "WIN-TEST-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 12347,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            # Process variant fields
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7abc",
            "NewProcessId": "0x1234",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "%%1936",
            "ProcessId": "0x5678",
            "CommandLine": "cmd.exe /c dir",
            "TargetUserName": "jsmith",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7abc",
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text()
        assert "<EventID>4688</EventID>" in content
        assert '<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>' in content
        assert '<Data Name="CommandLine">cmd.exe /c dir</Data>' in content

        print(f"\n{'='*80}")
        print("WINDOWS EVENT LOG SAMPLE (4688 - Process Creation):")
        print(f"{'='*80}")
        print(content)
        print(f"{'='*80}\n")

    def test_buffering(self, format_def, temp_output):
        """Test that events are buffered before flushing."""
        emitter = WindowsEventEmitter(format_def, temp_output, buffer_size=3)

        # Emit 2 events (below buffer size)
        for i in range(2):
            event_data = {
                "EventID": 4624,
                "TimeCreated": datetime(2024, 1, 15, 10, 30, i, 0, tzinfo=timezone.utc),
                "Computer": "WIN-TEST-01",
                "Channel": "Security",
                "Level": 0,
                "EventRecordID": 10000 + i,
                "ExecutionProcessID": 4,
                "ExecutionThreadID": 100,
                "TargetUserName": f"user{i}",
                "TargetDomainName": "CORP",
                "TargetLogonId": f"0x{i:06x}",
                "LogonType": 2,
                "WorkstationName": "WIN-TEST-01",
                "IpAddress": "192.168.1.100",
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            }
            emitter.emit_event(event_data)

        # File shouldn't exist yet (still in buffer)
        assert not temp_output.exists()

        # Emit 3rd event (reaches buffer size)
        event_data = {
            "EventID": 4624,
            "TimeCreated": datetime(2024, 1, 15, 10, 30, 2, 0, tzinfo=timezone.utc),
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 10002,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "TargetUserName": "user2",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x000002",
            "LogonType": 2,
            "WorkstationName": "WIN-TEST-01",
            "IpAddress": "192.168.1.100",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        }
        emitter.emit_event(event_data)

        # File should now exist (buffer flushed)
        assert temp_output.exists()

        # Verify all 3 events are in the file
        content = temp_output.read_text()
        assert content.count("<EventID>4624</EventID>") == 3
        assert "user0" in content
        assert "user1" in content
        assert "user2" in content


class TestZeekEmitter:
    """Tests for Zeek conn.log emitter."""

    @pytest.fixture
    def format_def(self):
        """Load Zeek format definition."""
        return load_format("zeek_conn")

    @pytest.fixture
    def temp_output(self, tmp_path):
        """Create temporary output file path."""
        return tmp_path / "conn.json"

    def test_emit_tcp_connection(self, format_def, temp_output):
        """Test emitting a TCP connection."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 0, 123456, tzinfo=timezone.utc),
            "uid": uid,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
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

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify content
        content = temp_output.read_text().strip()

        # Parse as JSON
        conn = json.loads(content)

        assert conn["uid"] == uid
        assert conn["id.orig_h"] == "192.168.1.100"
        assert conn["id.orig_p"] == 49152
        assert conn["id.resp_h"] == "93.184.216.34"
        assert conn["id.resp_p"] == 80
        assert conn["proto"] == "tcp"
        assert conn["service"] == "http"
        assert conn["conn_state"] == "SF"
        assert conn["local_orig"] is True
        assert conn["local_resp"] is False

        print(f"\n{'='*80}")
        print("ZEEK CONN.LOG SAMPLE (TCP Connection):")
        print(f"{'='*80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'='*80}\n")

    def test_emit_udp_connection(self, format_def, temp_output):
        """Test emitting a UDP connection (DNS query)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 5, 654321, tzinfo=timezone.utc),
            "uid": uid,
            "id.orig_h": "10.0.0.50",
            "id.orig_p": 53123,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.012,
            "orig_bytes": 64,
            "resp_bytes": 128,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "orig_pkts": 1,
            "orig_ip_bytes": 92,
            "resp_pkts": 1,
            "resp_ip_bytes": 156,
            "ip_proto": 17,
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and parse
        content = temp_output.read_text().strip()
        conn = json.loads(content)

        assert conn["proto"] == "udp"
        assert conn["service"] == "dns"
        assert conn["id.resp_p"] == 53
        assert conn["orig_bytes"] == 64
        assert conn["resp_bytes"] == 128

        print(f"\n{'='*80}")
        print("ZEEK CONN.LOG SAMPLE (UDP/DNS Query):")
        print(f"{'='*80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'='*80}\n")

    def test_emit_incomplete_connection(self, format_def, temp_output):
        """Test emitting an incomplete connection (no established state)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=1)

        uid = generate_zeek_uid()
        event_data = {
            "ts": datetime(2024, 1, 15, 10, 0, 10, 543210, tzinfo=timezone.utc),
            "uid": uid,
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 12345,
            "id.resp_h": "203.0.113.50",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "S0",  # SYN sent, no response
        }

        emitter.emit_event(event_data)
        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and parse
        content = temp_output.read_text().strip()
        conn = json.loads(content)

        assert conn["conn_state"] == "S0"
        assert "service" not in conn  # No service for incomplete connection
        assert "duration" not in conn  # No duration

        print(f"\n{'='*80}")
        print("ZEEK CONN.LOG SAMPLE (Incomplete Connection - S0):")
        print(f"{'='*80}")
        print("Raw file content (JSONL/NDJSON format - single line):")
        print(content)
        print(f"{'='*80}\n")

    def test_multiple_connections(self, format_def, temp_output):
        """Test emitting multiple connections (one per line JSON)."""
        emitter = ZeekEmitter(format_def, temp_output, buffer_size=10)

        # Emit 3 connections
        uids = [generate_zeek_uid() for _ in range(3)]
        # Use realistic microsecond values (not sequential patterns)
        microseconds = [876543, 291047, 638219]
        for i in range(3):
            event_data = {
                "ts": datetime(2024, 1, 15, 10, 0, i, microseconds[i], tzinfo=timezone.utc),
                "uid": uids[i],
                "id.orig_h": f"192.168.1.{100 + i}",
                "id.orig_p": 49152 + i,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 80,
                "proto": "tcp",
                "service": "http",
                "duration": float(i + 1),
                "orig_bytes": (i + 1) * 100,
                "resp_bytes": (i + 1) * 1000,
                "conn_state": "SF",
                "ip_proto": 6,
            }
            emitter.emit_event(event_data)

        emitter.close()

        # Verify file was created
        assert temp_output.exists()

        # Read and verify - should be 3 lines of JSON
        lines = temp_output.read_text().strip().split("\n")
        assert len(lines) == 3

        # Parse each line and verify data
        for i, line in enumerate(lines):
            conn = json.loads(line)
            assert conn["uid"] == uids[i]
            assert conn["id.orig_h"] == f"192.168.1.{100 + i}"
            assert conn["orig_bytes"] == (i + 1) * 100

        print(f"\n{'='*80}")
        print("ZEEK CONN.LOG SAMPLE (Multiple Connections):")
        print(f"{'='*80}")
        print("Raw file content (JSONL/NDJSON format - one JSON object per line):")
        for line in lines:
            print(line)
        print(f"{'='*80}\n")
