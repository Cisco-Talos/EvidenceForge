"""Integration tests for format definitions.

Tests that format definitions load correctly and validate sample data.
"""

from datetime import datetime

import pytest

from log_generator.formats import load_all_formats, load_format, validate_event


class TestWindowsEventFormat:
    """Tests for Windows Event Log format definition."""

    def setup_method(self):
        """Load Windows Event format before each test."""
        self.format = load_format("windows_event")

    def test_format_loads(self):
        """Test that windows_event.yaml loads successfully."""
        assert self.format is not None
        assert self.format.name == "windows_event"
        assert self.format.version == "1.0"
        assert self.format.category == "host"

    def test_has_three_variants(self):
        """Test that format has 3 EventID variants."""
        assert self.format.variants is not None
        assert len(self.format.variants) == 3
        variant_names = [v.name for v in self.format.variants]
        assert "logon" in variant_names
        assert "logoff" in variant_names
        assert "process_creation" in variant_names

    def test_base_fields(self):
        """Test that base fields are defined."""
        field_names = [f.name for f in self.format.fields]
        assert "EventID" in field_names
        assert "TimeCreated" in field_names
        assert "Computer" in field_names
        assert "Channel" in field_names
        assert "Level" in field_names

    def test_output_is_xml(self):
        """Test that output format is XML."""
        assert self.format.output.format == "xml"
        assert self.format.output.file_extension == ".xml"
        assert self.format.output.encoding == "utf-8"
        assert "<Event xmlns=" in self.format.output.template

    def test_validate_logon_event_4624(self):
        """Test validation of sample EventID 4624 logon event."""
        event_data = {
            "EventID": 4624,
            "TimeCreated": "2024-01-15T10:00:00Z",
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 1,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-5-21-1234-5678-9012-1001",
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e8",
            "LogonType": 2,
            "WorkstationName": "WS-01",
            "ProcessId": "0x4",
            "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
            "IpAddress": "-",
            "IpPort": 0,
        }

        result = validate_event(self.format, event_data, variant_name="logon")
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_validate_network_logon_4624(self):
        """Test validation of network logon event (LogonType 3)."""
        event_data = {
            "EventID": 4624,
            "TimeCreated": "2024-01-15T10:00:00Z",
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 2,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 101,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-5-21-1234-5678-9012-1002",
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e9",
            "LogonType": 3,
            "WorkstationName": "WS-02",
            "ProcessId": "0x4",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "IpAddress": "192.168.1.100",
            "IpPort": 49152,
        }

        result = validate_event(self.format, event_data, variant_name="logon")
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_validate_logoff_event_4634(self):
        """Test validation of sample EventID 4634 logoff event."""
        event_data = {
            "EventID": 4634,
            "TimeCreated": "2024-01-15T10:30:00Z",
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 10,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 200,
            "TargetUserSid": "S-1-5-21-1234-5678-9012-1001",
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e8",
            "LogonType": 2,
        }

        result = validate_event(self.format, event_data, variant_name="logoff")
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_validate_process_creation_event_4688(self):
        """Test validation of sample EventID 4688 process creation event."""
        event_data = {
            "EventID": 4688,
            "TimeCreated": "2024-01-15T10:15:00Z",
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 5,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 150,
            "SubjectUserSid": "S-1-5-21-1234-5678-9012-1001",
            "SubjectUserName": "jdoe",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e8",
            "NewProcessId": "0x1234",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "%%1936",
            "ProcessId": "0xabc",
            "CommandLine": "cmd.exe /c dir",
        }

        result = validate_event(self.format, event_data, variant_name="process_creation")
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_invalid_event_id(self):
        """Test that invalid EventID is rejected."""
        event_data = {
            "EventID": 9999,
            "TimeCreated": "2024-01-15T10:00:00Z",
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 1,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
        }

        result = validate_event(self.format, event_data)
        assert result.valid is False
        assert any("EventID" in error and "must be one of" in error for error in result.errors)

    def test_missing_required_field(self):
        """Test that missing required field is detected."""
        event_data = {
            "EventID": 4624,
            # Missing TimeCreated
            "Computer": "WIN-TEST-01",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 1,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 100,
        }

        result = validate_event(self.format, event_data, variant_name="logon")
        assert result.valid is False
        assert any("TimeCreated" in error for error in result.errors)


class TestZeekFormat:
    """Tests for Zeek conn.log format definition."""

    def setup_method(self):
        """Load Zeek format before each test."""
        self.format = load_format("zeek")

    def test_format_loads(self):
        """Test that zeek.yaml loads successfully."""
        assert self.format is not None
        assert self.format.name == "zeek"
        assert self.format.version == "1.0"
        assert self.format.category == "network"

    def test_no_variants(self):
        """Test that Zeek format has no variants."""
        assert self.format.variants is None or len(self.format.variants) == 0

    def test_has_connection_fields(self):
        """Test that connection fields are defined."""
        field_names = [f.name for f in self.format.fields]
        assert "ts" in field_names
        assert "uid" in field_names
        assert "id.orig_h" in field_names
        assert "id.orig_p" in field_names
        assert "id.resp_h" in field_names
        assert "id.resp_p" in field_names
        assert "proto" in field_names
        assert "conn_state" in field_names

    def test_output_is_tsv(self):
        """Test that output format is TSV."""
        assert self.format.output.format == "tsv"
        assert self.format.output.file_extension == ".log"
        assert self.format.output.encoding == "utf-8"
        assert self.format.output.header_template is not None
        assert "#separator" in self.format.output.header_template

    def test_validate_tcp_connection(self):
        """Test validation of sample TCP connection."""
        event_data = {
            "ts": "2024-01-15T10:00:00.123456Z",
            "uid": "C1a2b3c4d5e6f7g8",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": "1.234",
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
        }

        result = validate_event(self.format, event_data)
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_validate_udp_connection(self):
        """Test validation of sample UDP connection."""
        event_data = {
            "ts": "2024-01-15T10:00:05.654321Z",
            "uid": "D9h8g7f6e5d4c3b2",
            "id.orig_h": "10.0.0.50",
            "id.orig_p": 53123,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": "0.012",
            "orig_bytes": 64,
            "resp_bytes": 128,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "orig_pkts": 1,
            "orig_ip_bytes": 92,
            "resp_pkts": 1,
            "resp_ip_bytes": 156,
        }

        result = validate_event(self.format, event_data)
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_validate_incomplete_connection(self):
        """Test validation of incomplete connection (no duration)."""
        event_data = {
            "ts": "2024-01-15T10:00:10.000000Z",
            "uid": "E1f2g3h4i5j6k7l8",
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 12345,
            "id.resp_h": "203.0.113.50",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "S0",
        }

        result = validate_event(self.format, event_data)
        if not result.valid:
            print(f"Validation errors: {result.errors}")
        assert result.valid is True

    def test_invalid_uid_format(self):
        """Test that invalid UID format is rejected."""
        event_data = {
            "ts": "2024-01-15T10:00:00Z",
            "uid": "invalid",  # Should be 16 characters
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "tcp",
            "conn_state": "SF",
        }

        result = validate_event(self.format, event_data)
        assert result.valid is False
        assert any("uid" in error for error in result.errors)

    def test_invalid_protocol(self):
        """Test that invalid protocol is rejected."""
        event_data = {
            "ts": "2024-01-15T10:00:00Z",
            "uid": "C1a2b3c4d5e6f7g8",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "proto": "invalid_proto",
            "conn_state": "SF",
        }

        result = validate_event(self.format, event_data)
        assert result.valid is False
        assert any("proto" in error for error in result.errors)


class TestLoadAllFormats:
    """Tests for loading all format definitions."""

    def test_load_all_formats(self):
        """Test that both formats load successfully."""
        formats = load_all_formats()

        assert len(formats) == 2
        assert "windows_event" in formats
        assert "zeek" in formats

        # Verify Windows Event format
        windows_fmt = formats["windows_event"]
        assert windows_fmt.name == "windows_event"
        assert windows_fmt.category == "host"
        assert len(windows_fmt.variants) == 3

        # Verify Zeek format
        zeek_fmt = formats["zeek"]
        assert zeek_fmt.name == "zeek"
        assert zeek_fmt.category == "network"
        assert zeek_fmt.variants is None or len(zeek_fmt.variants) == 0

    def test_formats_cached(self):
        """Test that formats are cached after loading."""
        from log_generator.formats import get_format

        # Load all formats
        load_all_formats()

        # Both should be in cache
        assert get_format("windows_event") is not None
        assert get_format("zeek") is not None

    def test_clear_cache_works(self):
        """Test that cache clearing works."""
        from log_generator.formats import clear_cache, get_format

        # Load formats
        load_all_formats()
        assert get_format("windows_event") is not None

        # Clear cache
        clear_cache()
        assert get_format("windows_event") is None
