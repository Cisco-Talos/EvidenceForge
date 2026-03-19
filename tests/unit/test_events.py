"""Tests for the canonical event model types (SecurityEvent, contexts, RawLogEntry)."""

import pytest
from datetime import datetime, timezone

from evidenceforge.events import (
    SecurityEvent,
    RawLogEntry,
    HostContext,
    AuthContext,
    ProcessContext,
    NetworkContext,
    DnsContext,
    FileContext,
    RegistryContext,
    IdsContext,
)


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""

    def test_minimal_event(self):
        """SecurityEvent requires only timestamp and event_type."""
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=timezone.utc)
        event = SecurityEvent(timestamp=ts, event_type="logon")
        assert event.timestamp == ts
        assert event.event_type == "logon"

    def test_contexts_default_to_none(self):
        """All optional context fields default to None."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="logon",
        )
        assert event.host is None
        assert event.auth is None
        assert event.process is None
        assert event.network is None
        assert event.dns is None
        assert event.file is None
        assert event.registry is None
        assert event.ids is None

    def test_with_all_contexts(self):
        """SecurityEvent can hold all context types simultaneously."""
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=timezone.utc)
        event = SecurityEvent(
            timestamp=ts,
            event_type="logon",
            host=HostContext(
                hostname="WS-01", ip="10.0.1.50", os="Windows 10",
                os_category="windows", system_type="workstation",
            ),
            auth=AuthContext(username="alice"),
            process=ProcessContext(
                pid=1234, parent_pid=4, image="cmd.exe",
                command_line="cmd.exe /c dir", username="alice",
            ),
            network=NetworkContext(
                src_ip="10.0.1.50", src_port=54321,
                dst_ip="10.0.1.100", dst_port=443, protocol="tcp",
            ),
            dns=DnsContext(query="example.com"),
            file=FileContext(path="C:\\temp\\test.txt", action="create"),
            registry=RegistryContext(key="HKLM\\Software\\Test"),
            ids=IdsContext(sid=1000001, message="Test alert", classification="misc"),
        )
        assert event.host.hostname == "WS-01"
        assert event.auth.username == "alice"
        assert event.process.pid == 1234
        assert event.network.dst_port == 443
        assert event.dns.query == "example.com"
        assert event.file.path == "C:\\temp\\test.txt"
        assert event.registry.key == "HKLM\\Software\\Test"
        assert event.ids.sid == 1000001

    def test_slots_prevents_dynamic_attributes(self):
        """slots=True prevents adding undeclared attributes."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="logon",
        )
        with pytest.raises(AttributeError):
            event.bogus_field = "should fail"


class TestHostContext:
    """Tests for HostContext dataclass."""

    def test_required_fields(self):
        ctx = HostContext(
            hostname="WS-01", ip="10.0.1.50", os="Windows 10",
            os_category="windows", system_type="workstation",
        )
        assert ctx.hostname == "WS-01"
        assert ctx.os_category == "windows"

    def test_domain_defaults_to_empty(self):
        ctx = HostContext(
            hostname="WS-01", ip="10.0.1.50", os="Windows 10",
            os_category="windows", system_type="workstation",
        )
        assert ctx.domain == ""

    def test_slots_prevents_dynamic_attributes(self):
        ctx = HostContext(
            hostname="WS-01", ip="10.0.1.50", os="Windows 10",
            os_category="windows", system_type="workstation",
        )
        with pytest.raises(AttributeError):
            ctx.bogus = "fail"


class TestAuthContext:
    """Tests for AuthContext dataclass."""

    def test_defaults(self):
        ctx = AuthContext(username="alice")
        assert ctx.logon_type == 2
        assert ctx.auth_package == "Negotiate"
        assert ctx.result == "success"
        assert ctx.failure_reason == ""
        assert ctx.source_ip == ""
        assert ctx.source_port == 0
        assert ctx.elevated is False
        assert ctx.logon_id == ""
        assert ctx.user_sid == ""


class TestNetworkContext:
    """Tests for NetworkContext dataclass."""

    def test_defaults(self):
        ctx = NetworkContext(
            src_ip="10.0.1.50", src_port=54321,
            dst_ip="10.0.1.100", dst_port=443, protocol="tcp",
        )
        assert ctx.service == ""
        assert ctx.zeek_uid == ""
        assert ctx.conn_id == ""
        assert ctx.duration == 0.0
        assert ctx.orig_bytes == 0
        assert ctx.resp_bytes == 0
        assert ctx.orig_pkts == 0
        assert ctx.resp_pkts == 0
        assert ctx.conn_state == ""
        assert ctx.history == ""
        assert ctx.local_orig is True
        assert ctx.local_resp is False


class TestRawLogEntry:
    """Tests for RawLogEntry escape hatch."""

    def test_construction(self):
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=timezone.utc)
        entry = RawLogEntry(
            timestamp=ts,
            target_emitter="syslog",
            data={"message": "test", "hostname": "srv-01"},
        )
        assert entry.timestamp == ts
        assert entry.target_emitter == "syslog"
        assert entry.data["message"] == "test"

    def test_slots_prevents_dynamic_attributes(self):
        entry = RawLogEntry(
            timestamp=datetime.now(timezone.utc),
            target_emitter="syslog",
            data={},
        )
        with pytest.raises(AttributeError):
            entry.bogus = "fail"
