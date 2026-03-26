"""Tests for the canonical event model types (SecurityEvent, contexts, RawLogEntry)."""

from datetime import UTC, datetime

import pytest

from evidenceforge.events import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    IdsContext,
    NetworkContext,
    ProcessContext,
    RawLogEntry,
    RegistryContext,
    SecurityEvent,
)


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""

    def test_minimal_event(self):
        """SecurityEvent requires only timestamp and event_type."""
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        event = SecurityEvent(timestamp=ts, event_type="logon")
        assert event.timestamp == ts
        assert event.event_type == "logon"

    def test_contexts_default_to_none(self):
        """All optional context fields default to None."""
        event = SecurityEvent(
            timestamp=datetime.now(UTC),
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
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=ts,
            event_type="logon",
            host=HostContext(
                hostname="WS-01",
                ip="10.0.1.50",
                os="Windows 10",
                os_category="windows",
                system_type="workstation",
            ),
            auth=AuthContext(username="alice"),
            process=ProcessContext(
                pid=1234,
                parent_pid=4,
                image="cmd.exe",
                command_line="cmd.exe /c dir",
                username="alice",
            ),
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=54321,
                dst_ip="10.0.1.100",
                dst_port=443,
                protocol="tcp",
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
            timestamp=datetime.now(UTC),
            event_type="logon",
        )
        with pytest.raises(AttributeError):
            event.bogus_field = "should fail"


class TestHostContext:
    """Tests for HostContext dataclass."""

    def test_required_fields(self):
        ctx = HostContext(
            hostname="WS-01",
            ip="10.0.1.50",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
        )
        assert ctx.hostname == "WS-01"
        assert ctx.os_category == "windows"

    def test_domain_defaults_to_empty(self):
        ctx = HostContext(
            hostname="WS-01",
            ip="10.0.1.50",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
        )
        assert ctx.domain == ""
        assert ctx.fqdn == ""
        assert ctx.netbios_domain == ""

    def test_fqdn_and_netbios_precomputed(self):
        ctx = HostContext(
            hostname="WS-01",
            ip="10.0.1.50",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
            domain="corp.local",
            fqdn="WS-01.corp.local",
            netbios_domain="CORP",
        )
        assert ctx.fqdn == "WS-01.corp.local"
        assert ctx.netbios_domain == "CORP"

    def test_slots_prevents_dynamic_attributes(self):
        ctx = HostContext(
            hostname="WS-01",
            ip="10.0.1.50",
            os="Windows 10",
            os_category="windows",
            system_type="workstation",
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
        assert ctx.logon_process == ""
        assert ctx.lm_package == ""
        assert ctx.logon_guid == ""
        assert ctx.subject_sid == ""
        assert ctx.subject_username == ""
        assert ctx.subject_domain == ""
        assert ctx.subject_logon_id == ""


class TestProcessContext:
    """Tests for ProcessContext dataclass."""

    def test_defaults(self):
        ctx = ProcessContext(
            pid=1234,
            parent_pid=4,
            image="cmd.exe",
            command_line="cmd.exe /c dir",
            username="alice",
        )
        assert ctx.integrity_level == "Medium"
        assert ctx.logon_id == ""
        assert ctx.parent_image == ""
        assert ctx.token_elevation == ""
        assert ctx.mandatory_label == ""


class TestNetworkContext:
    """Tests for NetworkContext dataclass."""

    def test_defaults(self):
        ctx = NetworkContext(
            src_ip="10.0.1.50",
            src_port=54321,
            dst_ip="10.0.1.100",
            dst_port=443,
            protocol="tcp",
        )
        assert ctx.service == ""
        assert ctx.zeek_uid == ""
        assert ctx.conn_id == ""
        assert ctx.duration is None
        assert ctx.orig_bytes is None
        assert ctx.resp_bytes is None
        assert ctx.orig_pkts == 0
        assert ctx.resp_pkts == 0
        assert ctx.conn_state == ""
        assert ctx.history == ""
        assert ctx.local_orig is True
        assert ctx.local_resp is False


class TestRawLogEntry:
    """Tests for RawLogEntry escape hatch."""

    def test_construction(self):
        ts = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
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
            timestamp=datetime.now(UTC),
            target_emitter="syslog",
            data={},
        )
        with pytest.raises(AttributeError):
            entry.bogus = "fail"


class TestKerberosContext:
    """Tests for KerberosContext dataclass."""

    def test_defaults(self):
        from evidenceforge.events.contexts import KerberosContext

        ctx = KerberosContext(target_username="alice", target_domain="CORP")
        assert ctx.target_sid == ""
        assert ctx.service_name == ""
        assert ctx.ticket_status == "0x0"
        assert ctx.pre_auth_type == 0
        assert ctx.source_port == 0

    def test_tgt_fields(self):
        from evidenceforge.events.contexts import KerberosContext

        ctx = KerberosContext(
            target_username="alice",
            target_domain="CORP",
            target_sid="S-1-5-21-123-456-789-1001",
            service_name="krbtgt",
            service_sid="S-1-5-21-123-456-789-502",
            ticket_options="0x40810010",
            encryption_type="0x12",
            pre_auth_type=15,
            source_ip="::ffff:10.0.1.50",
        )
        assert ctx.service_name == "krbtgt"
        assert ctx.pre_auth_type == 15


class TestShellContext:
    """Tests for ShellContext dataclass."""

    def test_defaults(self):
        from evidenceforge.events.contexts import ShellContext

        ctx = ShellContext(command="ls -la")
        assert ctx.exit_code == 0

    def test_with_exit_code(self):
        from evidenceforge.events.contexts import ShellContext

        ctx = ShellContext(command="false", exit_code=1)
        assert ctx.exit_code == 1


class TestSecurityEventNewContexts:
    """Tests for SecurityEvent with kerberos and shell contexts."""

    def test_kerberos_slot(self):
        from evidenceforge.events.contexts import KerberosContext

        evt = SecurityEvent(
            timestamp=datetime.now(UTC),
            event_type="kerberos_tgt",
            kerberos=KerberosContext(target_username="alice", target_domain="CORP"),
        )
        assert evt.kerberos is not None
        assert evt.shell is None

    def test_shell_slot(self):
        from evidenceforge.events.contexts import ShellContext

        evt = SecurityEvent(
            timestamp=datetime.now(UTC),
            event_type="bash_command",
            shell=ShellContext(command="ls"),
        )
        assert evt.shell is not None
        assert evt.kerberos is None
