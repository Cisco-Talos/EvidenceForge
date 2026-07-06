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

"""Tests for the CausalExpansionEngine core mechanics."""

from datetime import UTC, datetime

import pytest

from evidenceforge.generation.causal.engine import (
    CausalExpansionEngine,
    ExpandedEvent,
    ExpansionContext,
)
from evidenceforge.generation.causal.rules import (
    DnsBeforeConnection,
    ExpansionRule,
    KerberosBeforeLogon,
    ProcessAccessAfterRemoteThread,
    SupplementaryAuditEvents,
)
from evidenceforge.generation.causal.timing import TimingSpec


def _make_ctx(**overrides) -> ExpansionContext:
    """Create a minimal ExpansionContext with overrides."""
    defaults = {
        "event_type": "connection",
        "timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return ExpansionContext(**defaults)


# --- TimingSpec ---


class TestTimingSpec:
    def test_frozen(self):
        ts = TimingSpec(min_ms=5, max_ms=80, position="before")
        with pytest.raises(AttributeError):
            ts.min_ms = 10  # type: ignore[misc]

    def test_fields(self):
        ts = TimingSpec(min_ms=5, max_ms=80, position="before")
        assert ts.min_ms == 5
        assert ts.max_ms == 80
        assert ts.position == "before"


# --- CausalExpansionEngine core ---


class TestEngineCore:
    def test_empty_rules_returns_empty(self):
        engine = CausalExpansionEngine(rules=[])
        ctx = _make_ctx()
        result = engine.expand("connection", ctx)
        assert result == []

    def test_raw_event_type_returns_empty(self):
        engine = CausalExpansionEngine(rules=[DnsBeforeConnection()])
        ctx = _make_ctx()
        result = engine.expand("raw", ctx)
        assert result == []

    def test_rule_priority_ordering(self):
        """Rules with lower priority values run first."""

        class HighPriorityRule(ExpansionRule):
            name = "high"
            description = "high priority"
            priority = 10

            def matches(self, event_type, ctx):
                return True

            def expand(self, event_type, ctx):
                return [
                    ExpandedEvent(
                        method="high",
                        kwargs={},
                        timing=TimingSpec(10, 20, "before"),
                        description="high",
                    )
                ]

        class LowPriorityRule(ExpansionRule):
            name = "low"
            description = "low priority"
            priority = 50

            def matches(self, event_type, ctx):
                return True

            def expand(self, event_type, ctx):
                return [
                    ExpandedEvent(
                        method="low",
                        kwargs={},
                        timing=TimingSpec(5, 10, "before"),
                        description="low",
                    )
                ]

        # Pass rules in reverse order — engine should sort by priority
        engine = CausalExpansionEngine(rules=[LowPriorityRule(), HighPriorityRule()])
        ctx = _make_ctx()
        result = engine.expand("connection", ctx)
        # Both rules fire; ordering is by timing position, not rule priority
        assert len(result) == 2

    def test_before_events_sorted_largest_offset_first(self):
        """Before-events are sorted so the earliest (largest offset) comes first."""

        class MultiBeforeRule(ExpansionRule):
            name = "multi"
            description = "multi"
            priority = 10

            def matches(self, event_type, ctx):
                return True

            def expand(self, event_type, ctx):
                return [
                    ExpandedEvent(method="close", kwargs={}, timing=TimingSpec(5, 10, "before")),
                    ExpandedEvent(method="far", kwargs={}, timing=TimingSpec(50, 100, "before")),
                ]

        engine = CausalExpansionEngine(rules=[MultiBeforeRule()])
        result = engine.expand("connection", _make_ctx())
        assert result[0].method == "far"
        assert result[1].method == "close"

    def test_after_events_sorted_smallest_offset_first(self):
        """After-events are sorted so the closest (smallest offset) comes first."""

        class MultiAfterRule(ExpansionRule):
            name = "multi"
            description = "multi"
            priority = 10

            def matches(self, event_type, ctx):
                return True

            def expand(self, event_type, ctx):
                return [
                    ExpandedEvent(method="far", kwargs={}, timing=TimingSpec(50, 100, "after")),
                    ExpandedEvent(method="close", kwargs={}, timing=TimingSpec(1, 5, "after")),
                ]

        engine = CausalExpansionEngine(rules=[MultiAfterRule()])
        result = engine.expand("connection", _make_ctx())
        assert result[0].method == "close"
        assert result[1].method == "far"

    def test_before_events_precede_after_events(self):
        """Before-events always come before after-events in the result."""

        class MixedRule(ExpansionRule):
            name = "mixed"
            description = "mixed"
            priority = 10

            def matches(self, event_type, ctx):
                return True

            def expand(self, event_type, ctx):
                return [
                    ExpandedEvent(
                        method="after_event",
                        kwargs={},
                        timing=TimingSpec(1, 5, "after"),
                    ),
                    ExpandedEvent(
                        method="before_event",
                        kwargs={},
                        timing=TimingSpec(10, 20, "before"),
                    ),
                ]

        engine = CausalExpansionEngine(rules=[MixedRule()])
        result = engine.expand("connection", _make_ctx())
        assert result[0].method == "before_event"
        assert result[1].method == "after_event"

    def test_non_matching_rule_skipped(self):
        """Rules that don't match produce no expanded events."""

        class NeverMatchRule(ExpansionRule):
            name = "never"
            description = "never"
            priority = 10

            def matches(self, event_type, ctx):
                return False

            def expand(self, event_type, ctx):
                return [ExpandedEvent(method="nope", kwargs={}, timing=TimingSpec(1, 1, "before"))]

        engine = CausalExpansionEngine(rules=[NeverMatchRule()])
        result = engine.expand("connection", _make_ctx())
        assert result == []

    def test_failing_rule_logged_and_skipped(self):
        """A rule that raises an exception is caught and skipped."""

        class BrokenRule(ExpansionRule):
            name = "broken"
            description = "broken"
            priority = 10

            def matches(self, event_type, ctx):
                raise ValueError("boom")

            def expand(self, event_type, ctx):
                return []

        engine = CausalExpansionEngine(rules=[BrokenRule()])
        result = engine.expand("connection", _make_ctx())
        assert result == []


# --- DnsBeforeConnection rule ---


class TestDnsBeforeConnection:
    def test_matches_tcp_connection(self):
        rule = DnsBeforeConnection()
        ctx = _make_ctx(dst_ip="8.8.8.8", protocol="tcp", dst_port=443)
        assert rule.matches("connection", ctx) is True

    def test_skips_udp(self):
        rule = DnsBeforeConnection()
        ctx = _make_ctx(dst_ip="8.8.8.8", protocol="udp", dst_port=443)
        assert rule.matches("connection", ctx) is False

    def test_skips_port_53(self):
        """DNS connections themselves should not trigger DNS expansion."""
        rule = DnsBeforeConnection()
        ctx = _make_ctx(dst_ip="10.0.0.1", protocol="tcp", dst_port=53)
        assert rule.matches("connection", ctx) is False

    def test_skips_non_connection_event(self):
        rule = DnsBeforeConnection()
        ctx = _make_ctx(dst_ip="8.8.8.8", protocol="tcp", dst_port=443)
        assert rule.matches("logon", ctx) is False

    def test_skips_missing_dst_ip(self):
        rule = DnsBeforeConnection()
        ctx = _make_ctx(dst_ip=None, protocol="tcp", dst_port=443)
        assert rule.matches("connection", ctx) is False

    def test_expand_returns_dns_lookup(self):
        rule = DnsBeforeConnection()
        ctx = _make_ctx(src_ip="10.10.10.5", dst_ip="203.0.113.50", protocol="tcp", dst_port=443)
        result = rule.expand("connection", ctx)
        assert len(result) == 1
        ev = result[0]
        assert ev.method == "_emit_dns_lookup"
        assert ev.kwargs["src_ip"] == "10.10.10.5"
        assert ev.kwargs["dst_ip"] == "203.0.113.50"
        assert ev.timing.position == "before"


# --- ExpansionContext ---


class TestExpansionContext:
    def test_defaults(self):
        ctx = ExpansionContext(
            event_type="connection",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
        )
        assert ctx.src_ip is None
        assert ctx.dst_ip is None
        assert ctx.dns_cache == {}
        assert ctx.kerberos_cache == {}
        assert ctx.dns_server_ips == ["10.0.0.1"]
        assert ctx.ad_domain == "corp.local"

    def test_dns_cache_shared(self):
        """DNS cache dict is shared by reference, not copied."""
        cache: dict[tuple[str, str], float] = {("10.0.0.1", "example.com"): 100.0}
        ctx = ExpansionContext(
            event_type="connection",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dns_cache=cache,
        )
        assert ctx.dns_cache is cache


# --- Default registry ---


class TestDefaultRegistry:
    def test_default_rules_returns_list(self):
        from evidenceforge.generation.causal.registry import default_rules

        rules = default_rules()
        assert isinstance(rules, list)
        assert len(rules) >= 1
        assert all(isinstance(r, ExpansionRule) for r in rules)

    def test_dns_rule_in_defaults(self):
        from evidenceforge.generation.causal.registry import default_rules

        rules = default_rules()
        names = [r.name for r in rules]
        assert "dns_before_connection" in names

    def test_kerberos_rule_in_defaults(self):
        from evidenceforge.generation.causal.registry import default_rules

        rules = default_rules()
        names = [r.name for r in rules]
        assert "kerberos_before_logon" in names


# --- KerberosBeforeLogon rule ---


class TestKerberosBeforeLogon:
    def test_matches_kerberos_logon_on_windows(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(auth_package="Kerberos", os_category="windows")
        assert rule.matches("logon", ctx) is True

    def test_skips_ntlm(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(auth_package="NTLM", os_category="windows")
        assert rule.matches("logon", ctx) is False

    def test_skips_negotiate(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(auth_package="Negotiate", os_category="windows")
        assert rule.matches("logon", ctx) is False

    def test_skips_linux(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(auth_package="Kerberos", os_category="linux")
        assert rule.matches("logon", ctx) is False

    def test_skips_non_logon_event(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(auth_package="Kerberos", os_category="windows")
        assert rule.matches("connection", ctx) is False

    def test_expand_returns_kerberos_call(self):
        rule = KerberosBeforeLogon()
        ctx = _make_ctx(
            auth_package="Kerberos",
            os_category="windows",
            actor="alice",
            target_system="WS-01",
            src_ip="10.10.10.5",
        )
        result = rule.expand("logon", ctx)
        assert len(result) == 1
        ev = result[0]
        assert ev.method == "_emit_dc_kerberos_for_logon"
        assert ev.kwargs["user"] == "alice"
        assert ev.kwargs["system"] == "WS-01"
        assert ev.kwargs["auth_package"] == "Kerberos"
        assert ev.kwargs["source_ip"] == "10.10.10.5"
        assert ev.timing.position == "before"


# --- ProcessAccessAfterRemoteThread rule ---


class TestProcessAccessAfterRemoteThread:
    def test_matches_crt_targeting_lsass(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            source_pid=1234,
            target_pid=636,
            target_image=r"C:\Windows\System32\lsass.exe",
        )
        assert rule.matches("create_remote_thread", ctx) is True

    def test_matches_lsass_case_insensitive(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            source_pid=1234,
            target_pid=636,
            target_image=r"C:\Windows\System32\LSASS.EXE",
        )
        assert rule.matches("create_remote_thread", ctx) is True

    def test_matches_non_lsass_target(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            source_pid=4600,
            target_pid=4796,
            target_image=r"C:\Windows\System32\svchost.exe",
        )
        assert rule.matches("create_remote_thread", ctx) is True

    def test_skips_non_crt_event(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            source_pid=1234,
            target_pid=636,
            target_image=r"C:\Windows\System32\lsass.exe",
        )
        assert rule.matches("process_create", ctx) is False

    def test_skips_no_target_image(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(source_pid=1234, target_pid=636, target_image=None)
        assert rule.matches("create_remote_thread", ctx) is False

    def test_skips_missing_pid_context(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(target_image=r"C:\Windows\System32\lsass.exe")
        assert rule.matches("create_remote_thread", ctx) is False

    def test_expand_returns_process_access(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            actor="attacker",
            target_system="WS-01",
            source_pid=1234,
            source_image=r"C:\temp\mimikatz.exe",
            target_pid=636,
            target_image=r"C:\Windows\System32\lsass.exe",
        )
        result = rule.expand("create_remote_thread", ctx)
        assert len(result) == 1
        ev = result[0]
        assert ev.method == "generate_process_access"
        assert ev.kwargs["granted_access"] == "0x1FFFFF"
        assert ev.kwargs["source_pid"] == 1234
        assert ev.kwargs["target_pid"] == 636
        assert ev.timing.position == "before"
        assert ev.timing.min_ms == 1
        assert ev.timing.max_ms == 75

    def test_expand_non_lsass_returns_lower_friction_process_access(self):
        rule = ProcessAccessAfterRemoteThread()
        ctx = _make_ctx(
            actor="SYSTEM",
            target_system="WS-01",
            source_pid=4600,
            source_image=(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform"
                r"\4.18.2301.6-0\MsMpEng.exe"
            ),
            target_pid=4796,
            target_image=r"C:\Windows\System32\RuntimeBroker.exe",
        )

        result = rule.expand("create_remote_thread", ctx)

        assert len(result) == 1
        ev = result[0]
        assert ev.method == "generate_process_access"
        assert ev.kwargs["granted_access"] == "0x1010"
        assert ev.kwargs["source_pid"] == 4600
        assert ev.kwargs["target_pid"] == 4796
        assert ev.timing.position == "before"
        assert ev.timing.min_ms == 8
        assert ev.timing.max_ms == 180


# --- SupplementaryAuditEvents rule ---


class TestSupplementaryAuditEvents:
    def test_matches_windows_process_with_command(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(os_category="windows", command_line="cmd.exe /c whoami")
        assert rule.matches("process_create", ctx) is True

    def test_skips_linux(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(os_category="linux", command_line="whoami")
        assert rule.matches("process_create", ctx) is False

    def test_skips_empty_command(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(os_category="windows", command_line="")
        assert rule.matches("process_create", ctx) is False

    def test_skips_non_process_event(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(os_category="windows", command_line="net user hacker P@ss /add")
        assert rule.matches("connection", ctx) is False

    def test_expand_net_user_add(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line="net user hacker P@ssw0rd /add /domain",
            actor="attacker",
            target_system="DC-01",
        )
        result = rule.expand("process_create", ctx)
        assert [ev.method for ev in result] == [
            "generate_account_created",
            "generate_password_reset",
            "generate_account_changed",
        ]
        assert all(ev.kwargs["target_username"] == "hacker" for ev in result)
        assert [ev.timing.position for ev in result] == ["after", "after", "after"]
        assert result[0].timing.max_ms < result[1].timing.min_ms
        assert result[1].timing.max_ms < result[2].timing.min_ms
        assert result[2].kwargs["password_last_set_to_event_time"] is True
        assert result[2].kwargs["old_uac_value"] == "0x15"
        assert result[2].kwargs["new_uac_value"] == "0x10"

    def test_expand_net_user_delete(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line="net user hacker /delete",
            actor="attacker",
            target_system="DC-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_account_deleted"

    def test_expand_schtasks_create(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line='schtasks /create /tn "Backdoor" /tr "C:\\temp\\evil.exe" /sc daily',
            actor="attacker",
            target_system="WS-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_scheduled_task"
        assert result[0].kwargs["task_name"] == "Backdoor"
        assert result[0].kwargs["source_command_line"] == ctx.command_line

    def test_expand_sc_create(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line='sc create EvilSvc binpath= "C:\\temp\\evil.exe"',
            actor="attacker",
            target_system="WS-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_service_installed"
        assert result[0].kwargs["service_name"] == "EvilSvc"
        assert result[0].kwargs["service_start_type"] == "3"

    def test_expand_sc_create_auto_start(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line='sc create EvilSvc binpath= "C:\\temp\\evil.exe" start= auto',
            actor="attacker",
            target_system="WS-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_service_installed"
        assert result[0].kwargs["service_name"] == "EvilSvc"
        assert result[0].kwargs["service_start_type"] == "2"

    def test_expand_wevtutil_cl(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line="wevtutil cl Security",
            actor="attacker",
            target_system="WS-01",
            logon_id="0xabc123",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_log_cleared"
        assert result[0].kwargs["subject_logon_id"] == "0xabc123"

    def test_skip_types_prevents_duplicate(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line="net user hacker P@ssw0rd /add /domain",
            actor="attacker",
            target_system="DC-01",
            skip_types={"account_created"},
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 0

    def test_no_match_for_benign_command(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line="whoami /all",
            actor="attacker",
            target_system="WS-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 0

    def test_expand_net_group_add(self):
        rule = SupplementaryAuditEvents()
        ctx = _make_ctx(
            os_category="windows",
            command_line='net group "Domain Admins" hacker /add /domain',
            actor="attacker",
            target_system="DC-01",
        )
        result = rule.expand("process_create", ctx)
        assert len(result) == 1
        assert result[0].method == "generate_group_membership_change"
        assert result[0].kwargs["group_name"] == "Domain Admins"
        assert result[0].kwargs["member_username"] == "hacker"
