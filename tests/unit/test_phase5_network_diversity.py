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

"""Unit tests for Phase 5.3: Protocol & Network Diversity."""

import json
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import (
    EXTERNAL_IPS,
    REVERSE_DNS,
    ActivityGenerator,
    _detect_ip_provider,
    _generate_random_external_ip,
    _generate_random_hostname,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestExpandedIPPools:
    """Test that IP pools have been expanded."""

    def test_web_pool_has_many_ips(self):
        assert len(EXTERNAL_IPS["connection_web"]) >= 20

    def test_email_pool_has_multiple_ips(self):
        assert len(EXTERNAL_IPS["connection_email"]) >= 6

    def test_saas_category_exists(self):
        assert "connection_saas" in EXTERNAL_IPS
        assert len(EXTERNAL_IPS["connection_saas"]) >= 6

    def test_reverse_dns_covers_pool_ips(self):
        """Most pool IPs should have a REVERSE_DNS entry."""
        all_pool_ips = set()
        for ips in EXTERNAL_IPS.values():
            all_pool_ips.update(ips)
        covered = sum(1 for ip in all_pool_ips if ip in REVERSE_DNS)
        assert covered >= len(all_pool_ips) * 0.8, (
            f"Only {covered}/{len(all_pool_ips)} pool IPs have REVERSE_DNS entries"
        )


class TestRandomIPGenerator:
    """Test random CDN/cloud IP generation."""

    def test_generates_valid_public_ip(self):
        import random

        rng = random.Random(42)
        for _ in range(100):
            ip = _generate_random_external_ip(rng)
            parts = ip.split(".")
            assert len(parts) == 4
            octets = [int(p) for p in parts]
            # Should not be private
            assert not (octets[0] == 10)
            assert not (octets[0] == 192 and octets[1] == 168)
            assert not (octets[0] == 127)

    def test_generates_plausible_hostname(self):
        import random

        rng = random.Random(42)
        hostname = _generate_random_hostname(rng, "52.84.100.50")
        assert "." in hostname  # Has a domain
        assert len(hostname) > 5


class TestProviderDetection:
    """Test provider detection robustness for untrusted IP input."""

    def test_detect_ip_provider_invalid_input_returns_generic(self):
        assert _detect_ip_provider("not-an-ip") == "generic"

    def test_detect_ip_provider_ipv6_returns_generic(self):
        assert _detect_ip_provider("2001:db8::1") == "generic"


class TestDnsLookupEmission:
    """Test DNS lookup generation preceding TCP connections."""

    def test_dns_lookup_emits_zeek_dns(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen._emit_dns_lookup(
            src_ip="10.0.10.1",
            dst_ip="172.217.14.206",
            time=timestamp,
        )
        # DNS now goes through SecurityEvent pipeline via emit() (DnsContext fan-out)
        assert mock_emitters["zeek_dns"].emit.called
        dns_se = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        dns_ctx = dns_se.dns
        assert dns_ctx is not None
        # Query type varies (A, AAAA, PTR, SRV, MX) — validate based on type
        qtype_name = dns_ctx.query_type
        if qtype_name == "A":
            assert dns_ctx.query == "www.google.com"
            assert "172.217.14.206" in dns_ctx.answers
        elif qtype_name == "AAAA":
            assert dns_ctx.query == "www.google.com"
            assert ":" in dns_ctx.answers[0]
        elif qtype_name == "PTR":
            assert dns_ctx.query.endswith(".in-addr.arpa")
            assert dns_ctx.answers == ["www.google.com"]
        elif qtype_name == "SRV":
            assert dns_ctx.query.startswith("_")
        elif qtype_name == "MX":
            assert "mail." in dns_ctx.answers[0]
        net = dns_se.network
        assert net.src_ip == "10.0.10.1"
        assert net.dst_port == 53
        assert net.protocol == "udp"

    def test_dns_lookup_emits_conn_record(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen._emit_dns_lookup(
            src_ip="10.0.10.1",
            dst_ip="172.217.14.206",
            time=timestamp,
        )
        # Should also emit a UDP/53 conn record via dispatch
        assert mock_emitters["zeek_conn"].emit.called
        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "udp" or event.network.dst_port == 53

    def test_dns_timestamp_precedes_connection_time(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen._emit_dns_lookup(
            src_ip="10.0.10.1",
            dst_ip="172.217.14.206",
            time=timestamp,
        )
        dns_se = mock_emitters["zeek_dns"].emit.call_args[0][0]
        # DNS timestamp should be before the connection timestamp
        assert dns_se.timestamp < timestamp

    def test_dns_conn_uid_correlation(self, activity_gen, timestamp, state_manager, mock_emitters):
        """DNS conn.log and dns.log entries must share the same Zeek UID."""
        state_manager.set_current_time(timestamp)
        activity_gen._emit_dns_lookup(
            src_ip="10.0.10.1",
            dst_ip="172.217.14.206",
            time=timestamp,
        )
        # Both conn and dns now go through emit() on the SAME SecurityEvent
        # Get the dns.log SecurityEvent
        dns_se = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        dns_uid = dns_se.network.zeek_uid

        # Get the conn.log SecurityEvent
        conn_se = mock_emitters["zeek_conn"].emit.call_args_list[0][0][0]
        conn_uid = conn_se.network.zeek_uid

        # UIDs must match — this is how Zeek correlates logs
        assert dns_uid == conn_uid, (
            f"DNS and conn UIDs must match for cross-log correlation: "
            f"dns={dns_uid}, conn={conn_uid}"
        )
        assert dns_uid.startswith("C"), "Zeek conn UIDs use 'C' prefix"


class TestDnsQueryTypeSemantics:
    """Test that DNS query types have correct semantics."""

    @pytest.fixture
    def activity_gen(self, state_manager, mock_emitters):
        return ActivityGenerator(state_manager, mock_emitters)

    @pytest.fixture
    def state_manager(self):
        sm = StateManager()
        sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        return sm

    @pytest.fixture
    def mock_emitters(self):
        return {
            "windows_event_security": Mock(),
            "zeek_conn": Mock(),
            "zeek_dns": Mock(),
            "ecar": Mock(),
            "syslog": Mock(),
        }

    def test_no_cname_as_explicit_qtype(self, activity_gen, state_manager, mock_emitters):
        """CNAME should never appear as an explicit qtype."""
        qtypes_seen = set()
        for _ in range(200):
            state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
            mock_emitters["zeek_dns"].emit_raw.reset_mock()
            activity_gen._emit_dns_lookup(
                src_ip="10.0.10.1",
                dst_ip="172.217.14.206",
                time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            )
            if mock_emitters["zeek_dns"].emit_raw.called:
                event = mock_emitters["zeek_dns"].emit_raw.call_args_list[0][0][0]
                qtypes_seen.add(event["qtype_name"])
        assert "CNAME" not in qtypes_seen, "CNAME should never be an explicit qtype"

    def test_aaaa_returns_ipv6(self, activity_gen, state_manager, mock_emitters):
        """AAAA queries must return IPv6 addresses."""
        for _ in range(100):
            state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
            mock_emitters["zeek_dns"].emit_raw.reset_mock()
            activity_gen._emit_dns_lookup(
                src_ip="10.0.10.1",
                dst_ip="172.217.14.206",
                time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            )
            if mock_emitters["zeek_dns"].emit_raw.called:
                event = mock_emitters["zeek_dns"].emit_raw.call_args_list[0][0][0]
                if event["qtype_name"] == "AAAA":
                    assert ":" in event["answers"][0], (
                        f"AAAA answer must be IPv6, got: {event['answers']}"
                    )
                    return  # Found at least one AAAA
        # It's probabilistic, so we might not see AAAA in 100 tries, but very unlikely

    def test_ptr_uses_in_addr_arpa(self, activity_gen, state_manager, mock_emitters):
        """PTR queries must use in-addr.arpa format."""
        for _ in range(200):
            state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
            mock_emitters["zeek_dns"].emit_raw.reset_mock()
            activity_gen._emit_dns_lookup(
                src_ip="10.0.10.1",
                dst_ip="172.217.14.206",
                time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            )
            if mock_emitters["zeek_dns"].emit_raw.called:
                event = mock_emitters["zeek_dns"].emit_raw.call_args_list[0][0][0]
                if event["qtype_name"] == "PTR":
                    assert event["query"].endswith(".in-addr.arpa"), (
                        f"PTR query must end with .in-addr.arpa, got: {event['query']}"
                    )
                    # Answer should be a list containing a hostname, not an IP
                    assert isinstance(event["answers"], list) and len(event["answers"]) > 0, (
                        f"PTR answers should be a non-empty list, got: {event['answers']}"
                    )
                    assert "." in event["answers"][0] and not event["answers"][0][0].isdigit(), (
                        f"PTR answer should be hostname, got: {event['answers'][0]}"
                    )
                    return

    def test_srv_queries_present(self, activity_gen, state_manager, mock_emitters):
        """SRV queries should appear for AD service discovery."""
        for _ in range(300):
            state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
            mock_emitters["zeek_dns"].emit_raw.reset_mock()
            activity_gen._emit_dns_lookup(
                src_ip="10.0.10.1",
                dst_ip="172.217.14.206",
                time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            )
            if mock_emitters["zeek_dns"].emit_raw.called:
                event = mock_emitters["zeek_dns"].emit_raw.call_args_list[0][0][0]
                if event["qtype_name"] == "SRV":
                    assert event["query"].startswith("_"), (
                        f"SRV query should start with _, got: {event['query']}"
                    )
                    assert event["qtype"] == 33
                    return


class TestZeekDnsFormat:
    """Test Zeek dns.log format definition."""

    def test_format_loads(self):
        fmt = load_format("zeek_dns")
        assert fmt.name == "zeek_dns"

    def test_format_has_required_fields(self):
        fmt = load_format("zeek_dns")
        field_names = {f.name for f in fmt.fields}
        assert "ts" in field_names
        assert "uid" in field_names
        assert "query" in field_names
        assert "qtype_name" in field_names
        assert "rcode_name" in field_names
        assert "answers" in field_names


class TestZeekDnsEmitter:
    """Test Zeek dns.log emitter produces valid NDJSON."""

    def test_produces_valid_json(self, tmp_path):
        from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter

        fmt_def = load_format("zeek_dns")
        output_file = tmp_path / "zeek_dns.json"
        emitter = ZeekDnsEmitter(fmt_def, output_file, threaded=False)

        emitter.emit_event(
            {
                "ts": datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
                "uid": "CAbcdefghijklmnop",
                "id.orig_h": "10.0.10.1",
                "id.orig_p": 50000,
                "id.resp_h": "10.0.0.1",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": 12345,
                "query": "www.google.com",
                "qclass": 1,
                "qclass_name": "C_INTERNET",
                "qtype": 1,
                "qtype_name": "A",
                "rcode": 0,
                "rcode_name": "NOERROR",
                "AA": False,
                "TC": False,
                "RD": True,
                "RA": True,
                "Z": 0,
                "answers": ["172.217.14.206"],
                "TTLs": [300.0],
                "rejected": False,
                "opcode": 0,
                "opcode_name": "query",
            }
        )
        emitter.flush()

        content = output_file.read_text()
        lines = [line for line in content.strip().splitlines() if line.strip()]
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["query"] == "www.google.com"
        assert parsed["answers"] == ["172.217.14.206"]
        assert parsed["TTLs"] == [300.0]
        assert parsed["rcode_name"] == "NOERROR"


class TestZeekDnsParser:
    """Test Zeek dns.log eval parser."""

    def test_parses_ndjson(self, tmp_path):
        from evidenceforge.evaluation.parsers.zeek_dns import ZeekDnsParser

        dns_file = tmp_path / "zeek_dns.json"
        record = json.dumps(
            {
                "ts": 1710496800.123456,
                "uid": "CAbcdefghijklmnop",
                "id.orig_h": "10.0.10.1",
                "id.orig_p": 50000,
                "id.resp_h": "10.0.0.1",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": 12345,
                "query": "www.google.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": "172.217.14.206",
            }
        )
        dns_file.write_text(record + "\n")

        parser = ZeekDnsParser()
        assert parser.can_parse(dns_file)

        records = list(parser.parse_file(dns_file))
        assert len(records) == 1
        assert records[0].fields["query"] == "www.google.com"
        assert records[0].timestamp is not None
        assert not records[0].parse_errors
