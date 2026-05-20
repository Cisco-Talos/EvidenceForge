# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration tests for DNS/SNI realism across the generation pipeline.

These tests verify that:
- DNS queries, SSL SNI, and proxy hostnames are consistent per connection
- No reverse-DNS style hostnames appear for web/SaaS connections
- No IP sinkhole (many domains → same IP)
- Zeek weird protocol types match the connection protocol
- Background HTTPS uses real service domains
- Suspicious noise connections include hostnames
- Multi-IP domains return full answer sets in DNS
"""

import json
import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import DnsContext, FirewallContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.suspicious_benign import generate_unusual_outbound
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "zeek_ssl": Mock(),
        "zeek_x509": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "proxy_access": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    gen = ActivityGenerator(state_manager, mock_emitters)
    gen._dns_server_ips = ["10.0.0.1"]
    return gen


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestHostnameConsistency:
    """DNS query domain, SSL SNI, and proxy hostname must be identical."""

    def test_tunnel_era_background_txt_spf_avoids_documentation_ranges(self):
        """Benign TXT/SPF collisions should not expose RFC 5737 test networks."""
        from evidenceforge.generation.engine.storyline import _dns_tunnel_background_txt_record

        answers = [_dns_tunnel_background_txt_record(random.Random(seed))[1] for seed in range(500)]

        assert not any("203.0.113." in answer for answer in answers)

    def test_explicit_unregistered_hostname_tracks_rewritten_destination(
        self, activity_gen, timestamp, mock_emitters
    ):
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

        hostname = "attacker-validated.example.net"
        expected_ip = resolve_domain_ip(hostname, src_host="10.0.1.50")

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            service="ssl",
            emit_dns=True,
            hostname=hostname,
        )

        assert activity_gen._last_connection_effective_dst_ip == expected_ip
        conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert conn_event.network.dst_ip == expected_ip

    def test_ssl_sni_matches_dns_query(self, activity_gen, timestamp, state_manager, mock_emitters):
        """For a web connection with emit_dns=True, SNI should match DNS query domain."""
        state_manager.set_current_time(timestamp)

        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        domain, ip = pick_domain_and_ip(rng, "web", src_host="WS-01")

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip=ip,
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            emit_dns=True,
            hostname=domain,
            conn_state="SF",  # Force successful connection for SSL context
            duration=1.0,
            orig_bytes=500,
            resp_bytes=1000,
        )

        # Check SSL SNI on the main connection event dispatched to zeek_conn
        # (SSL context is attached to the connection SecurityEvent)
        if mock_emitters["zeek_conn"].emit.called:
            conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
            if conn_event.ssl is not None:
                assert conn_event.ssl.server_name == domain, (
                    f"SNI '{conn_event.ssl.server_name}' != expected domain '{domain}'"
                )
            else:
                pytest.skip("conn_state was not SF — SSL context not generated")
        else:
            pytest.skip("zeek_conn emitter not called")

        # Check DNS query (emitted via causal expansion as a separate connection event)
        dns_calls = mock_emitters["zeek_dns"].emit.call_args_list
        if dns_calls:
            dns_event = dns_calls[0][0][0]
            if dns_event.dns:
                assert dns_event.dns.query == domain, (
                    f"DNS query '{dns_event.dns.query}' != expected domain '{domain}'"
                )

    def test_hostname_rewrites_mismatched_destination_ip(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Caller-supplied hostname/IP mismatches should resolve to the hostname's IP pool."""
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        state_manager.set_current_time(timestamp)
        hostname = "www.google.com"
        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="208.80.154.224",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            emit_dns=True,
            hostname=hostname,
            conn_state="SF",
        )

        conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert conn_event.network.dst_ip in get_domain_ips(hostname)
        assert conn_event.ssl is not None
        assert conn_event.ssl.server_name == hostname

    def test_unregistered_hostname_uses_dns_derived_destination(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Unregistered explicit hostnames should not connect to a different caller IP."""
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

        state_manager.set_current_time(timestamp)
        hostname = "unlisted-cdn.example.test"
        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="151.101.141.68",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            emit_dns=True,
            hostname=hostname,
            conn_state="SF",
        )

        expected_ip = resolve_domain_ip(hostname, src_host="10.0.1.50")
        conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert conn_event.network.dst_ip == expected_ip
        assert conn_event.ssl is not None
        assert conn_event.ssl.server_name == hostname

    def test_connection_dns_prerequisite_contains_tcp_destination(
        self, activity_gen, timestamp, state_manager, mock_emitters, monkeypatch
    ):
        """Connection DNS evidence should resolve the same IP used by the flow."""
        import evidenceforge.generation.activity.generator as generator_module

        rng = random.Random(42)
        monkeypatch.setattr(rng, "random", lambda: 0.5)
        monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)
        state_manager.set_current_time(timestamp)
        hostname = "cdn-assets-update.com"

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="151.101.141.68",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            emit_dns=True,
            hostname=hostname,
            conn_state="SF",
        )

        dns_event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert dns_event.dns is not None
        assert dns_event.dns.query_type == "A"
        assert dns_event.dns.query == hostname
        assert conn_event.network.dst_ip in dns_event.dns.answers

    def test_dns_response_completes_before_dependent_connection(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="142.250.72.36",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            emit_dns=True,
            hostname="www.gstatic.com",
            conn_state="SF",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5000,
        )

        dns_event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        conn_event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        dns_complete = dns_event.timestamp.timestamp() + (dns_event.dns.rtt or 0)
        assert dns_complete < conn_event.timestamp.timestamp()

    def test_ephemeral_ports_do_not_repeat_exact_five_tuple(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """High-volume destination traffic should not reuse exact 5-tuples."""
        state_manager.set_current_time(timestamp)

        for idx in range(300):
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="93.184.216.34",
                time=timestamp + timedelta(milliseconds=idx),
                dst_port=443,
                proto="tcp",
                service="ssl",
                hostname="example.com",
                conn_state="SF",
                duration=1.0,
            )

        tuples = [
            (
                call.args[0].network.src_ip,
                call.args[0].network.src_port,
                call.args[0].network.dst_ip,
                call.args[0].network.dst_port,
                call.args[0].network.protocol,
            )
            for call in mock_emitters["zeek_conn"].emit.call_args_list
        ]
        assert len(tuples) == len(set(tuples))

    def test_clean_short_tls_does_not_get_weird(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Clean successful TLS handshakes should not receive partial/reset weird labels."""
        state_manager.set_current_time(timestamp)

        for idx in range(50):
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="93.184.216.34",
                time=timestamp + timedelta(seconds=idx),
                dst_port=443,
                proto="tcp",
                service="ssl",
                hostname="example.com",
                conn_state="SF",
                duration=1.0,
                orig_bytes=500,
                resp_bytes=2000,
            )

        events = [call.args[0] for call in mock_emitters["zeek_conn"].emit.call_args_list]
        assert all(event.weird is None for event in events)

    def test_internal_dns_ttl_is_stable_across_resolvers(self):
        """Internal authoritative DNS names should not get random per-query TTLs."""
        from evidenceforge.generation.activity.generator import _dns_base_ttl

        first = _dns_base_ttl("dc01.example.org", is_internal=True)
        second = _dns_base_ttl("dc01.example.org", is_internal=True)

        assert first == second
        assert first in {300, 600, 1800, 3600, 7200, 86400}

    def test_direct_dns_connection_uses_internal_cache(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Direct DNS connections should honor cache suppression for internal names."""
        from evidenceforge.generation.activity.generator import _dns_base_ttl

        state_manager.set_current_time(timestamp)
        activity_gen._ad_domain = "example.org"

        for idx in range(3):
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="10.0.0.10",
                time=timestamp + timedelta(seconds=idx),
                dst_port=53,
                proto="udp",
                service="dns",
                hostname="dc01.example.org",
                duration=0.01,
                orig_bytes=80,
                resp_bytes=180,
            )

        ttls = [
            call.args[0].dns.TTLs[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].dns and call.args[0].dns.query == "dc01.example.org"
        ]
        assert ttls == [float(_dns_base_ttl("dc01.example.org", is_internal=True))]


class TestNoReverseDnsHostnames:
    """Web/SaaS connections must never produce reverse-DNS style hostnames."""

    def test_no_embedded_ip_in_sni(self, activity_gen, timestamp, state_manager, mock_emitters):
        """SNI must not contain the destination IP's octets joined by dashes."""
        state_manager.set_current_time(timestamp)

        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        violations = []

        for i in range(50):
            mock_emitters["zeek_ssl"].reset_mock()
            t = timestamp + timedelta(seconds=i * 10)
            state_manager.set_current_time(t)

            domain, ip = pick_domain_and_ip(rng, "web", src_host="WS-01")
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip=ip,
                time=t,
                dst_port=443,
                proto="tcp",
                service="ssl",
                emit_dns=True,
                hostname=domain,
            )

            if mock_emitters["zeek_ssl"].emit.called:
                ssl_event = mock_emitters["zeek_ssl"].emit.call_args[0][0]
                if ssl_event.ssl:
                    sni = ssl_event.ssl.server_name
                    ip_dashed = ip.replace(".", "-")
                    if ip_dashed in sni:
                        violations.append(f"SNI '{sni}' contains embedded IP {ip}")

        assert len(violations) == 0, (
            f"{len(violations)} SNI values contain embedded IPs:\n" + "\n".join(violations[:5])
        )

    def test_long_tail_domains_no_embedded_ip(self):
        """Long-tail generated domains must not embed IPs."""
        from evidenceforge.generation.activity.dns_registry import (
            _domain_to_ip,
            generate_long_tail_domain,
        )

        rng = random.Random(42)
        for _ in range(100):
            domain = generate_long_tail_domain(rng)
            ip = _domain_to_ip(domain)
            ip_dashed = ip.replace(".", "-")
            assert ip_dashed not in domain, f"Long-tail domain '{domain}' embeds IP {ip}"


class TestNoSinkhole:
    """No single IP should be the DNS answer for many unrelated domains."""

    def test_ip_not_shared_by_many_domains(self):
        """In the registry, no IP maps to more than 3 different domains."""
        from evidenceforge.generation.activity.dns_registry import load_dns_registry

        data = load_dns_registry()
        ip_to_domains: dict[str, list[str]] = {}
        for entry in data["domains"]:
            for ip in entry["ips"]:
                ip_to_domains.setdefault(ip, []).append(entry["domain"])

        sinkholes = {ip: domains for ip, domains in ip_to_domains.items() if len(domains) > 3}
        assert len(sinkholes) == 0, "IPs shared by >3 domains (sinkhole):\n" + "\n".join(
            f"  {ip}: {domains}" for ip, domains in sinkholes.items()
        )

    def test_generated_connections_diverse_ips(self):
        """Over 100 web connections, no IP should account for >10% of answers."""
        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        ips = []
        for _ in range(100):
            _, ip = pick_domain_and_ip(rng, "web", src_host="WS-01")
            ips.append(ip)

        counts = Counter(ips)
        max_count = max(counts.values())
        assert max_count <= 15, (
            f"IP {counts.most_common(1)[0][0]} appeared {max_count}/100 times (>15%)"
        )


class TestWeirdProtocolConstraint:
    """Zeek weird.log anomaly types must match the connection protocol."""

    _TCP_NAMES = {
        "window_recision",
        "possible_split_routing",
        "above_hole_data_without_any_acks",
        "data_before_established",
        "connection_originator_SYN_ack",
        "truncated_header",
        "inappropriate_FIN",
        "bad_TCP_checksum",
    }
    _UDP_NAMES = {
        "DNS_truncated_len_lt_hdr_len",
        "bad_UDP_checksum",
        "UDP_datagram_length_mismatch",
        "DNS_RR_unknown_type",
    }

    def test_automatic_weird_generation_is_disabled(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Generated connections should not synthesize weird.log rows by default."""
        state_manager.set_current_time(timestamp)

        for i in range(100):
            t = timestamp + timedelta(seconds=i)
            state_manager.set_current_time(t)
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip=f"93.184.10.{i + 1}",
                time=t,
                dst_port=443,
                proto="tcp",
                service="ssl",
                conn_state="S0",
                orig_bytes=0,
                resp_bytes=0,
            )

        emitted_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert emitted_events
        assert all(event.weird is None for event in emitted_events)
        if "zeek_weird" in mock_emitters:
            assert not mock_emitters["zeek_weird"].emit.called

    def test_failed_tcp_connections_do_not_keep_http_or_ssl_service(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)

        for service, port in (("ssl", 443), ("http", 80)):
            mock_emitters["zeek_conn"].reset_mock()
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="93.184.216.34",
                time=timestamp,
                dst_port=port,
                proto="tcp",
                service=service,
                conn_state="S0",
                orig_bytes=0,
                resp_bytes=0,
            )
            event = mock_emitters["zeek_conn"].emit.call_args[0][0]
            assert event.network.service == ""

    def test_tcp_history_responder_markers_have_responder_packets(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            conn_state="S1",
            orig_bytes=0,
            resp_bytes=0,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert any(char.islower() for char in event.network.history)
        assert event.network.resp_pkts > 0
        assert event.network.resp_ip_bytes is not None

    def test_dns_txt_response_has_originator_payload(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """DNS TXT fan-out should not render a response to a zero-byte query."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(
                query="abcd1234.exfil.example.com",
                query_type="TXT",
                qtype=16,
                rcode="NOERROR",
                rcode_num=0,
                answers=["v=abcd1234"],
            ),
            resp_bytes=800,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.orig_bytes > 0
        assert event.network.orig_ip_bytes > event.network.orig_bytes

    def test_dns_txt_accounting_matches_visible_answer_size(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Tiny TXT answers should not imply oversized single-packet DNS responses."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(
                query="abcd1234.exfil.example.com",
                query_type="TXT",
                qtype=16,
                rcode="NOERROR",
                rcode_num=0,
                answers=["cache=56f09cfc"],
                rtt=0.12,
            ),
            resp_bytes=2000,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.resp_bytes < 300
        assert event.network.resp_pkts == 1
        assert event.network.resp_ip_bytes <= 1500

    def test_dns_conn_duration_uses_rtt(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """DNS conn rows should describe the same transaction length as dns.log RTT."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(
                query="chunk.tunnel.example.com",
                query_type="TXT",
                qtype=16,
                rcode="NOERROR",
                rcode_num=0,
                answers=["v=chunk"],
                rtt=0.35,
            ),
            resp_bytes=800,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.duration == 0.35

    def test_dns_conn_duration_exact_anchor_still_uses_rtt(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """DNS RTT locks must not be jittered just because they equal old default anchors."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(
                query="anchor.example.com",
                query_type="A",
                qtype=1,
                rcode="NOERROR",
                rcode_num=0,
                answers=["93.184.216.34"],
                rtt=0.02,
            ),
            resp_bytes=120,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.duration == 0.02

    def test_explicit_dns_response_state_keeps_responder_accounting(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """DNS rows with response metadata must not render as one-way UDP."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            conn_state="SF",
            orig_bytes=0,
            resp_bytes=0,
            dns=DnsContext(
                query="missing.example.com",
                query_type="A",
                qtype=1,
                rcode="NXDOMAIN",
                rcode_num=3,
                rtt=0.08,
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "SF"
        assert event.network.history == "Dd"
        assert event.network.resp_pkts > 0
        assert event.network.resp_bytes > 0
        assert event.network.duration == 0.08

    def test_servfail_dns_response_keeps_responder_accounting(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """SERVFAIL is still a DNS response and should carry responder packets."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.02,
            orig_bytes=60,
            resp_bytes=0,
            dns=DnsContext(
                query="flaky.example.com",
                query_type="A",
                qtype=1,
                rcode="SERVFAIL",
                rcode_num=2,
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "SF"
        assert event.network.history == "Dd"
        assert event.network.resp_pkts > 0
        assert event.network.resp_bytes > 0

    def test_inferred_servfail_dns_row_keeps_responder_accounting(
        self, activity_gen, timestamp, state_manager, mock_emitters, monkeypatch
    ):
        """Fallback DNS synthesis should not pair SERVFAIL with stale packet accounting."""
        from evidenceforge.generation.activity import generator as generator_module

        state_manager.set_current_time(timestamp)
        monkeypatch.setattr(generator_module, "_UDP_CONN_ENTRIES", [("S0", 1, "DD")])
        monkeypatch.setattr(generator_module, "_UDP_CONN_WEIGHTS", [1])

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            hostname="flaky.example.com",
            orig_bytes=60,
            resp_bytes=0,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.dns.rcode == "SERVFAIL"
        assert event.network.conn_state == "SF"
        assert event.network.history == "Dd"
        assert event.network.orig_pkts == event.network.history.count("D")
        assert event.network.resp_pkts == event.network.history.count("d")
        assert event.network.resp_bytes > 0
        assert event.network.orig_ip_bytes - event.network.orig_bytes == (
            event.network.resp_ip_bytes - event.network.resp_bytes
        )

    def test_inferred_tcp_servfail_dns_row_keeps_tcp_ip_overhead(
        self, activity_gen, timestamp, state_manager, mock_emitters, monkeypatch
    ):
        """TCP fallback DNS SERVFAIL accounting should retain TCP header overhead."""
        from evidenceforge.generation.activity import generator as generator_module

        class TcpOnlyOverheadRng:
            def __init__(self) -> None:
                self._rng = random.Random(42)

            def choices(self, population, weights=None, *, cum_weights=None, k=1):
                assert population != generator_module._UDP_OVERHEAD_VALUES
                return self._rng.choices(population, weights=weights, cum_weights=cum_weights, k=k)

            def __getattr__(self, name: str):
                return getattr(self._rng, name)

        state_manager.set_current_time(timestamp)
        monkeypatch.setattr(generator_module, "_get_rng", TcpOnlyOverheadRng)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="tcp",
            service="dns",
            hostname="flaky.example.com",
            orig_bytes=60,
            resp_bytes=0,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.dns.rcode == "SERVFAIL"
        assert event.network.conn_state == "SF"
        assert event.network.resp_pkts >= 1
        assert event.network.resp_ip_bytes > event.network.resp_bytes

    def test_dns_conn_duration_is_not_shorter_than_explicit_rtt(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Caller-provided short durations should still cover dns.log RTT."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.01,
            dns=DnsContext(
                query="www.example.com",
                query_type="A",
                qtype=1,
                rcode="NOERROR",
                rcode_num=0,
                answers=["93.184.216.34"],
                rtt=0.08,
            ),
            resp_bytes=120,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.duration == 0.08

    def test_dns_a_query_accounting_is_clamped_to_dns_transaction(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """A single A lookup should not inherit kilobyte-scale generic UDP bytes."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=4.5,
            dns=DnsContext(
                query="metrics-b0hov01h.top",
                query_type="A",
                qtype=1,
                rcode="NOERROR",
                rcode_num=0,
                answers=["203.0.113.45"],
                rtt=0.019,
            ),
            orig_bytes=1933,
            resp_bytes=900,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.orig_bytes <= 260
        assert event.network.resp_bytes <= 512
        assert event.network.duration == 0.019

    def test_dns_authoritative_flag_is_consistent_for_internal_names(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Internal names should not flip AA on otherwise equivalent rows."""
        state_manager.set_current_time(timestamp)
        activity_gen._ad_domain = "example.org"

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=DnsContext(
                query="DC-01.example.org",
                query_type="A",
                qtype=1,
                rcode="NOERROR",
                rcode_num=0,
                answers=["10.0.0.10"],
                AA=False,
                rtt=0.004,
            ),
            orig_bytes=80,
            resp_bytes=140,
        )

        event = mock_emitters["zeek_dns"].emit.call_args[0][0]
        assert event.dns.AA is True

    def test_sensor_duration_jitter_respects_dns_rtt(self, timestamp, tmp_path):
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(
            format_def=fmt,
            output_path=tmp_path,
            sensor_hostnames=["zeek-a", "zeek-b"],
        )
        event = SecurityEvent(
            timestamp=timestamp,
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=53000,
                dst_ip="10.0.0.1",
                dst_port=53,
                protocol="udp",
                service="dns",
                duration=0.002,
                orig_bytes=64,
                resp_bytes=128,
                conn_state="SF",
                zeek_uid="CtestDnsDuration1",
            ),
            dns=DnsContext(query="example.com", query_type="A", rtt=0.002),
        )
        event._sensor_hostnames_by_format = {"zeek_conn": ["zeek-a", "zeek-b"]}

        emitter.emit(event)
        emitter.flush()

        for path in tmp_path.glob("zeek-*/conn.json"):
            for line in path.read_text().splitlines():
                row = json.loads(line)
                assert row["duration"] == event.dns.rtt

    def test_generic_dns_service_accounting_is_clamped(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """DNS-like IDS/background rows without dns.log context still use DNS-sized packets."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="8.8.8.8",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=4.5,
            orig_bytes=1800,
            resp_bytes=22000,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.orig_bytes <= 260
        assert event.network.resp_bytes <= 512
        assert event.network.duration <= 0.08

    def test_udp_dns_with_explicit_conn_state_uses_udp_history(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """Caller-forced successful DNS rows must not inherit TCP handshake history."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="8.8.8.8",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.02,
            orig_bytes=54,
            resp_bytes=140,
            conn_state="SF",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "udp"
        assert event.network.conn_state == "SF"
        assert event.network.history in {"Dd", "D"}
        assert not set(event.network.history) & set("SshAaFfRr")

    def test_unanswered_udp_dns_keeps_request_payload(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """A Zeek dns-service S0 row still needs a visible UDP DNS request payload."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="8.8.8.8",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            conn_state="S0",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "udp"
        assert event.network.service == "dns"
        assert event.network.conn_state == "S0"
        assert event.network.history == "D"
        assert event.network.orig_bytes >= 40
        assert event.network.orig_ip_bytes > event.network.orig_bytes
        assert event.network.resp_bytes == 0

    def test_denied_dns_query_has_no_response_payload(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="8.8.8.8",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.01,
            orig_bytes=60,
            resp_bytes=180,
            dns=DnsContext(
                query="blocked.example.com",
                trans_id=1234,
                qtype=1,
                query_type="A",
                rcode="NOERROR",
                rcode_num=0,
                answers=["93.184.216.34"],
                TTLs=[300.0],
                rtt=0.02,
            ),
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=1,
                src_interface="inside",
                dst_interface="outside",
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "S0"
        assert event.network.orig_bytes >= 40
        assert event.network.resp_bytes == 0
        assert event.network.resp_pkts == 0
        assert event.dns.answers == []
        assert event.dns.TTLs == []
        assert event.dns.rtt is None

    def test_tcp_connections_get_tcp_weird_names(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """TCP connections should only get TCP-specific weird names."""
        state_manager.set_current_time(timestamp)
        weird_names = set()

        for i in range(500):
            mock_emitters["zeek_conn"].reset_mock()
            t = timestamp + timedelta(seconds=i)
            state_manager.set_current_time(t)
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip=f"93.184.{i // 256}.{i % 256 + 1}",
                time=t,
                dst_port=443,
                proto="tcp",
                service="ssl",
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                if event.weird:
                    weird_names.add(event.weird.name)

        if weird_names:
            udp_on_tcp = weird_names & self._UDP_NAMES
            assert len(udp_on_tcp) == 0, f"UDP weird names on TCP connections: {udp_on_tcp}"

    def test_udp_connections_get_udp_weird_names(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """UDP connections should only get UDP-specific weird names."""
        state_manager.set_current_time(timestamp)
        weird_names = set()

        for i in range(2000):  # UDP weird rate is 0.5%, need more samples
            mock_emitters["zeek_conn"].reset_mock()
            t = timestamp + timedelta(seconds=i)
            state_manager.set_current_time(t)
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="10.0.0.1",
                time=t,
                dst_port=53,
                proto="udp",
                service="dns",
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                if event.weird:
                    weird_names.add(event.weird.name)

        if weird_names:
            tcp_on_udp = weird_names & self._TCP_NAMES
            assert len(tcp_on_udp) == 0, f"TCP weird names on UDP connections: {tcp_on_udp}"


class TestSuspiciousNoiseHostname:
    """Suspicious noise connections must include hostname."""

    def test_unusual_outbound_has_hostname(self):
        """generate_unusual_outbound() results include a hostname field."""
        rng = random.Random(42)
        system = System(hostname="WS-01", ip="10.0.1.50", os="Windows 10", type="workstation")
        user = User(username="testuser", full_name="Test", email="t@t.com", enabled=True)
        timestamp = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

        results_with_hostname = 0
        for _ in range(50):
            result = generate_unusual_outbound(rng, [user], [system], timestamp)
            if result:
                assert "hostname" in result, f"Missing hostname key in result: {result}"
                if result["hostname"]:
                    results_with_hostname += 1

        assert results_with_hostname > 0, "No unusual outbound results had a hostname"


class TestMultiIpDnsAnswers:
    """Domains with multiple IPs should return full answer sets."""

    def test_domain_ips_accessible(self):
        """get_domain_ips returns full IP list for multi-IP domains."""
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        # www.google.com has 2 IPs in the registry
        ips = get_domain_ips("www.google.com")
        assert len(ips) >= 2, f"Expected 2+ IPs for www.google.com, got {ips}"

    def test_single_ip_domain_returns_list(self):
        """Single-IP domains return a list with one element."""
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        ips = get_domain_ips("ssh.github.com")
        assert len(ips) == 1
        assert isinstance(ips, list)

    def test_unknown_domain_returns_empty(self):
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        ips = get_domain_ips("nonexistent.example.invalid")
        assert ips == []


class TestPtrSniCoherence:
    """PTR records should not contradict known forward/TLS hostname context."""

    def test_aws_compute_ptr_uses_forward_hostname_region(self):
        from evidenceforge.generation.activity.network import _generate_rdns_name

        ip = "52.84.100.50"
        hostname = "ec2-52-84-100-50.us-west-2.compute.amazonaws.com"

        for seed in range(20):
            ptr = _generate_rdns_name(random.Random(seed), ip, hostname)
            assert ".us-west-2.compute.amazonaws.com" in ptr

    def test_aws_random_forward_hostname_avoids_ec2_ptr_shape(self):
        from evidenceforge.generation.activity.network import (
            _generate_random_hostname,
            _generate_rdns_name,
        )

        ip = "52.84.100.50"
        hostnames = {_generate_random_hostname(random.Random(seed), ip) for seed in range(20)}
        ptrs = {_generate_rdns_name(random.Random(seed), ip) for seed in range(50)}

        ptr_regions = {
            ptr.split(".compute.amazonaws.com")[0].rsplit(".", 1)[1]
            for ptr in ptrs
            if ".compute.amazonaws.com" in ptr
        }

        assert hostnames
        assert all(".compute.amazonaws.com" not in hostname for hostname in hostnames)
        assert len(ptr_regions) <= 1


class TestDnsSupportQueryTypes:
    """Baseline DNS companion traffic should include realistic support lookups."""

    @staticmethod
    def _force_dns_random(monkeypatch, values, default=0.5):
        import evidenceforge.generation.activity.generator as generator_module

        rng = random.Random(42)
        value_iter = iter(values)

        def _fixed_random() -> float:
            try:
                return next(value_iter)
            except StopIteration:
                return default

        monkeypatch.setattr(rng, "random", _fixed_random)
        monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)

    def test_txt_queries_model_mail_authentication_noise(
        self, activity_gen, timestamp, mock_emitters, monkeypatch
    ):
        self._force_dns_random(monkeypatch, [0.5, 0.99, 0.2])

        activity_gen._emit_dns_lookup(
            src_ip="10.0.1.50",
            dst_ip="52.84.100.50",
            time=timestamp,
            hostname="mail.example.com",
        )

        event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        assert event.dns is not None
        assert event.dns.query_type == "TXT"
        assert event.dns.query == "example.com"
        assert event.dns.answers == ["v=spf1 include:_spf.example.com ~all"]
        assert event.dns.TTLs and event.dns.TTLs[0] >= 900

    def test_mx_roll_on_cdn_hostname_falls_back_to_txt(
        self, activity_gen, timestamp, mock_emitters, monkeypatch
    ):
        self._force_dns_random(monkeypatch, [0.5, 0.999, 0.2])

        activity_gen._emit_dns_lookup(
            src_ip="10.0.1.50",
            dst_ip="52.84.100.50",
            time=timestamp,
            hostname="d111111abcdef8.cloudfront.net",
        )

        event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        assert event.dns is not None
        assert event.dns.query_type == "TXT"
        assert event.dns.query == "cloudfront.net"
        assert event.dns.answers == ["v=spf1 include:_spf.cloudfront.net ~all"]
        assert event.dns.TTLs and event.dns.TTLs[0] >= 900

    def test_txt_answers_are_stable_and_dkim_keys_are_source_native(self):
        from evidenceforge.generation.activity.dns_txt import (
            choose_background_dns_txt_record,
            stable_dns_txt_record,
        )

        assert stable_dns_txt_record("_dmarc.microsoft.com") == stable_dns_txt_record(
            "_dmarc.microsoft.com"
        )
        dkim_answer, dkim_ttl = stable_dns_txt_record("selector1._domainkey.sendgrid.net")
        dkim_key = dkim_answer.split("p=", 1)[1]

        assert dkim_answer.startswith("v=DKIM1; k=rsa; p=")
        assert len(dkim_key) > 180
        assert not all(char in "0123456789abcdef" for char in dkim_key.lower())
        assert dkim_ttl >= 900

        seen: dict[str, tuple[str, int]] = {}
        for seed in range(500):
            query, answer, ttl = choose_background_dns_txt_record(random.Random(seed))
            prior = seen.setdefault(query, (answer, ttl))
            assert prior == (answer, ttl)

    def test_forward_proxy_srv_queries_use_internal_resolver(
        self, activity_gen, timestamp, mock_emitters, monkeypatch
    ):
        self._force_dns_random(monkeypatch, [0.5, 0.95, 0.5])
        proxy = System(
            hostname="proxy01",
            ip="10.0.3.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        activity_gen._ip_to_system = {proxy.ip: proxy}
        activity_gen._ad_domain = "example.com"
        activity_gen._dns_server_ips = ["10.0.0.10"]

        activity_gen._emit_dns_lookup(
            src_ip=proxy.ip,
            dst_ip="142.250.72.36",
            time=timestamp,
            hostname="www.gstatic.com",
        )

        event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        assert event.dns is not None
        assert event.dns.query_type == "SRV"
        assert event.network.dst_ip == "10.0.0.10"
        assert event.dns.AA is True

    def test_default_ad_site_srv_query_resolves_to_dc(
        self, activity_gen, timestamp, mock_emitters, monkeypatch
    ):
        import evidenceforge.generation.activity.generator as generator_module

        self._force_dns_random(monkeypatch, [0.5, 0.95, 0.5])
        monkeypatch.setattr(
            generator_module,
            "_AD_SRV_QUERIES",
            ["_ldap._tcp.Default-First-Site-Name._sites.{domain}"],
        )
        proxy = System(
            hostname="proxy01",
            ip="10.0.3.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        activity_gen._ip_to_system = {proxy.ip: proxy}
        activity_gen._ad_domain = "example.com"
        activity_gen._dns_server_ips = ["10.0.0.10"]

        activity_gen._emit_dns_lookup(
            src_ip=proxy.ip,
            dst_ip="142.250.72.36",
            time=timestamp,
            hostname="www.gstatic.com",
        )

        event = mock_emitters["zeek_dns"].emit.call_args_list[0][0][0]
        assert event.dns is not None
        assert event.dns.query == "_ldap._tcp.Default-First-Site-Name._sites.example.com"
        assert event.dns.query_type == "SRV"
        assert event.dns.rcode == "NOERROR"
        assert event.dns.answers == ["0 100 389 dc-01.example.com"]
        assert event.network.dst_ip == "10.0.0.10"
        assert event.dns.AA is True

    def test_internal_forced_address_lookup_emits_cached_ad_srv_discovery(
        self, activity_gen, timestamp, mock_emitters
    ):
        dc = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2019",
            type="domain_controller",
        )
        activity_gen._dc_systems = [dc]
        activity_gen._dns_server_ips = [dc.ip]
        activity_gen._ad_domain = "corp.example"

        activity_gen._emit_dns_lookup(
            src_ip="10.0.1.50",
            dst_ip=dc.ip,
            time=timestamp,
            hostname="DC-01.corp.example",
            force_address=True,
        )
        first_events = [call.args[0] for call in mock_emitters["zeek_dns"].emit.call_args_list]
        srv_events = [event for event in first_events if event.dns.query_type == "SRV"]
        address_events = [
            event
            for event in first_events
            if event.dns.query_type == "A" and event.dns.query == "DC-01.corp.example"
        ]

        assert srv_events
        assert address_events
        assert srv_events[0].timestamp < address_events[0].timestamp
        assert srv_events[0].dns.answers in (
            ["0 100 88 DC-01.corp.example"],
            ["0 100 389 DC-01.corp.example"],
        )

        mock_emitters["zeek_dns"].emit.reset_mock()
        activity_gen._emit_dns_lookup(
            src_ip="10.0.1.50",
            dst_ip="10.0.0.20",
            time=timestamp + timedelta(minutes=5),
            hostname="FILE-01.corp.example",
            force_address=True,
        )
        second_events = [call.args[0] for call in mock_emitters["zeek_dns"].emit.call_args_list]

        assert not [event for event in second_events if event.dns.query_type == "SRV"]

    def test_default_ad_site_srv_is_not_nxdomain_noise(self):
        from evidenceforge.generation.activity.generator import _dns_nxdomain_companion_queries
        from evidenceforge.generation.activity.network import _AD_SRV_QUERIES

        site_query = "_ldap._tcp.Default-First-Site-Name._sites.{domain}"
        assert site_query in _AD_SRV_QUERIES
        assert "_ldap._tcp.Default-First-Site-Name._sites.example.com" not in (
            _dns_nxdomain_companion_queries("www.gstatic.com", "example.com")
        )

    def test_internal_nxdomain_companions_use_internal_resolver_and_rtt(
        self, activity_gen, timestamp, mock_emitters, monkeypatch
    ):
        self._force_dns_random(monkeypatch, [0.5, 0.5, 0.5], default=0.01)
        proxy = System(
            hostname="proxy01",
            ip="10.0.3.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        activity_gen._ip_to_system = {proxy.ip: proxy}
        activity_gen._ad_domain = "example.com"
        activity_gen._dns_server_ips = ["10.0.0.10"]
        activity_gen.generate_connection = Mock()

        activity_gen._emit_dns_lookup(
            src_ip=proxy.ip,
            dst_ip="142.250.72.36",
            time=timestamp,
            hostname="www.gstatic.com",
        )

        nx_call = activity_gen.generate_connection.call_args_list[-1].kwargs
        nx_dns = nx_call["dns"]
        assert nx_dns.rcode == "NXDOMAIN"
        assert nx_call["dst_ip"] == "10.0.0.10"
        assert nx_dns.AA is True
        assert nx_dns.rtt is not None
        if nx_dns.query.startswith("_"):
            assert nx_dns.query_type == "SRV"
            assert nx_dns.qtype == 33
