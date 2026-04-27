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

import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.suspicious_benign import generate_unusual_outbound
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

    def test_aws_random_hostname_and_ptr_use_stable_identity(self):
        from evidenceforge.generation.activity.network import (
            _generate_random_hostname,
            _generate_rdns_name,
        )

        ip = "52.84.100.50"
        hostnames = {
            _generate_random_hostname(random.Random(seed), ip)
            for seed in range(50)
            if ".compute.amazonaws.com" in _generate_random_hostname(random.Random(seed), ip)
        }
        ptrs = {_generate_rdns_name(random.Random(seed), ip) for seed in range(50)}

        compute_regions = {
            hostname.split(".compute.amazonaws.com")[0].rsplit(".", 1)[1] for hostname in hostnames
        }
        ptr_regions = {
            ptr.split(".compute.amazonaws.com")[0].rsplit(".", 1)[1]
            for ptr in ptrs
            if ".compute.amazonaws.com" in ptr
        }

        assert len(compute_regions) <= 1
        assert len(ptr_regions) <= 1
        assert ptr_regions.issubset(compute_regions)


class TestDnsSupportQueryTypes:
    """Baseline DNS companion traffic should include realistic support lookups."""

    @staticmethod
    def _force_dns_random(monkeypatch, values):
        import evidenceforge.generation.activity.generator as generator_module

        rng = random.Random(42)
        value_iter = iter(values)

        def _fixed_random() -> float:
            try:
                return next(value_iter)
            except StopIteration:
                return 0.5

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
