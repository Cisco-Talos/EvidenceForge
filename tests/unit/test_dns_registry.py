# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the unified DNS registry (dns_registry.yaml + dns_registry.py)."""

import random

from evidenceforge.generation.activity.dns_registry import (
    _domain_to_ip,
    generate_long_tail_domain,
    get_cdn_ranges,
    get_domains_by_tag,
    get_forward_dns,
    get_reverse_dns,
    load_dns_registry,
    pick_domain_and_ip,
    resolve_domain_ip,
)


class TestRegistryLoading:
    """Tests for YAML loading and structure validation."""

    def test_dns_registry_loads(self):
        """YAML loads without errors and has required sections."""
        data = load_dns_registry()
        assert "domains" in data
        assert "long_tail" in data
        assert "cdn_ranges" in data
        assert "ipv6_map" in data

    def test_all_entries_have_required_fields(self):
        """Every domain entry has domain, ips, and tags."""
        data = load_dns_registry()
        for entry in data["domains"]:
            assert "domain" in entry, f"Missing domain in entry: {entry}"
            assert "ips" in entry, f"Missing ips in entry for {entry.get('domain')}"
            assert "tags" in entry, f"Missing tags in entry for {entry.get('domain')}"
            assert len(entry["ips"]) >= 1, f"Empty ips for {entry['domain']}"
            assert len(entry["tags"]) >= 1, f"Empty tags for {entry['domain']}"


class TestReverseDNS:
    """Tests for IP → domain mapping."""

    def test_reverse_dns_covers_all_ips(self):
        """Every IP in every entry appears in REVERSE_DNS."""
        data = load_dns_registry()
        rdns = get_reverse_dns()
        for entry in data["domains"]:
            for ip in entry["ips"]:
                assert ip in rdns, f"IP {ip} from {entry['domain']} not in REVERSE_DNS"

    def test_no_ip_maps_to_multiple_domains(self):
        """Each IP maps to exactly one domain in REVERSE_DNS (first wins)."""
        rdns = get_reverse_dns()
        # Just verify it's a clean dict — no structural issue
        assert len(rdns) > 0
        for ip, domain in rdns.items():
            assert isinstance(ip, str)
            assert isinstance(domain, str)


class TestForwardDNS:
    """Tests for domain → IP list mapping."""

    def test_forward_dns_covers_all_domains(self):
        """Every domain has a FORWARD_DNS entry."""
        data = load_dns_registry()
        fdns = get_forward_dns()
        for entry in data["domains"]:
            assert entry["domain"] in fdns, f"Domain {entry['domain']} not in FORWARD_DNS"

    def test_forward_dns_returns_ip_lists(self):
        """FORWARD_DNS values are lists of IPs."""
        fdns = get_forward_dns()
        for domain, ips in fdns.items():
            assert isinstance(ips, list), f"{domain}: expected list, got {type(ips)}"
            assert len(ips) >= 1, f"{domain}: empty IP list"


class TestTagQueries:
    """Tests for tag-based domain lookups."""

    def test_web_tag_returns_entries(self):
        entries = get_domains_by_tag("web")
        assert len(entries) >= 5, f"Expected 5+ web entries, got {len(entries)}"

    def test_email_tag_returns_entries(self):
        entries = get_domains_by_tag("email")
        assert len(entries) >= 3

    def test_background_windows_tag_returns_entries(self):
        entries = get_domains_by_tag("background", "windows")
        assert len(entries) >= 3

    def test_background_linux_tag_returns_entries(self):
        entries = get_domains_by_tag("background", "linux")
        assert len(entries) >= 2

    def test_office_app_tags_return_specific_entries(self):
        assert {entry["domain"] for entry in get_domains_by_tag("outlook")} >= {
            "outlook.office365.com",
            "outlook.office.com",
        }
        assert {entry["domain"] for entry in get_domains_by_tag("teams")} >= {
            "teams.microsoft.com",
            "login.microsoftonline.com",
        }
        assert {entry["domain"] for entry in get_domains_by_tag("onedrive")} >= {
            "sharepoint.com",
            "onedrive.live.com",
        }

    def test_multi_tag_filters_correctly(self):
        """Entries returned by multi-tag query have ALL specified tags."""
        entries = get_domains_by_tag("background", "windows")
        for entry in entries:
            assert "background" in entry["tags"]
            assert "windows" in entry["tags"]


class TestPickDomainAndIp:
    """Tests for domain-first connection selection."""

    def test_returns_valid_pair(self):
        rng = random.Random(42)
        domain, ip = pick_domain_and_ip(rng, "web", src_host="WS-01")
        assert isinstance(domain, str)
        assert isinstance(ip, str)
        assert "." in domain  # Looks like a domain
        assert "." in ip  # Looks like an IP

    def test_ip_is_from_domain_pool(self):
        """Returned IP belongs to the domain's IP pool."""
        rng = random.Random(42)
        fdns = get_forward_dns()
        for _ in range(20):
            domain, ip = pick_domain_and_ip(rng, "web", src_host="WS-01")
            if domain in fdns:
                assert ip in fdns[domain], f"{ip} not in {domain}'s pool: {fdns[domain]}"

    def test_deterministic_for_same_host(self):
        """Same host + same domain → same IP (DNS cache simulation)."""
        rng1 = random.Random(42)
        rng2 = random.Random(42)
        d1, ip1 = pick_domain_and_ip(rng1, "web", src_host="WS-01")
        d2, ip2 = pick_domain_and_ip(rng2, "web", src_host="WS-01")
        assert d1 == d2
        assert ip1 == ip2

    def test_fallback_to_long_tail(self):
        """Unknown tag falls back to long-tail domain generation."""
        rng = random.Random(42)
        domain, ip = pick_domain_and_ip(rng, "nonexistent_tag", src_host="WS-01")
        assert isinstance(domain, str)
        assert "." in domain


class TestResolveDomainIp:
    """Tests for deterministic direct domain resolution."""

    def test_registered_domain_uses_configured_pool(self):
        fdns = get_forward_dns()
        ip = resolve_domain_ip("outlook.office365.com", src_host="WS-01")
        assert ip in fdns["outlook.office365.com"]

    def test_unregistered_domain_uses_external_hash_mapping(self):
        ip = resolve_domain_ip("static.hotjar.com", src_host="WS-01")
        assert ip == _domain_to_ip("static.hotjar.com")
        assert not ip.startswith("10.")


class TestLongTailDomains:
    """Tests for random domain generation."""

    def test_generates_valid_domains(self):
        rng = random.Random(42)
        for _ in range(20):
            domain = generate_long_tail_domain(rng)
            parts = domain.split(".")
            assert len(parts) == 3, f"Expected 3 parts: {domain}"

    def test_not_in_registry(self):
        """Long-tail domains don't collide with registry domains."""
        fdns = get_forward_dns()
        rng = random.Random(42)
        for _ in range(100):
            domain = generate_long_tail_domain(rng)
            assert domain not in fdns, f"Long-tail domain {domain} collides with registry"


class TestDomainToIp:
    """Tests for hash-based IP derivation."""

    def test_deterministic(self):
        assert _domain_to_ip("example.com") == _domain_to_ip("example.com")

    def test_different_domains_different_ips(self):
        ip1 = _domain_to_ip("cdn.acmehealth.com")
        ip2 = _domain_to_ip("static.medflow.io")
        assert ip1 != ip2

    def test_ip_in_cdn_range(self):
        ranges = get_cdn_ranges()
        ip = _domain_to_ip("test.example.com")
        first, second = ip.split(".")[:2]
        valid_prefixes = [(r[0], r[1]) for r in ranges]
        assert (int(first), int(second)) in valid_prefixes, f"{ip} not in CDN ranges"


class TestBackwardCompatibility:
    """Tests that legacy imports from network.py still work."""

    def test_reverse_dns_importable(self):
        from evidenceforge.generation.activity.network import REVERSE_DNS

        assert isinstance(REVERSE_DNS, dict)
        assert len(REVERSE_DNS) > 50

    def test_forward_dns_importable(self):
        from evidenceforge.generation.activity.network import FORWARD_DNS

        assert isinstance(FORWARD_DNS, dict)
        assert len(FORWARD_DNS) > 30

    def test_external_ips_importable(self):
        from evidenceforge.generation.activity.network import EXTERNAL_IPS

        assert isinstance(EXTERNAL_IPS, dict)
        assert "connection_web" in EXTERNAL_IPS
        assert "connection_email" in EXTERNAL_IPS
        assert "connection_git" in EXTERNAL_IPS
        assert "connection_saas" in EXTERNAL_IPS

    def test_cdn_ranges_importable(self):
        from evidenceforge.generation.activity.network import _CDN_RANGES

        assert isinstance(_CDN_RANGES, list)
        assert len(_CDN_RANGES) >= 5
