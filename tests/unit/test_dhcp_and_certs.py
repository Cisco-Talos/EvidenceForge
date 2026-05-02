# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 3 (DHCP jitter) and Theme 4 (certificate realism)."""

import random
from datetime import UTC, datetime

import yaml

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext, X509Context
from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    _dns_rtt,
    _ntp_stratum_and_ref_id,
    _ocsp_status_for_certificate,
    _tls_san_dns_names,
)
from evidenceforge.generation.activity.tls_issuers import (
    load_tls_issuers,
    pick_issuer,
    pick_key_type,
)
from evidenceforge.generation.activity.tls_realism import (
    certificate_chain_config,
    multi_label_public_suffixes,
    ocsp_config,
    pick_ocsp_responder,
    pick_tls_destination,
    reset_tls_realism_cache,
    tls_destination_config,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System

# ---------------------------------------------------------------------------
# Theme 4: Certificate realism tests
# ---------------------------------------------------------------------------


class TestTlsIssuers:
    """Tests for TLS issuer configuration and selection."""

    def test_windowsupdate_uses_microsoft_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "download.windowsupdate.com")
        assert "Microsoft" in issuer["name"]

    def test_office_cdn_uses_digicert_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "res.cdn.office.net")
        assert "DigiCert" in issuer["name"]

    def test_aws_uses_amazon_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "aws.amazon.com")
        assert "Amazon" in issuer["name"]

    def test_awsstatic_uses_amazon_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "a.b.cdn.console.awsstatic.com")
        assert "Amazon" in issuer["name"]

    def test_apple_uses_apple_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "www.apple.com")
        assert "Apple" in issuer["name"]

    def test_icloud_uses_apple_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "www.icloud.com")
        assert "Apple" in issuer["name"]

    def test_google_pki_uses_google_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "ocsp.pki.goog")
        assert "Google Trust Services" in issuer["name"]

    def test_github_assets_use_digicert_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "github.githubassets.com")
        assert "DigiCert" in issuer["name"]

    def test_linkedin_uses_digicert_ev(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "www.linkedin.com")
        assert "DigiCert SHA2 Extended Validation" in issuer["name"]

    def test_internal_test_domain_uses_enterprise_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "WKS-02.acme.test")
        assert "Enterprise Issuing CA" in issuer["name"]

    def test_validity_range_produces_varied_periods(self):
        """100 certificates should span more than 2 distinct validity values."""
        rng = random.Random(42)
        validity_days = set()
        for _ in range(100):
            issuer = pick_issuer(rng, "")
            _vd_fallback = issuer.get("validity_days", 397)
            _vd_min = issuer.get("validity_days_min", _vd_fallback)
            _vd_max = issuer.get("validity_days_max", _vd_fallback)
            validity_days.add(rng.randint(_vd_min, _vd_max))
        assert len(validity_days) > 5, (
            f"Only {len(validity_days)} distinct values: {sorted(validity_days)}"
        )

    def test_backward_compat_scalar_validity_days(self):
        """An issuer with only validity_days (old format) should still work."""
        rng = random.Random(42)
        old_format = {"name": "Test CA", "weight": 10, "validity_days": 365}
        _vd_fallback = old_format.get("validity_days", 397)
        _vd_min = old_format.get("validity_days_min", _vd_fallback)
        _vd_max = old_format.get("validity_days_max", _vd_fallback)
        assert rng.randint(_vd_min, _vd_max) == 365

    def test_all_issuers_have_validity_range(self):
        """Every issuer in tls_issuers.yaml should have validity_days_min/max."""
        data = load_tls_issuers()
        for issuer in data["issuers"]:
            assert "validity_days_min" in issuer, f"{issuer['name']} missing validity_days_min"
            assert "validity_days_max" in issuer, f"{issuer['name']} missing validity_days_max"
            assert issuer["validity_days_min"] <= issuer["validity_days_max"]

    def test_domain_overrides_reference_existing_issuers(self):
        """Every CA name in domain_ca_overrides should exist in the issuers list."""
        data = load_tls_issuers()
        issuer_names = {i["name"] for i in data["issuers"]}
        for pattern, ca_name in data.get("domain_ca_overrides", {}).items():
            assert ca_name in issuer_names, (
                f"Override '{pattern}' references '{ca_name}' which is not in issuers list"
            )

    def test_lets_encrypt_r3_is_rsa_intermediate(self):
        """Let's Encrypt R3 should not emit ECDSA certificate metadata."""
        data = load_tls_issuers()
        issuer = next(i for i in data["issuers"] if i["name"] == "CN=R3, O=Let's Encrypt, C=US")
        observed = {pick_key_type(random.Random(seed), issuer) for seed in range(20)}
        assert observed == {("rsa", 2048)}

    def test_rsa_named_issuers_only_emit_rsa_certificate_metadata(self):
        """RSA-branded issuers should not produce ECDSA x509 key/signature pairs."""
        data = load_tls_issuers()
        rsa_named_issuers = [
            issuer for issuer in data["issuers"] if " rsa " in f" {issuer['name'].lower()} "
        ]

        assert rsa_named_issuers
        for issuer in rsa_named_issuers:
            observed = {pick_key_type(random.Random(seed), issuer)[0] for seed in range(20)}
            assert observed == {"rsa"}, issuer["name"]

    def test_san_dns_never_wildcards_public_suffix(self):
        """Generated SAN lists should not contain impossible public-suffix wildcards."""
        assert _tls_san_dns_names("stackoverflow.com") == [
            "stackoverflow.com",
            "*.stackoverflow.com",
        ]
        assert _tls_san_dns_names("gcr.io") == ["gcr.io", "*.gcr.io"]
        assert _tls_san_dns_names("www.gstatic.com") == ["www.gstatic.com", "*.gstatic.com"]
        assert _tls_san_dns_names("example.co.uk") == ["example.co.uk", "*.example.co.uk"]
        assert _tls_san_dns_names("203.0.113.45") == []

    def test_ocsp_status_is_stable_by_certificate_but_not_globally_flat(self):
        """OCSP status should be stable per cert while still varying across certs."""
        assert _ocsp_status_for_certificate(
            "www.example.com", "01"
        ) == _ocsp_status_for_certificate("www.example.com", "01")
        statuses = {
            _ocsp_status_for_certificate(f"host{i}.example.com", f"{i:02X}") for i in range(1000)
        }
        assert "good" in statuses
        assert statuses & {"unknown", "revoked"}

    def test_ocsp_does_not_mark_mainstream_domains_revoked(self):
        """Ordinary mainstream browsing certificates should not produce revoked OCSP."""
        domains = ["zoom.us", "www.bing.com", "slack.com", "a0.awsstatic.com", "www.google.com"]
        for domain in domains:
            statuses = {_ocsp_status_for_certificate(domain, f"{i:02X}") for i in range(200)}
            assert "revoked" not in statuses

    def test_ocsp_responder_selection_is_issuer_aware(self):
        """OCSP responders should come from issuer-specific config."""
        assert pick_ocsp_responder("CN=R3, O=Let's Encrypt, C=US", random.Random(1)) in {
            "r3.o.lencr.org",
            "ocsp.int-x3.letsencrypt.org",
        }
        assert (
            pick_ocsp_responder(
                "CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1, O=GlobalSign nv-sa, C=BE",
                random.Random(1),
            )
            == "ocsp.globalsign.com"
        )
        assert (
            pick_ocsp_responder(
                "CN=Acme Enterprise Issuing CA, O=Acme Corp, C=US",
                random.Random(1),
            )
            == "ocsp.example.com"
        )

    def test_tls_realism_overlay_extends_lists_and_replaces_scalars(self, tmp_path, monkeypatch):
        """TLS realism config should support project-local overlays."""
        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "tls_realism.yaml").write_text(
            yaml.safe_dump(
                {
                    "san": {"multi_label_public_suffixes": ["example.test"]},
                    "ocsp": {
                        "cache_bucket_seconds": 7200,
                        "responders": [
                            {
                                "issuer_patterns": ["*Custom*"],
                                "domains": ["ocsp.custom.example.test"],
                            }
                        ],
                    },
                    "certificate_chains": {
                        "templates": [
                            {
                                "name": "custom",
                                "issuer_patterns": ["*Custom*"],
                                "intermediates": ["CN=Custom Root, O=Example, C=US"],
                            }
                        ]
                    },
                    "destinations": {
                        "host_preferred_probability": 0.25,
                        "profiles": [
                            {
                                "name": "custom_tls",
                                "weight": 10,
                                "domains": ["updates.example.test"],
                            }
                        ],
                    },
                },
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_tls_realism_cache()

        try:
            assert "example.test" in multi_label_public_suffixes()
            assert ocsp_config()["cache_bucket_seconds"] == 7200
            assert (
                pick_ocsp_responder("CN=Custom TLS CA", random.Random(1))
                == "ocsp.custom.example.test"
            )
            assert any(
                template.get("name") == "custom"
                for template in certificate_chain_config()["templates"]
            )
            assert tls_destination_config()["host_preferred_probability"] == 0.25
            assert any(
                profile.get("name") == "custom_tls"
                for profile in tls_destination_config()["profiles"]
            )
        finally:
            reset_tls_realism_cache()

    def test_tls_destination_profiles_expand_domain_diversity(self):
        """TLS destination profiles should provide a broad SNI/certificate pool."""
        profiles = tls_destination_config()["profiles"]
        domains = {
            domain
            for profile in profiles
            for domain in profile.get("domains", [])
            if isinstance(domain, str)
        }

        assert len(profiles) >= 5
        assert len(domains) >= 50
        assert {"login.microsoftonline.com", "github.com", "security.ubuntu.com"} <= domains

    def test_tls_destination_picker_is_host_stable_but_not_globally_flat(self):
        """Different hosts should draw from overlapping but distinct TLS preferences."""
        host_a = [
            pick_tls_destination(random.Random(seed), src_host="WKS-01", source_os="windows")[0]
            for seed in range(80)
        ]
        host_b = [
            pick_tls_destination(random.Random(seed), src_host="WKS-02", source_os="windows")[0]
            for seed in range(80)
        ]

        assert len(set(host_a)) >= 12
        assert len(set(host_b)) >= 12
        assert set(host_a) != set(host_b)

    def test_tls_destination_os_overrides_replace_generic_package_domains(self):
        """OS-specific package profiles should not mix Windows and Linux update domains."""
        windows_domains = {
            pick_tls_destination(
                random.Random(seed),
                src_host="WKS-01",
                source_os="windows",
                system_type="workstation",
                purpose_tags=("background",),
            )[0]
            for seed in range(400)
        }
        linux_domains = {
            pick_tls_destination(
                random.Random(seed),
                src_host="LINUX-01",
                source_os="linux",
                system_type="server",
                purpose_tags=("background",),
            )[0]
            for seed in range(400)
        }

        assert not {domain for domain in windows_domains if "ubuntu.com" in domain}
        assert "download.windowsupdate.com" not in linux_domains

    def test_tls_destination_servers_avoid_human_saas_profiles(self):
        """Server-origin TLS background should not pick browser/SaaS-heavy destinations."""
        server_domains = {
            pick_tls_destination(
                random.Random(seed),
                src_host="web01",
                source_os="linux",
                system_type="server",
            )[0]
            for seed in range(600)
        }

        human_saas = {
            "teams.microsoft.com",
            "slack.com",
            "portal.azure.com",
            "console.aws.amazon.com",
        }
        assert not server_domains & human_saas

    def test_private_ntp_servers_do_not_claim_primary_stratum(self):
        """Internal NTP servers should look like upstream-synchronized infrastructure."""
        stratum, ref_id = _ntp_stratum_and_ref_id("10.30.10.10")

        assert stratum in {2, 3, 4}
        assert ref_id.count(".") == 3
        assert ref_id not in {".GPS.", ".PPS.", ".GOES.", ".ACTS.", ".DCFa."}

    def test_public_ntp_servers_are_loaded_from_network_params_overlay(self, tmp_path, monkeypatch):
        """Public NTP defaults should be project-overlay configurable."""
        from evidenceforge.generation.activity.network_params import reset_network_params_cache

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {
                    "public_ntp_servers": [
                        {
                            "name": "time.example.net",
                            "ip": "198.51.100.123",
                            "operator": "Example",
                            "stratum": 2,
                            "ref_id": ".GPS.",
                            "weight": 1,
                        }
                    ]
                },
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert _ntp_stratum_and_ref_id("198.51.100.123") == (2, ".GPS.")
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_rtt_is_loaded_from_network_params_overlay(self, tmp_path, monkeypatch):
        """DNS tunnel timing should be project-overlay configurable."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_rtt_range,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {"dns_tunnel_rtt": {"min_seconds": 0.2, "max_seconds": 0.9}},
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert dns_tunnel_rtt_range() == (0.2, 0.9)
        finally:
            reset_network_params_cache()

    def test_internal_tls_certificates_use_enterprise_identity(self):
        """Private-IP TLS certificates should use internal DNS names and enterprise CA."""
        generator = ActivityGenerator(StateManager(), {})
        generator._ad_domain = "example.com"
        web_system = System(
            hostname="web01",
            ip="10.30.20.10",
            os="Ubuntu 24.04",
            type="server",
        )
        generator._ip_to_system[web_system.ip] = web_system
        event = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.101",
                src_port=50123,
                dst_ip=web_system.ip,
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestInternalTls1",
            ),
        )

        generator._attach_ssl_context(
            event,
            hostname=None,
            dns=None,
            dst_ip=web_system.ip,
            rng=random.Random(42),
            allow_failure=False,
        )

        assert event.x509 is not None
        assert event.x509.certificate_subject == "CN=web01.example.com"
        assert event.x509.certificate_issuer == "CN=Example Enterprise Issuing CA, O=Example, C=US"
        assert event.x509.san_dns == ["web01.example.com", "web01"]

    def test_internal_tls_explicit_sni_controls_enterprise_sans(self):
        """Explicit internal SNI should not get overwritten by dst host canonical name."""
        generator = ActivityGenerator(StateManager(), {})
        generator._ad_domain = "example.com"
        dc_system = System(
            hostname="dc01",
            ip="10.30.10.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        generator._ip_to_system[dc_system.ip] = dc_system
        event = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.101",
                src_port=50123,
                dst_ip=dc_system.ip,
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestInternalTls2",
            ),
        )

        generator._attach_ssl_context(
            event,
            hostname="srv-05.example.com",
            dns=None,
            dst_ip=dc_system.ip,
            rng=random.Random(42),
            allow_failure=False,
        )

        assert event.ssl is not None
        assert event.ssl.server_name == "srv-05.example.com"
        assert event.x509 is not None
        assert event.x509.certificate_subject == "CN=srv-05.example.com"
        assert event.x509.certificate_issuer == "CN=Example Enterprise Issuing CA, O=Example, C=US"
        assert event.x509.san_dns == ["srv-05.example.com", "srv-05"]

    def test_raw_ip_tls_certificate_avoids_public_ca_dnsless_identity(self):
        """Raw-IP TLS should not render a public-CA CN-only certificate."""
        generator = ActivityGenerator(StateManager(), {})
        event = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.101",
                src_port=50123,
                dst_ip="45.33.32.30",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestRawIpTls",
            ),
        )

        generator._attach_ssl_context(
            event,
            hostname="",
            dns=None,
            dst_ip="45.33.32.30",
            rng=random.Random(42),
            allow_failure=False,
        )

        assert event.x509 is not None
        assert event.x509.certificate_subject == "CN=45.33.32.30"
        assert event.x509.certificate_issuer == "CN=45.33.32.30"
        assert event.x509.san_dns == []
        assert event.x509_chain == [event.x509]

    def test_same_certificate_fingerprint_has_same_metadata(self):
        """Repeated cert identity should not reuse a fingerprint for conflicting metadata."""
        generator = ActivityGenerator(StateManager(), {})
        first = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.101",
                src_port=50123,
                dst_ip="142.250.190.99",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestExternalTls1",
            ),
        )
        second = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 5, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.102",
                src_port=50124,
                dst_ip="142.250.190.99",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestExternalTls2",
            ),
        )

        for event in (first, second):
            generator._attach_ssl_context(
                event,
                hostname="ocsp.pki.goog",
                dns=None,
                dst_ip="142.250.190.99",
                rng=random.Random(43),
                allow_failure=False,
            )

        assert first.x509 is not None
        assert second.x509 is not None
        assert first.x509.fingerprint == second.x509.fingerprint
        assert first.x509.certificate_issuer == second.x509.certificate_issuer
        assert first.x509.certificate_key_type == second.x509.certificate_key_type
        assert first.x509.certificate_key_length == second.x509.certificate_key_length

    def test_intermediate_ca_profile_is_stable_across_leaf_certificates(self):
        """The same intermediate CA subject/issuer should not get many cert identities."""
        generator = ActivityGenerator(StateManager(), {})
        issuer_name = "CN=Cloudflare Inc ECC CA-3, O=Cloudflare Inc, C=US"
        first_chain = generator._build_tls_certificate_chain(
            leaf=X509Context(fuid="FLeafOne", certificate_subject="CN=one.example"),
            cert_name="one.example",
            issuer_name=issuer_name,
            event_time=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
            connection_uid="COne",
            rng=random.Random(1),
        )
        second_chain = generator._build_tls_certificate_chain(
            leaf=X509Context(fuid="FLeafTwo", certificate_subject="CN=two.example"),
            cert_name="two.example",
            issuer_name=issuer_name,
            event_time=datetime(2024, 10, 14, 12, 5, tzinfo=UTC),
            connection_uid="CTwo",
            rng=random.Random(1),
        )

        first_intermediate = first_chain[1]
        second_intermediate = second_chain[1]

        assert first_intermediate.fuid != second_intermediate.fuid
        assert first_intermediate.certificate_subject == second_intermediate.certificate_subject
        assert first_intermediate.certificate_issuer == second_intermediate.certificate_issuer
        assert first_intermediate.certificate_serial == second_intermediate.certificate_serial
        assert first_intermediate.fingerprint == second_intermediate.fingerprint
        assert (
            first_intermediate.certificate_not_valid_before
            == second_intermediate.certificate_not_valid_before
        )
        assert (
            first_intermediate.certificate_not_valid_after
            == second_intermediate.certificate_not_valid_after
        )


class TestDnsRtt:
    """Tests for resolver-aware DNS timing realism."""

    def test_public_resolver_rtts_are_not_submillisecond(self):
        rng = random.Random(42)
        samples = [_dns_rtt(rng, "8.8.8.8") for _ in range(500)]

        assert min(samples) >= 0.002
        assert sum(1 for sample in samples if sample < 0.001) == 0

    def test_internal_resolver_can_return_cache_hit_rtts(self):
        rng = random.Random(42)
        samples = [_dns_rtt(rng, "10.0.0.10") for _ in range(500)]

        assert any(sample < 0.001 for sample in samples)
