# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 3 (DHCP jitter) and Theme 4 (certificate realism)."""

import math
import random
import re
from datetime import UTC, datetime

import yaml

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext, X509Context
from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    _dns_rtt,
    _ntp_stratum_and_ref_id,
    _ocsp_status_for_certificate,
    _tls_certificate_serial,
    _tls_san_dns_names,
)
from evidenceforge.generation.activity.tls_issuers import (
    load_tls_issuers,
    pick_issuer,
    pick_key_type,
)
from evidenceforge.generation.activity.tls_realism import (
    certificate_chain_config,
    certificate_subject_key_profile,
    chain_template_for_issuer,
    multi_label_public_suffixes,
    ocsp_config,
    pick_ocsp_responder,
    pick_tls_destination,
    reset_tls_realism_cache,
    signature_algorithm_for_issuer,
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
        """Generated SAN lists should vary while avoiding public-suffix wildcards."""
        assert _tls_san_dns_names("stackoverflow.com")[0] == "stackoverflow.com"
        assert _tls_san_dns_names("gcr.io")[0] == "gcr.io"
        assert _tls_san_dns_names("www.gstatic.com")[0] == "www.gstatic.com"
        assert _tls_san_dns_names("example.co.uk")[0] == "example.co.uk"
        assert _tls_san_dns_names("203.0.113.45") == []
        all_names = {
            name
            for domain in [
                "stackoverflow.com",
                "gcr.io",
                "www.gstatic.com",
                "example.co.uk",
                "files.pythonhosted.org",
            ]
            for name in _tls_san_dns_names(domain)
        }
        assert "*.co.uk" not in all_names
        assert "*.io" not in all_names
        assert any(not name.startswith("*.") for name in all_names)

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

    def test_tls_certificate_serial_lengths_vary_but_remain_stable(self):
        """Certificate serials should not all look like fixed 128-bit generated values."""
        serials = [_tls_certificate_serial(f"cert-{idx}") for idx in range(120)]

        assert _tls_certificate_serial("stable-cert") == _tls_certificate_serial("stable-cert")
        assert len({len(serial) for serial in serials}) >= 3
        assert all(16 <= len(serial) <= 40 for serial in serials)
        assert all(len(serial) % 2 == 0 for serial in serials)
        assert all(re.fullmatch(r"[0-9A-F]+", serial) for serial in serials)

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
            == "ocsp.meridianhcs.local"
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
            pick_tls_destination(
                random.Random(seed),
                src_host="WKS-01",
                source_os="windows",
                system_type="workstation",
            )[0]
            for seed in range(80)
        ]
        host_b = [
            pick_tls_destination(
                random.Random(seed),
                src_host="WKS-02",
                source_os="windows",
                system_type="workstation",
            )[0]
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
        assert not {domain for domain in linux_domains if "windowsupdate.com" in domain}

    def test_tls_destination_picker_excludes_cleartext_cert_infra_domains(self):
        """OCSP/CRL responders are HTTP objects, not direct TLS SNI destinations."""
        from evidenceforge.generation.activity.proxy_uri import get_proxy_domain_class

        domains = {
            pick_tls_destination(
                random.Random(seed),
                src_host="WKS-01",
                source_os="windows",
                system_type="workstation",
                purpose_tags=("background",),
            )[0]
            for seed in range(1200)
        }

        assert "ctldl.windowsupdate.com" in domains
        assert not {
            domain for domain in domains if get_proxy_domain_class(domain) in {"ocsp", "crl"}
        }

    def test_public_ca_chain_templates_keep_issuer_family(self):
        """Public CA intermediates should not fall through to an unrelated root family."""
        globalsign = chain_template_for_issuer(
            "CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1, O=GlobalSign nv-sa, C=BE"
        )
        sectigo = chain_template_for_issuer(
            "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, "
            "L=Salford, ST=Greater Manchester, C=GB"
        )

        assert globalsign["name"] == "globalsign"
        assert all("GlobalSign" in subject for subject in globalsign["intermediates"])
        assert sectigo["name"] == "sectigo"
        assert any(
            "Sectigo" in subject or "USERTrust" in subject for subject in sectigo["intermediates"]
        )
        lets_encrypt_rsa = chain_template_for_issuer("CN=R3, O=Let's Encrypt, C=US")
        lets_encrypt_ecdsa = chain_template_for_issuer("CN=E1, O=Let's Encrypt, C=US")
        assert lets_encrypt_rsa["intermediates"] == [
            "CN=ISRG Root X1, O=Internet Security Research Group, C=US"
        ]
        assert lets_encrypt_ecdsa["intermediates"] == [
            "CN=ISRG Root X2, O=Internet Security Research Group, C=US"
        ]

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

    def test_dns_tunnel_rtt_invalid_overlay_shape_falls_back_to_default(
        self, tmp_path, monkeypatch
    ):
        """Non-mapping dns_tunnel_rtt overlay values should not break config loading."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_rtt_range,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump({"dns_tunnel_rtt": 0}, sort_keys=False)
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert dns_tunnel_rtt_range() == (0.04, 0.35)
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_rtt_non_finite_overlay_values_fall_back_to_default(
        self, tmp_path, monkeypatch
    ):
        """Non-finite dns_tunnel_rtt overlay values should not propagate to generation."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_rtt_range,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            "dns_tunnel_rtt:\n  min_seconds: .nan\n  max_seconds: 1.0\n",
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert dns_tunnel_rtt_range() == (0.04, 0.35)
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_response_templates_are_loaded_from_network_params_overlay(
        self, tmp_path, monkeypatch
    ):
        """DNS tunnel response token shapes should be project-overlay configurable."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_response_templates,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {"dns_tunnel_response_templates": ["edge-{token}"]},
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert "edge-{token}" in dns_tunnel_response_templates()
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_rcode_weights_are_loaded_from_network_params_overlay(
        self, tmp_path, monkeypatch
    ):
        """DNS tunnel response-code mix should be project-overlay configurable."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_rcode_weights,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {"dns_tunnel_rcode_weights": {"NOERROR": 80, "NXDOMAIN": 20}},
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert dns_tunnel_rcode_weights() == {"NOERROR": 80.0, "NXDOMAIN": 20.0}
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_rcode_weights_normalize_overflowing_overlay_total(
        self, tmp_path, monkeypatch
    ):
        """DNS tunnel response-code weights should stay safe for random.choices."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_rcode_weights,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {"dns_tunnel_rcode_weights": {"NOERROR": 1.0e308, "NXDOMAIN": 1.0e308}},
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            weights = dns_tunnel_rcode_weights()

            assert weights == {"NOERROR": 1.0, "NXDOMAIN": 1.0}
            assert math.isfinite(sum(weights.values()))
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_ttl_choices_are_loaded_from_network_params_overlay(
        self, tmp_path, monkeypatch
    ):
        """DNS tunnel response TTL weights should be project-overlay configurable."""
        from evidenceforge.generation.activity.network_params import (
            dns_tunnel_ttl_choices,
            reset_network_params_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "network_params.yaml").write_text(
            yaml.safe_dump(
                {"dns_tunnel_ttl_choices": [{"value": 9, "weight": 5}]},
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_network_params_cache()
        try:
            assert (9, 5.0) in dns_tunnel_ttl_choices()
        finally:
            reset_network_params_cache()

    def test_dns_tunnel_ttl_choices_ignore_non_finite_overlay_values(self, monkeypatch):
        """Non-finite overlay TTL values should not crash runtime config loading."""
        from evidenceforge.generation.activity import network_params

        monkeypatch.setattr(
            network_params,
            "load_network_params",
            lambda: {"dns_tunnel_ttl_choices": [{"value": float("inf"), "weight": 1}]},
        )

        assert network_params.dns_tunnel_ttl_choices() == list(
            network_params._DEFAULT_DNS_TUNNEL_TTL_CHOICES
        )

    def test_dns_tunnel_ttl_choices_normalize_overflowing_weight_totals(self, monkeypatch):
        """Huge finite weights should remain usable by random.choices after normalization."""
        from evidenceforge.generation.activity import network_params
        from evidenceforge.generation.engine.storyline import _choose_dns_tunnel_campaign_ttl

        monkeypatch.setattr(
            network_params,
            "load_network_params",
            lambda: {
                "dns_tunnel_ttl_choices": [
                    {"value": 9, "weight": 1e308},
                    {"value": 10, "weight": 1e308},
                ]
            },
        )

        choices = network_params.dns_tunnel_ttl_choices()

        assert choices == [(9, 1.0), (10, 1.0)]
        assert math.isfinite(sum(weight for _value, weight in choices))
        assert _choose_dns_tunnel_campaign_ttl(choices, random.Random(7)) in {9, 10}

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
                src_ip="10.30.40.3",
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
                src_ip="10.30.40.3",
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
                src_ip="10.30.40.1",
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

    def test_tls_validity_window_is_not_observation_second_anchored(self):
        """Leaf cert validity should not reveal the exact first observation timestamp."""
        generator = ActivityGenerator(StateManager(), {})
        event = SecurityEvent(
            timestamp=datetime(2024, 10, 14, 12, 34, 56, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.30.40.101",
                src_port=50123,
                dst_ip="142.250.190.99",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTestExternalValidity",
            ),
        )

        generator._attach_ssl_context(
            event,
            hostname="github.com",
            dns=None,
            dst_ip="142.250.190.99",
            rng=random.Random(42),
            allow_failure=False,
        )

        assert event.x509 is not None
        observed_epoch = int(event.timestamp.timestamp())
        age_seconds = observed_epoch - event.x509.certificate_not_valid_before
        assert age_seconds > 0
        assert age_seconds % 86400 != 0

    def test_intermediate_validity_window_is_not_observation_second_anchored(self):
        """Intermediate CA validity should have its own issuance clock."""
        generator = ActivityGenerator(StateManager(), {})
        event_time = datetime(2024, 10, 14, 12, 34, 56, tzinfo=UTC)
        chain = generator._build_tls_certificate_chain(
            leaf=X509Context(fuid="FLeaf", certificate_subject="CN=leaf.example"),
            cert_name="leaf.example",
            issuer_name="CN=Cloudflare Inc ECC CA-3, O=Cloudflare Inc, C=US",
            event_time=event_time,
            connection_uid="CIntermediateValidity",
            rng=random.Random(1),
        )

        intermediate = chain[1]
        observed_epoch = int(event_time.timestamp())
        age_seconds = observed_epoch - intermediate.certificate_not_valid_before
        assert age_seconds > 0
        assert age_seconds % 86400 != 0

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
                hostname="www.cloudflare.com",
                dns=None,
                dst_ip="142.250.190.99",
                rng=random.Random(43),
                allow_failure=False,
            )

        assert first.x509 is not None
        assert second.x509 is not None
        assert len(first.x509.fingerprint) == 40
        assert first.x509.fingerprint == second.x509.fingerprint
        assert {len(first.x509.fuid), len(second.x509.fuid)} <= {17, 18, 19}
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
        assert {len(first_intermediate.fuid), len(second_intermediate.fuid)} <= {17, 18, 19}
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

    def test_intermediate_signature_algorithm_follows_issuer_key(self):
        """Intermediate certificate signatures should be signed by the issuer key."""
        generator = ActivityGenerator(StateManager(), {})
        issuer_name = "CN=Amazon RSA 2048 M01, O=Amazon, C=US"
        intermediate = None
        for seed in range(1, 200):
            chain = generator._build_tls_certificate_chain(
                leaf=X509Context(
                    fuid="FLeaf",
                    certificate_subject="CN=leaf.example",
                    certificate_issuer=issuer_name,
                ),
                cert_name=f"leaf-{seed}.example",
                issuer_name=issuer_name,
                event_time=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
                connection_uid=f"CLeE1{seed}",
                rng=random.Random(seed),
            )
            if len(chain) < 2:
                continue
            candidate = chain[1]
            if (
                certificate_subject_key_profile(candidate.certificate_subject)[0]
                != certificate_subject_key_profile(candidate.certificate_issuer)[0]
            ):
                intermediate = candidate
                break

        assert intermediate is not None

        assert intermediate.certificate_subject == issuer_name
        assert intermediate.certificate_issuer != intermediate.certificate_subject
        expected = signature_algorithm_for_issuer(intermediate.certificate_issuer)
        assert intermediate.certificate_sig_alg == expected

    def test_leaf_signature_algorithm_follows_issuer_not_leaf_key(self):
        """An ECDSA leaf signed by an RSA CA should render an RSA signature algorithm."""
        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 10, 14, 12, 0, tzinfo=UTC))
        generator = ActivityGenerator(state_manager, {})
        generator._emit_ocsp_http_response = lambda *args, **kwargs: None
        event = None

        for seed in range(1, 100):
            candidate = SecurityEvent(
                timestamp=datetime(2024, 10, 14, 12, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.30.40.101",
                    src_port=50123 + seed,
                    dst_ip="142.250.190.99",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    zeek_uid=f"CGtsLeafSignature{seed}",
                ),
            )
            generator._attach_ssl_context(
                candidate,
                hostname=f"asset-{seed}.google.com",
                dns=None,
                dst_ip="142.250.190.99",
                rng=random.Random(seed),
                allow_failure=False,
            )
            if candidate.x509 is not None:
                event = candidate
                break

        assert event is not None and event.x509 is not None
        assert event.x509.certificate_issuer == "CN=GTS CA 1C3, O=Google Trust Services LLC, C=US"
        expected = signature_algorithm_for_issuer(event.x509.certificate_issuer)
        assert event.x509.certificate_sig_alg == expected


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
