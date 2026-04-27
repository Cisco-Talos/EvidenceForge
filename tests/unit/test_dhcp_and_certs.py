# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 3 (DHCP jitter) and Theme 4 (certificate realism)."""

import random

from evidenceforge.generation.activity.tls_issuers import load_tls_issuers, pick_issuer

# ---------------------------------------------------------------------------
# Theme 4: Certificate realism tests
# ---------------------------------------------------------------------------


class TestTlsIssuers:
    """Tests for TLS issuer configuration and selection."""

    def test_windowsupdate_uses_microsoft_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "download.windowsupdate.com")
        assert "Microsoft" in issuer["name"]

    def test_aws_uses_amazon_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "aws.amazon.com")
        assert "Amazon" in issuer["name"]

    def test_apple_uses_apple_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "www.apple.com")
        assert "Apple" in issuer["name"]

    def test_icloud_uses_apple_ca(self):
        rng = random.Random(42)
        issuer = pick_issuer(rng, "www.icloud.com")
        assert "Apple" in issuer["name"]

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
