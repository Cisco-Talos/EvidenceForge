# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public DNS profile realism regression tests."""

from evidenceforge.generation.activity.generator import (
    _dns_registrable_domain,
    _public_dns_mx_answers,
    _public_dns_ns_answers,
    _public_dns_soa_answers,
)


def test_registrable_domain_handles_common_multi_label_suffixes():
    assert _dns_registrable_domain("www.example.co.uk") == "example.co.uk"
    assert _dns_registrable_domain("assets.service.com.au") == "service.com.au"


def test_public_dns_profiles_avoid_default_ns_mx_soa_templates():
    domain = "pypi.org"

    assert _public_dns_ns_answers(domain) != [f"ns1.{domain}", f"ns2.{domain}"]
    assert _public_dns_mx_answers(domain) != [f"10 mail.{domain}"]
    assert _public_dns_soa_answers(domain) != [f"ns1.{domain} hostmaster.{domain}"]


def test_public_dns_profiles_preserve_well_known_provider_overrides():
    assert _public_dns_ns_answers("google.com") == [
        "ns1.google.com",
        "ns2.google.com",
        "ns3.google.com",
        "ns4.google.com",
    ]
    assert _public_dns_mx_answers("microsoft.com") == [
        "0 microsoft-com.mail.protection.outlook.com"
    ]
    assert _public_dns_soa_answers("microsoft.com")[0].endswith("azuredns-hostmaster.microsoft.com")


def test_public_dns_answer_renderer_allows_only_literal_domain_tokens():
    from evidenceforge.generation.activity.generator import _render_public_dns_answer

    assert _render_public_dns_answer("10 {domain_hyphen}.mx.{domain}", "victim.test") == (
        "10 victim-test.mx.victim.test"
    )
    assert _render_public_dns_answer("literal {{ brace }} {domain}", "victim.test") == (
        "literal { brace } victim.test"
    )


def test_public_dns_answer_renderer_rejects_unsafe_format_fields():
    import pytest

    from evidenceforge.generation.activity.generator import _render_public_dns_answer

    for template in ("{missing}", "{domain:1000000000}", "{domain!r}", "{domain.__class__}"):
        with pytest.raises(ValueError, match="public DNS answer templates"):
            _render_public_dns_answer(template, "victim.test")
