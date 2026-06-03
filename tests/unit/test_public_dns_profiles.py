# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public DNS profile realism regression tests."""

from evidenceforge.generation.activity.generator import (
    _dns_registrable_domain,
    _dns_reverse_query,
    _dns_soa_answer,
    _public_dns_aaaa_answers,
    _public_dns_mx_answers,
    _public_dns_ns_answers,
    _public_dns_ptr_response,
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


def test_public_dns_profiles_are_diverse_for_unrelated_domains():
    domains = [
        "pypi.org",
        "slack.com",
        "zoom.us",
        "dropbox.com",
        "atlassian.com",
        "okta.com",
        "tableau.com",
        "wellbridge.io",
        "cloudmetrics.co",
        "vitalsource.io",
        "salesforce.com",
        "reddit.com",
    ]

    ns_answer_sets = {tuple(_public_dns_ns_answers(domain)) for domain in domains}
    mx_answer_sets = {tuple(_public_dns_mx_answers(domain)) for domain in domains}

    assert len(ns_answer_sets) >= 8
    assert len(mx_answer_sets) >= 7


def test_public_ptr_responses_are_sparse_and_not_forward_hostname_echoes():
    samples = [
        ("13.107.246.52", "packages.microsoft.com"),
        ("142.250.191.46", "drive.google.com"),
        ("52.84.162.162", "cdn.typekit.com"),
        ("23.45.118.80", "wd3.myworkdaycdn.com"),
    ]

    rcode_names: set[str] = set()
    for ip, forward_hostname in samples:
        rcode, rcode_num, answers = _public_dns_ptr_response(ip, forward_hostname)
        rcode_names.add(rcode)

        assert _dns_reverse_query(ip).endswith(".in-addr.arpa")
        if rcode == "NXDOMAIN":
            assert rcode_num == 3
            assert answers == []
        else:
            assert rcode == "NOERROR"
            assert rcode_num == 0
            assert len(answers) == 1
            assert answers[0] != forward_hostname

    assert "NXDOMAIN" in rcode_names
    assert "NOERROR" in rcode_names


def test_public_dns_soa_answers_include_full_rdata():
    answer = _public_dns_soa_answers("pypi.org")[0]
    fields = answer.split()

    assert len(fields) == 7
    assert fields[0].endswith(".net") or fields[0].endswith(".com") or fields[0].endswith(".org")
    assert "." in fields[1]
    assert all(field.isdigit() for field in fields[2:])
    assert int(fields[3]) > int(fields[4])
    assert int(fields[5]) > int(fields[3])


def test_internal_dns_soa_answers_include_full_rdata():
    answer = _dns_soa_answer(
        "meridianhcs.local",
        "ns1.meridianhcs.local",
        "hostmaster.meridianhcs.local",
        "internal",
    )
    fields = answer.split()

    assert fields[:2] == ["ns1.meridianhcs.local", "hostmaster.meridianhcs.local"]
    assert len(fields) == 7
    assert all(field.isdigit() for field in fields[2:])


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
    assert _public_dns_soa_answers("microsoft.com")[0].split()[1] == (
        "azuredns-hostmaster.microsoft.com"
    )


def test_public_dns_profiles_preserve_known_authority_ownership():
    assert all(answer.endswith(".canonical.com") for answer in _public_dns_ns_answers("ubuntu.com"))
    assert all(
        answer.endswith(".canonical.com") for answer in _public_dns_ns_answers("snapcraft.io")
    )
    assert all(
        answer.endswith(".facebook.com") for answer in _public_dns_ns_answers("facebook.net")
    )
    assert all(answer.endswith(".akam.net") for answer in _public_dns_ns_answers("akamai.net"))
    assert all(
        answer.endswith(".google.com") for answer in _public_dns_ns_answers("googleusercontent.com")
    )


def test_public_dns_mail_profiles_preserve_recognizable_owner_families():
    assert _public_dns_mx_answers("gstatic.com") == ["0 ."]
    assert _public_dns_mx_answers("akamaihd.net") == ["0 ."]
    assert _public_dns_mx_answers("office.net") == ["0 ."]
    assert _public_dns_mx_answers("live.com") == ["0 live-com.mail.protection.outlook.com"]
    assert _public_dns_mx_answers("powerapps.com") != [
        "10 mx1.sendgrid.net",
        "20 mx2.sendgrid.net",
    ]
    assert all(answer.endswith(".adobe.com") for answer in _public_dns_mx_answers("adobe.com"))
    assert all(
        answer.endswith(".facebook.com") for answer in _public_dns_mx_answers("facebook.com")
    )
    assert all(
        answer.endswith(".cisco.com") for answer in _public_dns_mx_answers("duosecurity.com")
    )


def test_public_dns_nameserver_profiles_preserve_saas_owner_families():
    azure_dns_suffixes = (".azure-dns.com", ".azure-dns.net", ".azure-dns.org", ".azure-dns.info")
    assert all(
        answer.endswith(azure_dns_suffixes) for answer in _public_dns_ns_answers("onenote.net")
    )
    assert all(
        answer.endswith(azure_dns_suffixes) for answer in _public_dns_ns_answers("powerapps.com")
    )
    assert all(answer.endswith(".cisco.com") for answer in _public_dns_ns_answers("webex.com"))
    assert all(
        answer.endswith(".adobe.com") or answer.endswith(".akam.net")
        for answer in _public_dns_ns_answers("typekit.net")
    )


def test_public_dns_aaaa_profiles_preserve_recognizable_owner_families():
    assert all(
        answer.startswith("2607:f8b0:")
        for answer in _public_dns_aaaa_answers("static.gstatic.com", "23.45.118.80")
    )
    assert all(
        answer.startswith(("2620:1ec:", "2603:1000:"))
        for answer in _public_dns_aaaa_answers("statics.teams.cdn.office.net", "23.45.118.80")
    )
    assert all(
        answer.startswith("2a03:2880:")
        for answer in _public_dns_aaaa_answers("static.xx.fbcdn.net", "23.45.118.80")
    )
    assert all(
        answer.startswith(("2a02:26f0:", "2600:9000:"))
        for answer in _public_dns_aaaa_answers("auth.services.adobe.com", "23.45.118.80")
    )


def test_public_dns_aaaa_known_owner_without_profile_uses_nodata_not_fake_ipv6(monkeypatch):
    from evidenceforge.generation.activity import public_dns_profiles

    real_loader = public_dns_profiles.load_public_dns_profiles

    def load_without_cisco_aaaa():
        data = real_loader()
        return {
            **data,
            "aaaa_profiles": [
                profile for profile in data["aaaa_profiles"] if profile["name"] != "cisco"
            ],
        }

    monkeypatch.setattr(public_dns_profiles, "load_public_dns_profiles", load_without_cisco_aaaa)

    assert _public_dns_aaaa_answers("api.webexapis.com", "23.45.118.80") == []


def test_public_dns_aaaa_generic_unknown_domain_keeps_deterministic_fallback():
    answers = _public_dns_aaaa_answers("api.wellbridge-services.net", "45.56.88.10")

    assert len(answers) == 1
    assert ":" in answers[0]


def test_public_dns_soa_serials_do_not_look_future_date_coded():
    domains = [
        "meridianhcs.local",
        "adobedtm.com",
        "healthnexus.io",
        "akamai.net",
        "ubuntu.com",
    ]

    for domain in domains:
        serial = _dns_soa_answer(domain, f"ns1.{domain}", f"hostmaster.{domain}").split()[2]
        assert serial.isdigit()
        assert not serial.startswith("2024")


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
