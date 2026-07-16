# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Stable DNS TXT answer generation for mail/authentication lookups."""

import random

from evidenceforge.generation.cryptographic_material import (
    shared_cryptographic_material_registry,
)
from evidenceforge.utils.rng import _stable_seed


def dns_registrable_domain(hostname: str) -> str:
    """Return a practical DNS owner name for mail/TXT companion lookups."""
    from evidenceforge.generation.activity.tls_realism import multi_label_public_suffixes

    parts = [part.lower() for part in hostname.rstrip(".").split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    lowered = ".".join(parts)
    for suffix in multi_label_public_suffixes():
        suffix_parts = suffix.split(".")
        if lowered.endswith(f".{suffix}") and len(parts) > len(suffix_parts):
            return ".".join(parts[-(len(suffix_parts) + 1) :])
    return ".".join(parts[-2:])


def stable_dns_txt_record(query: str) -> tuple[str, int]:
    """Return a source-native stable TXT answer and TTL for a query name."""
    query_l = query.rstrip(".").lower()
    rng = random.Random(_stable_seed(f"dns_txt_record:{query_l}"))

    if "._domainkey." in query_l:
        return f"v=DKIM1; k=rsa; p={_stable_dkim_key(query_l)}", rng.choice((900, 1800, 3600))

    if query_l.startswith("_dmarc."):
        domain = query_l.removeprefix("_dmarc.")
        policy = _domain_policy(domain)
        return (
            f"v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}; "
            f"ruf=mailto:dmarc-forensics@{domain}; fo=1",
            rng.choice((900, 1800, 3600)),
        )

    if query_l.startswith("_verify."):
        return f"verification={_stable_verification_token(query_l)}", rng.choice((300, 600, 900))

    domain = dns_registrable_domain(query_l)
    return _stable_spf_answer(domain), rng.choice((900, 1800, 3600))


def choose_dns_txt_query(hostname: str, roll: float | None = None) -> tuple[str, str, int]:
    """Choose a stable SPF/DMARC/DKIM-style TXT lookup for a hostname."""
    domain = dns_registrable_domain(hostname)
    selector_rng = random.Random(_stable_seed(f"dns_txt_query:{hostname.lower()}:{roll}"))
    effective_roll = selector_rng.random() if roll is None else roll

    if effective_roll < 0.45:
        query = domain
    elif effective_roll < 0.75:
        query = f"_dmarc.{domain}"
    else:
        selector = selector_rng.choice(("selector1", "selector2", "google", "k1", "mail", "s1"))
        query = f"{selector}._domainkey.{domain}"

    answer, ttl = stable_dns_txt_record(query)
    return query, answer, ttl


def choose_background_dns_txt_record(rng: random.Random) -> tuple[str, str, int]:
    """Return a benign TXT query/answer that can collide with tunnel-era DNS."""
    domain = rng.choice(
        (
            "meridianhcs.com",
            "microsoft.com",
            "github.com",
            "sendgrid.net",
            "okta.com",
            "duo.com",
            "zoom.us",
            "atlassian.net",
        )
    )
    style = rng.choices(("spf", "dkim", "dmarc", "verify"), weights=[38, 32, 20, 10], k=1)[0]
    if style == "spf":
        query = domain
    elif style == "dkim":
        selector = rng.choice(("selector1", "selector2", "s1", "mail", "k1", "mta"))
        query = f"{selector}._domainkey.{domain}"
    elif style == "dmarc":
        query = f"_dmarc.{domain}"
    else:
        query = f"_verify.{domain}"

    answer, ttl = stable_dns_txt_record(query)
    return query, answer, ttl


def _stable_dkim_key(query: str) -> str:
    """Return a selector-stable RSA SubjectPublicKeyInfo value."""

    normalized = query.rstrip(".").lower()
    selector, separator, domain = normalized.partition("._domainkey.")
    if not separator or not selector or not domain:
        raise ValueError(
            "DKIM owner names must use <selector>._domainkey.<domain> before key planning"
        )
    return (
        shared_cryptographic_material_registry()
        .resolve_dkim_key(
            domain,
            selector,
        )
        .public_key_base64
    )


def _stable_verification_token(query: str) -> str:
    rng = random.Random(_stable_seed(f"dns_verify:{query}"))
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(32))


def _domain_policy(domain: str) -> str:
    if domain.endswith(("microsoft.com", "github.com", "sendgrid.net", "okta.com")):
        return "reject"
    if domain.endswith(("duo.com", "zoom.us", "atlassian.net")):
        return "quarantine"
    return "none"


def _stable_spf_answer(domain: str) -> str:
    domain_l = domain.lower()
    domain_spf: dict[str, str] = {
        "duo.com": "v=spf1 include:spf.protection.outlook.com include:_spf.salesforce.com -all",
        "github.com": "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all",
        "meridianhcs.com": "v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all",
        "microsoft.com": (
            "v=spf1 include:spf.protection.outlook.com include:_spf-a.microsoft.com "
            "include:_spf-b.microsoft.com -all"
        ),
        "okta.com": "v=spf1 include:spf.protection.outlook.com include:sendgrid.net -all",
        "sendgrid.net": "v=spf1 include:sendgrid.net -all",
        "zoom.us": "v=spf1 include:spf.protection.outlook.com include:amazonses.com ~all",
    }
    return domain_spf.get(domain_l, f"v=spf1 include:_spf.{domain_l} ~all")
