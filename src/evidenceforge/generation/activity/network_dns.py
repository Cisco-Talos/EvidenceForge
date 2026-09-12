# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared dns protocol planning helpers."""

from __future__ import annotations

import logging
import math
import random

from evidenceforge.events.contexts import (
    DnsContext,
)
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)

_DNS_QTYPE_RDATA_LENGTHS = {
    "A": 4,
    "AAAA": 16,
}


def _dns_name_wire_size(name: str) -> int:
    """Return the encoded DNS owner-name size, including label lengths and root."""
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        return 1
    return sum(1 + len(label.encode("utf-8", errors="ignore")) for label in labels) + 1


def _dns_question_wire_size(query: str) -> int:
    """Return DNS question section size for one IN-class query."""
    return _dns_name_wire_size(query) + 4


def _dns_payload_padding(*, query: str, query_type: str, response: bool) -> int:
    """Return stable EDNS/client-padding texture for DNS payload accounting."""
    seed = _stable_seed(f"dns_payload_padding:{query.lower()}:{query_type}:{response}")
    rng = random.Random(seed)
    if query_type in {"TXT", "NULL"}:
        choices = (0, 11, 23, 47, 71)
        weights = (30, 35, 20, 10, 5)
    elif response:
        choices = (0, 11, 23, 35)
        weights = (45, 35, 15, 5)
    else:
        choices = (0, 11, 23)
        weights = (35, 50, 15)
    return rng.choices(choices, weights=weights, k=1)[0]


def _dns_rr_rdata_size(query_type: str, answer: str) -> int:
    """Return an approximate RDATA length for a source-native DNS answer."""
    if query_type in _DNS_QTYPE_RDATA_LENGTHS:
        return _DNS_QTYPE_RDATA_LENGTHS[query_type]
    if query_type in {"CNAME", "PTR", "NS"}:
        return _dns_name_wire_size(answer)
    if query_type == "MX":
        parts = answer.split(maxsplit=1)
        exchange = parts[1] if len(parts) == 2 else answer
        return 2 + _dns_name_wire_size(exchange)
    if query_type == "SRV":
        parts = answer.split()
        target = parts[-1] if parts else answer
        return 6 + _dns_name_wire_size(target)
    if query_type == "SOA":
        parts = answer.split()
        if len(parts) >= 2:
            return _dns_name_wire_size(parts[0]) + _dns_name_wire_size(parts[1]) + 20
        return max(24, len(answer.encode("utf-8", errors="ignore")))
    if query_type == "TXT":
        text_len = len(answer.encode("utf-8", errors="ignore"))
        return text_len + max(1, math.ceil(text_len / 255))
    return max(4, len(answer.encode("utf-8", errors="ignore")))


def _dns_response_wire_size(*, dns: DnsContext, question_size: int, query_type: str) -> int:
    """Return DNS response payload bytes derived from the visible DNS context."""
    base_size = 12 + question_size
    answers = dns.answers or []
    if answers:
        rr_bytes = 0
        for answer in answers:
            rdata_size = _dns_rr_rdata_size(query_type, str(answer))
            rr_bytes += 2 + 10 + rdata_size  # compressed owner pointer + RR metadata
        return (
            base_size
            + rr_bytes
            + _dns_payload_padding(
                query=dns.query,
                query_type=query_type,
                response=True,
            )
        )

    rcode = (dns.rcode or "").upper()
    if rcode in {"NXDOMAIN", "SERVFAIL", "REFUSED"} or dns.rcode_num in {2, 3, 5}:
        failure_seed = _stable_seed(f"dns_failure_payload:{dns.query}:{query_type}:{rcode}")
        failure_rng = random.Random(failure_seed)
        authority_bytes = {
            "NXDOMAIN": failure_rng.randint(36, 92),
            "SERVFAIL": failure_rng.randint(18, 46),
            "REFUSED": failure_rng.randint(18, 54),
        }.get(rcode, failure_rng.randint(18, 54))
        return (
            base_size
            + authority_bytes
            + _dns_payload_padding(
                query=dns.query,
                query_type=query_type,
                response=True,
            )
        )

    if rcode == "NOERROR" or dns.rcode_num == 0:
        return base_size + _dns_payload_padding(
            query=dns.query,
            query_type=query_type,
            response=True,
        )
    return 0


def _dns_payload_accounting(
    *,
    dns: DnsContext,
    duration: float | None,
    orig_bytes: int | None,
    resp_bytes: int | None,
) -> tuple[float | None, int, int]:
    """Normalize DNS conn.log payload accounting to the DNS transaction."""
    query = dns.query or ""
    query_type = (dns.query_type or "").upper()
    response_rcodes = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
    has_response = (
        dns.rtt is not None
        or bool(dns.answers)
        or dns.rcode.upper() in response_rcodes
        or dns.rcode_num in {0, 2, 3, 5}
    )
    question_size = _dns_question_wire_size(query)
    query_payload_size = (
        12
        + question_size
        + _dns_payload_padding(
            query=query,
            query_type=query_type,
            response=False,
        )
    )
    normalized_orig = max(28, min(query_payload_size, 1232))

    if not has_response:
        normalized_resp = 0
    else:
        response_payload_size = _dns_response_wire_size(
            dns=dns,
            question_size=question_size,
            query_type=query_type,
        )
        normalized_resp = max(40, min(response_payload_size, 1232))

    normalized_duration = duration
    if dns.rtt is not None:
        normalized_duration = dns.rtt

    return normalized_duration, normalized_orig, normalized_resp


def _dns_base_ttl(query: str, is_internal: bool) -> int:
    """Return a stable authoritative TTL for a DNS query name."""
    domain_seed = random.Random(_stable_seed(f"dns_ttl_{query}"))
    if is_internal:
        return domain_seed.choice([300, 600, 1800, 3600, 7200, 86400])
    return domain_seed.choice([30, 60, 120, 300, 600, 1800, 3600])


def _dns_observation_cache_key(
    src_ip: str,
    resolver_ip: str,
    dns: DnsContext,
) -> tuple[str, str, str, str] | None:
    """Return the cache key for suppressing repeated visible DNS observations."""
    qtype_name = (dns.query_type or str(dns.qtype)).upper()
    if qtype_name not in {"A", "AAAA", "MX", "SRV"}:
        return None
    if dns.rcode != "NOERROR" or not dns.answers or not dns.TTLs:
        return None
    normalized_query = (dns.query or "").rstrip(".").lower()
    if not normalized_query:
        return None
    normalized_answers = "|".join(sorted(str(answer) for answer in dns.answers))
    return (src_ip, resolver_ip, normalized_query, f"{qtype_name}:{normalized_answers}")


def _dns_is_internal_name(query: str, ad_domain: str) -> bool:
    """Return whether a DNS query belongs to the scenario's internal namespace."""
    lowered = query.rstrip(".").lower()
    domain = ad_domain.rstrip(".").lower()
    return lowered.endswith(f".{domain}") or lowered == domain or lowered.endswith(".local")
