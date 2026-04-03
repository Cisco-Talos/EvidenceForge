# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unified DNS registry — single source of truth for all domain↔IP mappings.

Loads dns_registry.yaml and builds all derived lookup structures:
- REVERSE_DNS: IP → domain (for backward compatibility)
- FORWARD_DNS: domain → list of IPs
- Tag-based queries: get_domains_by_tag("web") → [(domain, ips), ...]
- pick_domain_and_ip(): domain-first connection selection

Follows the same cached-loader pattern as spawn_rules.py, bash_commands.py, etc.
"""

import hashlib
import random
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.utils.rng import _stable_seed

_REGISTRY_PATH = Path(__file__).parent / "dns_registry.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_CACHED_REVERSE_DNS: dict[str, str] | None = None
_CACHED_FORWARD_DNS: dict[str, list[str]] | None = None
_CACHED_TAG_INDEX: dict[str, list[dict]] | None = None


def load_dns_registry() -> dict[str, Any]:
    """Load the DNS registry YAML. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    with open(_REGISTRY_PATH) as f:
        _CACHED_DATA = yaml.safe_load(f)
    return _CACHED_DATA


def get_reverse_dns() -> dict[str, str]:
    """Build IP → domain mapping (first domain wins for shared IPs).

    Returns a dict compatible with the legacy REVERSE_DNS format.
    """
    global _CACHED_REVERSE_DNS
    if _CACHED_REVERSE_DNS is not None:
        return _CACHED_REVERSE_DNS

    data = load_dns_registry()
    result: dict[str, str] = {}
    for entry in data.get("domains", []):
        domain = entry["domain"]
        for ip in entry["ips"]:
            if ip not in result:
                result[ip] = domain
    _CACHED_REVERSE_DNS = result
    return result


def get_forward_dns() -> dict[str, list[str]]:
    """Build domain → list of IPs mapping.

    Returns full IP list per domain (not just first IP).
    """
    global _CACHED_FORWARD_DNS
    if _CACHED_FORWARD_DNS is not None:
        return _CACHED_FORWARD_DNS

    data = load_dns_registry()
    result: dict[str, list[str]] = {}
    for entry in data.get("domains", []):
        result[entry["domain"]] = entry["ips"]
    _CACHED_FORWARD_DNS = result
    return result


def _build_tag_index() -> dict[str, list[dict]]:
    """Build tag → list of domain entries index."""
    global _CACHED_TAG_INDEX
    if _CACHED_TAG_INDEX is not None:
        return _CACHED_TAG_INDEX

    data = load_dns_registry()
    result: dict[str, list[dict]] = {}
    for entry in data.get("domains", []):
        for tag in entry.get("tags", []):
            result.setdefault(tag, []).append(entry)
    _CACHED_TAG_INDEX = result
    return result


def get_domains_by_tag(*tags: str) -> list[dict]:
    """Get domain entries matching ALL specified tags.

    Args:
        *tags: One or more tags to filter by (e.g., "background", "windows").
               Entries must have ALL specified tags.

    Returns:
        List of domain entry dicts with keys: domain, ips, tags.
    """
    index = _build_tag_index()
    if not tags:
        return []

    # Start with entries matching first tag, intersect with remaining tags
    tag_set = set(tags)
    candidates = index.get(tags[0], [])
    return [entry for entry in candidates if tag_set.issubset(set(entry.get("tags", [])))]


def pick_domain_and_ip(
    rng: random.Random,
    *tags: str,
    src_host: str = "",
) -> tuple[str, str]:
    """Pick a domain by tag(s) and select a deterministic primary IP.

    The IP is deterministic per (src_host, domain) pair using _stable_seed,
    simulating DNS caching — the same host always connects to the same IP
    for a given domain.

    Args:
        rng: Random instance for domain selection.
        *tags: Tags to filter domains by (e.g., "web", or "background", "windows").
        src_host: Source hostname for deterministic IP selection.

    Returns:
        (domain, ip) tuple.
    """
    entries = get_domains_by_tag(*tags)
    if not entries:
        # Fallback: generate a long-tail domain
        data = load_dns_registry()
        lt = data.get("long_tail", {})
        prefix = rng.choice(lt.get("prefixes", ["cdn"]))
        brand = rng.choice(lt.get("brands", ["example"]))
        tld = rng.choice(lt.get("tlds", ["com"]))
        domain = f"{prefix}.{brand}.{tld}"
        ip = _domain_to_ip(domain)
        return domain, ip

    entry = rng.choice(entries)
    domain = entry["domain"]
    ips = entry["ips"]

    # Deterministic IP per (src_host, domain) — simulates DNS cache
    if len(ips) == 1:
        return domain, ips[0]
    ip_idx = _stable_seed(f"dns_ip_{src_host}_{domain}") % len(ips)
    return domain, ips[ip_idx]


def get_domain_ips(domain: str) -> list[str]:
    """Get the full IP list for a domain (for DNS multi-answer responses).

    Returns empty list if domain not in registry.
    """
    forward = get_forward_dns()
    return forward.get(domain, [])


def generate_long_tail_domain(rng: random.Random) -> str:
    """Generate a plausible SaaS/CDN/analytics domain for long-tail traffic.

    Uses templates from the registry's long_tail section.
    """
    data = load_dns_registry()
    lt = data.get("long_tail", {})
    prefix = rng.choice(lt.get("prefixes", ["cdn"]))
    brand = rng.choice(lt.get("brands", ["example"]))
    tld = rng.choice(lt.get("tlds", ["com"]))
    return f"{prefix}.{brand}.{tld}"


def _domain_to_ip(domain: str) -> str:
    """Derive a deterministic external IP from a domain name.

    Uses a hash to map the domain to an IP in a realistic CDN range.
    Same domain always produces the same IP.
    """
    data = load_dns_registry()
    ranges = data.get("cdn_ranges", [[104, 16]])

    h = int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16)
    prefix = ranges[h % len(ranges)]
    octet3 = (h >> 8) & 0xFF
    octet4 = max(1, (h >> 16) & 0xFE)  # Avoid .0 and .255
    return f"{prefix[0]}.{prefix[1]}.{octet3}.{octet4}"


def get_ipv6_map() -> dict[str, str]:
    """Get IPv4 → IPv6 mapping for AAAA queries."""
    data = load_dns_registry()
    return data.get("ipv6_map", {})


def get_cdn_ranges() -> list[list[int]]:
    """Get CDN IP ranges for random IP generation."""
    data = load_dns_registry()
    return data.get("cdn_ranges", [])
