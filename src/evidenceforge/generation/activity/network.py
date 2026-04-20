# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Network helper functions and data for activity generation.

Provides IP generation, hostname resolution, DNS data, and network validation.
All domain↔IP data is loaded from dns_registry.yaml via dns_registry.py.
"""

import ipaddress
import random

from evidenceforge.generation.activity.dns_registry import (
    generate_long_tail_domain,
    get_cdn_ranges,
    get_domains_by_tag,
    get_forward_dns,
    get_ipv6_map,
    get_reverse_dns,
    load_dns_registry,
)


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC 1918 private address (for Zeek local_orig/local_resp)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ============================================================================
# All domain↔IP data is loaded from dns_registry.yaml (single source of truth).
# These module-level variables are backward-compatible wrappers.
# ============================================================================

# Backward-compatible: IP → domain (used by many modules)
REVERSE_DNS: dict[str, str] = get_reverse_dns()

# Backward-compatible: domain → first IP
FORWARD_DNS: dict[str, str] = {d: ips[0] for d, ips in get_forward_dns().items()}

# Backward-compatible: activity type → list of IPs
# Built from registry tags: web, email, git, saas, internal
_TAG_TO_ACTIVITY = {
    "connection_web": "web",
    "connection_email": "email",
    "connection_git": "git",
    "connection_saas": "saas",
    "connection_db": "internal",
}
EXTERNAL_IPS: dict[str, list[str]] = {}
for _act_type, _tag in _TAG_TO_ACTIVITY.items():
    _entries = get_domains_by_tag(_tag)
    _ips: list[str] = []
    for _e in _entries:
        _ips.extend(_e["ips"])
    EXTERNAL_IPS[_act_type] = list(dict.fromkeys(_ips))  # Deduplicate, preserve order

# CDN ranges and IPv6 map from registry
_CDN_RANGES = [tuple(r) for r in get_cdn_ranges()]
_IPV6_MAP: dict[str, str] = get_ipv6_map()

# AD SRV record templates for domain service discovery
_AD_SRV_QUERIES = [
    "_ldap._tcp.dc._msdcs.{domain}",
    "_kerberos._tcp.{domain}",
    "_kerberos._tcp.dc._msdcs.{domain}",
    "_ldap._tcp.{domain}",
    "_gc._tcp.{domain}",
    "_kpasswd._tcp.{domain}",
]

# SRV query -> port mapping
_SRV_PORT_MAP = {
    "_ldap": 389,
    "_gc": 3268,
    "_kerberos": 88,
    "_kpasswd": 464,
}


_CACHED_IPV6_PREFIXES: dict | None = None


def _load_ipv6_prefixes() -> dict:
    """Load IPv6 prefix config from dns_registry.yaml (cached)."""
    global _CACHED_IPV6_PREFIXES
    if _CACHED_IPV6_PREFIXES is not None:
        return _CACHED_IPV6_PREFIXES
    data = load_dns_registry()
    _CACHED_IPV6_PREFIXES = data.get("ipv6_prefixes", {"default": "2a09:bac0", "ranges": []})
    return _CACHED_IPV6_PREFIXES


def _ipv4_to_fake_ipv6(ipv4: str) -> str:
    """Generate a deterministic plausible IPv6 address from an IPv4 address.

    Uses provider-specific prefixes loaded from dns_registry.yaml ipv6_prefixes
    section, keyed by first octet of the IPv4 address.
    """
    octets = ipv4.split(".")
    o0, o1, o2, o3 = int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3])

    # Private IPs get ULA prefix (fd00::/8)
    if o0 == 10 or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168):
        return f"fd00:{o1:02x}{o2:02x}:{o3:04x}::1"

    config = _load_ipv6_prefixes()
    prefix = config.get("default", "2a09:bac0")
    for entry in config.get("ranges", []):
        if entry["lo"] <= o0 <= entry["hi"]:
            prefix = entry["prefix"]
            break
    return f"{prefix}:{o1:02x}{o2:02x}:{o3:04x}::1"


def _generate_random_external_ip(rng) -> str:
    """Generate a random plausible external IP from common cloud/CDN ranges."""
    prefix = rng.choice(_CDN_RANGES)
    return f"{prefix[0]}.{prefix[1]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _generate_internal_hostname(rng, ip: str, domain: str = "corp.local") -> str:
    """Generate a plausible internal hostname for RFC 1918 IPs.

    Deterministic based on IP so the same IP always gets the same hostname
    (avoids multiple different hostnames resolving to the same IP).
    """
    prefixes = ["srv", "app", "db", "web", "print", "nas", "mgmt", "mon", "backup"]
    suffixes = ["01", "02", "03", "04", "05"]
    # Deterministic selection based on IP hash
    from evidenceforge.utils.rng import _stable_seed

    ip_hash = _stable_seed(f"internal_hostname_{ip}")
    prefix = prefixes[ip_hash % len(prefixes)]
    suffix = suffixes[(ip_hash >> 8) % len(suffixes)]
    return f"{prefix}-{suffix}.{domain}"


def _detect_ip_provider(ip: str) -> str:
    """Detect cloud/CDN provider for a public IPv4 address.

    Returns "generic" for invalid inputs and non-IPv4 addresses.
    """
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return "generic"

    if not isinstance(parsed_ip, ipaddress.IPv4Address):
        return "generic"

    first = int(str(parsed_ip).split(".")[0])
    if first in (172, 142, 209, 74, 108):
        return "google"
    if first in (140, 185) and ip.startswith("140.82."):
        return "github"
    if first in (151,):
        return "fastly"
    if first in (23,):
        return "akamai"
    if first in (52, 54, 3, 18, 44, 34):
        return "aws"
    if first in (13, 20, 40, 204) and not ip.startswith("13.108."):
        return "microsoft"
    if first in (104,) and (
        ip.startswith("104.16.")
        or ip.startswith("104.18.")
        or ip.startswith("104.21.")
        or ip.startswith("104.26.")
    ):
        return "cloudflare"
    return "generic"


# Long-tail domain generation — delegates to dns_registry
_generate_long_tail_domain = generate_long_tail_domain


def _generate_random_hostname(rng, ip: str) -> str:
    """Generate a provider-aware hostname matching the IP's cloud/CDN provider.

    Ensures the hostname pattern is coherent with the IP range -- no Google
    hostnames for AWS IPs or vice versa.
    """
    octets = ip.split(".")
    provider = _detect_ip_provider(ip)

    if provider == "google":
        return rng.choice(
            [
                f"{'-'.join(octets)}.bc.googleusercontent.com",
                f"lax17s{rng.randint(10, 99)}-in-f{octets[3]}.1e100.net",
            ]
        )
    elif provider == "aws":
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        cf_chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return rng.choice(
            [
                f"ec2-{'-'.join(octets)}.{rng.choice(regions)}.compute.amazonaws.com",
                f"d{''.join(rng.choices(cf_chars, k=13))}.cloudfront.net",
                f"server-{'-'.join(octets)}.iad89.r.cloudfront.net",
            ]
        )
    elif provider == "akamai":
        return f"a{'-'.join(octets)}.deploy.static.akamaitechnologies.com"
    elif provider == "cloudflare":
        return f"{'-'.join(octets)}.cdn.cloudflare.net"
    elif provider == "github":
        return f"lb-{'-'.join(octets)}-iad.github.com"
    elif provider == "fastly":
        return f"{'-'.join(octets)}.{'fastly' if rng.random() < 0.5 else 'global.ssl.fastly'}.net"
    elif provider == "microsoft":
        return f"{'-'.join(octets)}.microsoft.com"
    else:
        # Generate plausible domain names for unknown IPs (including RFC 5737
        # documentation ranges used for attacker C2/exfiltration in storylines).
        # Realistic mix of SaaS, CDN, analytics, and cloud storage domains.
        _PLAUSIBLE_DOMAINS = [
            "api.segment-analytics.io",
            "cdn.jsdelivr.net",
            "assets.zendesk.com",
            "static.intercom-mail.com",
            "media.licdn.com",
            "p.typekit.net",
            "fonts.gstatic.com",
            "cdn.datatables.net",
            "js.stripe.com",
            "cdn.cookielaw.org",
            "static.hotjar.com",
            "api.hubspot.com",
            "widget.intercom.io",
            "cdn.optimizely.com",
            "snap.licdn.com",
            "connect.facebook.net",
            "cdn.amplitude.com",
            "api.mixpanel.com",
            "assets.adobedtm.com",
            "cdn.heapanalytics.com",
            "api.segment.io",
            "px.ads.linkedin.com",
            "cdn.mouseflow.com",
            "js.hs-analytics.net",
            "static.parastorage.com",
            "cdn.branch.io",
            "api.logz.io",
            "cdn.mxpnl.com",
            "sdk.split.io",
            "app.launchdarkly.com",
        ]
        return rng.choice(_PLAUSIBLE_DOMAINS)


def _generate_rdns_name(rng, ip: str) -> str:
    """Generate a realistic reverse DNS name for an IP (for PTR query answers).

    rDNS names differ from forward hostnames -- they typically embed the IP
    octets and use provider-specific naming conventions.
    """
    octets = ip.split(".")
    provider = _detect_ip_provider(ip)

    if provider == "google":
        # Google rDNS: {region}s{NN}-in-f{last_octet}.1e100.net
        regions = ["lax17", "sfo07", "dfw25", "iad30", "ord37"]
        return f"{rng.choice(regions)}s{rng.randint(10, 99)}-in-f{octets[3]}.1e100.net"
    elif provider == "aws":
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        return rng.choice(
            [
                f"ec2-{'-'.join(octets)}.{rng.choice(regions)}.compute.amazonaws.com",
                f"server-{'-'.join(octets)}.iad89.r.cloudfront.net",
            ]
        )
    elif provider == "akamai":
        return f"a{octets[1]}-{octets[2]}-{octets[3]}.deploy.static.akamaitechnologies.com"
    elif provider == "cloudflare":
        return f"{'-'.join(octets)}.cdn.cloudflare.net"
    elif provider == "github":
        return f"lb-{'-'.join(octets)}-iad.github.com"
    elif provider == "fastly":
        return f"{'-'.join(octets)}.fastly.net"
    elif provider == "microsoft":
        return f"msnbot-{'-'.join(octets)}.search.msn.com"
    else:
        return f"{'-'.join(octets)}.generic-host.net"


_HTTP_URI_STATUS_CACHE: dict[tuple[str, str], tuple[int, str]] = {}


def _get_http_status(dst_ip: str, uri: str) -> tuple[int, str]:
    """Get a deterministic HTTP status for a (dst_ip, uri) pair.

    Same URI on same server always returns same status (baseline consistency).
    Storyline code can bypass this by setting status_code directly on HttpContext.
    """
    key = (dst_ip, uri)
    if key in _HTTP_URI_STATUS_CACHE:
        return _HTTP_URI_STATUS_CACHE[key]
    roll = random.Random(f"http_status:{dst_ip}:{uri}").random()
    if roll < 0.04:
        result = (404, "Not Found")
    elif roll < 0.06:
        result = (403, "Forbidden")
    elif roll < 0.07:
        result = (500, "Internal Server Error")
    elif roll < 0.17:
        result = (301, "Moved Permanently")
    elif roll < 0.22:
        result = (302, "Found")
    elif roll < 0.30:
        result = (304, "Not Modified")
    else:
        result = (200, "OK")
    _HTTP_URI_STATUS_CACHE[key] = result
    return result


def _is_invalid_network_connection(src_ip: str, dst_ip: str) -> tuple[bool, str]:
    """Validate that a network connection is not fundamentally impossible.

    Checks for addresses that should never appear in generated traffic
    (localhost, link-local, multicast). Same-host connections (src==dst) are
    valid for host-based logs and handled separately via SecurityEvent.local_only.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address

    Returns:
        Tuple of (is_invalid, reason). If is_invalid=True, connection should not be generated.
    """
    # Check for localhost addresses (127.0.0.0/8)
    # Network sensors cannot observe localhost traffic
    if src_ip.startswith("127.") or dst_ip.startswith("127."):
        return True, f"Connection involves localhost address (src={src_ip}, dst={dst_ip})"

    # Check for link-local addresses (169.254.0.0/16)
    # These are auto-configured and typically not routed
    if src_ip.startswith("169.254.") or dst_ip.startswith("169.254."):
        return True, f"Connection involves link-local address (src={src_ip}, dst={dst_ip})"

    # Check for multicast addresses (224.0.0.0/4)
    # These require special handling and shouldn't appear in typical conn logs
    try:
        src_first_octet = int(src_ip.split(".")[0])
        dst_first_octet = int(dst_ip.split(".")[0])
        if src_first_octet >= 224 or dst_first_octet >= 224:
            return (
                True,
                f"Connection involves multicast/reserved address (src={src_ip}, dst={dst_ip})",
            )
    except (ValueError, IndexError):
        # Invalid IP format - let it pass, will be caught by other validation
        pass

    return False, ""
