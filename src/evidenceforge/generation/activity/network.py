"""Network helper functions and data for activity generation.

Provides IP generation, hostname resolution, DNS data, and network validation.
"""

import ipaddress
import random


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC 1918 private address (for Zeek local_orig/local_resp)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# External IPs for network connections (non-RFC1918)
# Phase 5.3: Expanded from 9 to 50+ IPs for destination diversity
EXTERNAL_IPS = {
    'connection_web': [
        # Google
        '172.217.14.206', '142.250.80.46', '142.250.185.206', '142.250.191.46',
        # Cloudflare
        '104.16.132.229', '104.18.32.7', '104.18.25.35', '104.21.67.152',
        # Fastly (Reddit, GitHub Pages, etc.)
        '151.101.1.140', '151.101.65.140', '151.101.129.140', '151.101.193.140',
        # Akamai
        '23.45.67.89', '23.72.134.56', '23.196.25.38', '23.205.100.42',
        # AWS CloudFront
        '52.84.123.45', '54.230.67.89', '54.230.129.180', '13.35.42.100',
        # Azure CDN / Microsoft
        '13.107.42.14', '13.107.213.70', '204.79.197.200', '13.107.246.40',
        # Other popular sites
        '93.184.216.34',     # example.com
        '31.13.65.36',       # facebook.com
        '44.238.149.75',     # stackoverflow.com
        '199.232.64.133',    # npmjs.org
        '185.199.108.153',   # github.io
        '52.85.83.55',       # aws.amazon.com
    ],
    'connection_email': [
        # Office 365
        '52.97.145.162', '52.97.151.18', '52.97.200.30', '52.97.166.42',
        '40.107.22.52', '40.107.22.53',
        # Gmail / Google Workspace
        '209.85.233.27', '209.85.128.25', '74.125.68.27', '74.125.200.27',
        '108.177.96.27', '108.177.97.27',
    ],
    'connection_git': [
        # GitHub
        '140.82.121.3', '140.82.121.4', '140.82.112.22', '140.82.114.3',
        # GitLab
        '104.26.7.33', '172.65.251.78', '104.26.6.33',
        # Bitbucket
        '185.166.143.48', '185.166.143.49',
    ],
    'connection_db': [
        # Internal DB servers (separate subnet to avoid self-connections)
        '10.0.100.10', '10.0.100.11', '10.0.100.12',
    ],
    'connection_saas': [
        # SharePoint / OneDrive
        '13.107.6.156', '13.107.18.10', '52.109.8.20', '52.109.12.22',
        # Azure AD / Entra ID
        '40.126.28.17', '40.126.28.19', '20.190.159.64',
        # Slack
        '34.237.161.42', '52.26.132.56', '54.187.91.57',
        # Zoom
        '3.21.137.128', '3.235.69.6', '18.205.93.88',
        # Salesforce
        '13.108.0.20', '13.110.54.8',
    ],
}

# Per-provider IP groups for DNS multi-answer responses
# Each group contains IPs from the SAME provider so multi-answer
# responses don't mix IPs from different organizations
_PROVIDER_IP_GROUPS = [
    ['172.217.14.206', '142.250.80.46', '142.250.185.206', '142.250.191.46'],  # Google
    ['104.16.132.229', '104.18.32.7', '104.18.25.35', '104.21.67.152'],        # Cloudflare
    ['151.101.1.140', '151.101.65.140', '151.101.129.140', '151.101.193.140'],  # Fastly
    ['23.45.67.89', '23.72.134.56', '23.196.25.38', '23.205.100.42'],          # Akamai
    ['52.84.123.45', '54.230.67.89', '54.230.129.180', '13.35.42.100'],        # AWS CloudFront
    ['13.107.42.14', '13.107.213.70', '204.79.197.200', '13.107.246.40'],      # Microsoft
    ['140.82.121.3', '140.82.121.4', '140.82.112.22', '140.82.114.3'],         # GitHub
    ['52.97.145.162', '52.97.151.18', '52.97.200.30', '52.97.166.42'],         # Office 365
    ['209.85.233.27', '209.85.128.25', '74.125.68.27', '74.125.200.27'],       # Gmail
]

# Reverse DNS mapping: IP -> hostname (for DNS query generation)
REVERSE_DNS: dict[str, str] = {
    # Google
    '172.217.14.206': 'www.google.com', '142.250.80.46': 'accounts.google.com',
    '142.250.185.206': 'drive.google.com', '142.250.191.46': 'calendar.google.com',
    # Cloudflare
    '104.16.132.229': 'www.cloudflare.com', '104.18.32.7': 'dash.cloudflare.com',
    '104.18.25.35': 'api.cloudflare.com', '104.21.67.152': 'blog.cloudflare.com',
    # Fastly
    '151.101.1.140': 'www.reddit.com', '151.101.65.140': 'i.redd.it',
    '151.101.129.140': 'old.reddit.com', '151.101.193.140': 'v.redd.it',
    # Akamai
    '23.45.67.89': 'e13678.dscb.akamaiedge.net', '23.72.134.56': 'static.akamai.net',
    '23.196.25.38': 'download.windowsupdate.com', '23.205.100.42': 'media.akamai.net',
    # AWS
    '52.84.123.45': 'd3c33hcgiwev3.cloudfront.net', '54.230.67.89': 'dph5t2lbz8eri.cloudfront.net',
    '54.230.129.180': 'cdn.jsdelivr.net', '13.35.42.100': 'd1w8cc2yygc27j.cloudfront.net',
    # Microsoft
    '13.107.42.14': 'www.office.com', '13.107.213.70': 'outlook.office365.com',
    '204.79.197.200': 'www.bing.com', '13.107.246.40': 'teams.microsoft.com',
    # Other
    '93.184.216.34': 'www.reuters.com', '31.13.65.36': 'www.facebook.com',
    '44.238.149.75': 'stackoverflow.com', '199.232.64.133': 'registry.npmjs.org',
    '185.199.108.153': 'pages.github.io', '52.85.83.55': 'aws.amazon.com',
    # Email
    '52.97.145.162': 'outlook.office365.com', '52.97.151.18': 'smtp.office365.com',
    '52.97.200.30': 'protection.outlook.com', '52.97.166.42': 'outlook.office.com',
    '40.107.22.52': 'mail.protection.outlook.com', '40.107.22.53': 'mx.office365.com',
    '209.85.233.27': 'smtp.gmail.com', '209.85.128.25': 'imap.gmail.com',
    '74.125.68.27': 'smtp-relay.gmail.com', '74.125.200.27': 'pop.gmail.com',
    '108.177.96.27': 'aspmx.l.google.com', '108.177.97.27': 'alt1.aspmx.l.google.com',
    # Git
    '140.82.121.3': 'github.com', '140.82.121.4': 'api.github.com',
    '140.82.112.22': 'ssh.github.com', '140.82.114.3': 'gist.github.com',
    '104.26.7.33': 'gitlab.com', '172.65.251.78': 'registry.gitlab.com',
    '104.26.6.33': 'api.gitlab.com',
    '185.166.143.48': 'bitbucket.org', '185.166.143.49': 'api.bitbucket.org',
    # SaaS
    '13.107.6.156': 'sharepoint.com', '13.107.18.10': 'onedrive.live.com',
    '52.109.8.20': 'cdn.onenote.net', '52.109.12.22': 'onenote.officeapps.live.com',
    '40.126.28.17': 'login.microsoftonline.com', '40.126.28.19': 'graph.microsoft.com',
    '20.190.159.64': 'login.live.com',
    '34.237.161.42': 'slack.com', '52.26.132.56': 'api.slack.com',
    '54.187.91.57': 'files.slack.com',
    '3.21.137.128': 'zoom.us', '3.235.69.6': 'us02web.zoom.us',
    '18.205.93.88': 'us06web.zoom.us',
    '13.108.0.20': 'login.salesforce.com', '13.110.54.8': 'na139.salesforce.com',
    # Cloud storage (exfiltration targets use real routable IPs)
    '185.26.156.40': 'api.pcloud.com',
    # Internal
    '10.0.100.10': 'db-primary.corp.local', '10.0.100.11': 'db-replica.corp.local',
    '10.0.100.12': 'db-analytics.corp.local',
}

# Cloud/CDN IP ranges for random long-tail destination generation
_CDN_RANGES = [
    (13, 32), (13, 35), (13, 107), (13, 108), (13, 110),    # Azure / Salesforce
    (52, 84), (52, 85), (54, 230), (54, 187),                # AWS CloudFront
    (104, 16), (104, 18), (104, 21), (104, 26),              # Cloudflare
    (142, 250), (172, 217), (172, 253),                       # Google
    (23, 45), (23, 72), (23, 196), (23, 205),                # Akamai
    (151, 101), (199, 232),                                    # Fastly
]

# IPv6 addresses for known services (used by AAAA queries)
_IPV6_MAP: dict[str, str] = {
    '172.217.14.206': '2607:f8b0:4004:800::200e',
    '142.250.80.46': '2607:f8b0:4004:806::200e',
    '142.250.185.206': '2607:f8b0:4004:803::200e',
    '142.250.191.46': '2607:f8b0:4004:810::200e',
    '13.107.42.14': '2620:1ec:c11::14',
    '13.107.213.70': '2620:1ec:a92::70',
    '204.79.197.200': '2620:1ec:c11::200',
    '13.107.246.40': '2620:1ec:46::40',
    '140.82.121.3': '2606:50c0:8000::153',
    '140.82.121.4': '2606:50c0:8001::154',
    '31.13.65.36': '2a03:2880:f12f:83:face:b00c:0:25de',
    '104.16.132.229': '2606:4700::6810:84e5',
    '151.101.1.140': '2a04:4e42::396',
    '93.184.216.34': '2606:2800:220:1:248:1893:25c8:1946',
}

# AD SRV record templates for domain service discovery
_AD_SRV_QUERIES = [
    '_ldap._tcp.dc._msdcs.{domain}',
    '_kerberos._tcp.{domain}',
    '_kerberos._tcp.dc._msdcs.{domain}',
    '_ldap._tcp.{domain}',
    '_gc._tcp.{domain}',
    '_kpasswd._tcp.{domain}',
]

# SRV query -> port mapping
_SRV_PORT_MAP = {
    '_ldap': 389,
    '_gc': 3268,
    '_kerberos': 88,
    '_kpasswd': 464,
}


def _ipv4_to_fake_ipv6(ipv4: str) -> str:
    """Generate a deterministic plausible IPv6 address from an IPv4 address.

    Uses diverse prefixes from real providers based on the first octet.
    """
    octets = ipv4.split('.')
    o0, o1, o2, o3 = int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3])
    # Select prefix based on first octet range to simulate different providers
    prefixes = {
        (13, 13): '2620:1ec',    # Microsoft Azure
        (23, 23): '2a02:26f0',   # Akamai
        (52, 54): '2600:1f18',   # AWS
        (104, 104): '2606:4700', # Cloudflare
        (142, 142): '2607:f8b0', # Google
        (151, 151): '2a04:4e42', # Fastly
        (172, 172): '2607:f8b0', # Google
    }
    # Private IPs get ULA prefix (fd00::/8), not documentation 2001:db8::/32
    if o0 == 10 or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168):
        return f"fd00:{o1:02x}{o2:02x}:{o3:04x}::1"

    prefix = '2a00:1450'  # default (generic, not documentation)
    for (lo, hi), pfx in prefixes.items():
        if lo <= o0 <= hi:
            prefix = pfx
            break
    return f"{prefix}:{o1:02x}{o2:02x}:{o3:04x}::1"


def _generate_random_external_ip(rng) -> str:
    """Generate a random plausible external IP from common cloud/CDN ranges."""
    prefix = rng.choice(_CDN_RANGES)
    return f"{prefix[0]}.{prefix[1]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _generate_internal_hostname(rng, ip: str, domain: str = 'corp.local') -> str:
    """Generate a plausible internal hostname for RFC 1918 IPs.

    Deterministic based on IP so the same IP always gets the same hostname
    (avoids multiple different hostnames resolving to the same IP).
    """
    prefixes = ['srv', 'app', 'db', 'web', 'print', 'nas', 'mgmt', 'mon', 'backup']
    suffixes = ['01', '02', '03', '04', '05']
    # Deterministic selection based on IP hash
    ip_hash = hash(ip)
    prefix = prefixes[ip_hash % len(prefixes)]
    suffix = suffixes[(ip_hash >> 8) % len(suffixes)]
    return f"{prefix}-{suffix}.{domain}"


def _detect_ip_provider(ip: str) -> str:
    """Detect the cloud/CDN provider for an IP based on first-octet ranges."""
    first = int(ip.split('.')[0])
    if first in (172, 142, 209, 74, 108):
        return 'google'
    if first in (140, 185) and ip.startswith('140.82.'):
        return 'github'
    if first in (151,):
        return 'fastly'
    if first in (23,):
        return 'akamai'
    if first in (52, 54, 3, 18, 44, 34):
        return 'aws'
    if first in (13, 20, 40, 204) and not ip.startswith('13.108.'):
        return 'microsoft'
    if first in (104,) and ip.startswith('104.16.') or ip.startswith('104.18.') or ip.startswith('104.21.') or ip.startswith('104.26.'):
        return 'cloudflare'
    return 'generic'


def _generate_random_hostname(rng, ip: str) -> str:
    """Generate a provider-aware hostname matching the IP's cloud/CDN provider.

    Ensures the hostname pattern is coherent with the IP range -- no Google
    hostnames for AWS IPs or vice versa.
    """
    octets = ip.split('.')
    provider = _detect_ip_provider(ip)

    if provider == 'google':
        return rng.choice([
            f"{'-'.join(octets)}.bc.googleusercontent.com",
            f"lax17s{rng.randint(10,99)}-in-f{octets[3]}.1e100.net",
        ])
    elif provider == 'aws':
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        cf_chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        return rng.choice([
            f"ec2-{'-'.join(octets)}.{rng.choice(regions)}.compute.amazonaws.com",
            f"d{''.join(rng.choices(cf_chars, k=13))}.cloudfront.net",
            f"server-{'-'.join(octets)}.iad89.r.cloudfront.net",
        ])
    elif provider == 'akamai':
        return f"a{'-'.join(octets)}.deploy.static.akamaitechnologies.com"
    elif provider == 'cloudflare':
        return f"{'-'.join(octets)}.cdn.cloudflare.net"
    elif provider == 'github':
        return f"lb-{'-'.join(octets)}-iad.github.com"
    elif provider == 'fastly':
        return f"{'-'.join(octets)}.{'fastly' if rng.random() < 0.5 else 'global.ssl.fastly'}.net"
    elif provider == 'microsoft':
        return f"{'-'.join(octets)}.microsoft.com"
    else:
        return f"host-{'-'.join(octets)}.cdn-provider.net"


def _generate_rdns_name(rng, ip: str) -> str:
    """Generate a realistic reverse DNS name for an IP (for PTR query answers).

    rDNS names differ from forward hostnames -- they typically embed the IP
    octets and use provider-specific naming conventions.
    """
    octets = ip.split('.')
    provider = _detect_ip_provider(ip)

    if provider == 'google':
        # Google rDNS: {region}s{NN}-in-f{last_octet}.1e100.net
        regions = ['lax17', 'sfo07', 'dfw25', 'iad30', 'ord37']
        return f"{rng.choice(regions)}s{rng.randint(10,99)}-in-f{octets[3]}.1e100.net"
    elif provider == 'aws':
        regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        return rng.choice([
            f"ec2-{'-'.join(octets)}.{rng.choice(regions)}.compute.amazonaws.com",
            f"server-{'-'.join(octets)}.iad89.r.cloudfront.net",
        ])
    elif provider == 'akamai':
        return f"a{octets[1]}-{octets[2]}-{octets[3]}.deploy.static.akamaitechnologies.com"
    elif provider == 'cloudflare':
        return f"{'-'.join(octets)}.cdn.cloudflare.net"
    elif provider == 'github':
        return f"lb-{'-'.join(octets)}-iad.github.com"
    elif provider == 'fastly':
        return f"{'-'.join(octets)}.fastly.net"
    elif provider == 'microsoft':
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
        result = (404, 'Not Found')
    elif roll < 0.06:
        result = (403, 'Forbidden')
    elif roll < 0.07:
        result = (500, 'Internal Server Error')
    elif roll < 0.17:
        result = (301, 'Moved Permanently')
    elif roll < 0.22:
        result = (302, 'Found')
    elif roll < 0.30:
        result = (304, 'Not Modified')
    else:
        result = (200, 'OK')
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
    if src_ip.startswith('127.') or dst_ip.startswith('127.'):
        return True, f"Connection involves localhost address (src={src_ip}, dst={dst_ip})"

    # Check for link-local addresses (169.254.0.0/16)
    # These are auto-configured and typically not routed
    if src_ip.startswith('169.254.') or dst_ip.startswith('169.254.'):
        return True, f"Connection involves link-local address (src={src_ip}, dst={dst_ip})"

    # Check for multicast addresses (224.0.0.0/4)
    # These require special handling and shouldn't appear in typical conn logs
    try:
        src_first_octet = int(src_ip.split('.')[0])
        dst_first_octet = int(dst_ip.split('.')[0])
        if src_first_octet >= 224 or dst_first_octet >= 224:
            return True, f"Connection involves multicast/reserved address (src={src_ip}, dst={dst_ip})"
    except (ValueError, IndexError):
        # Invalid IP format - let it pass, will be caught by other validation
        pass

    return False, ""
