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

"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import logging
import math
import random
import uuid
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any, Optional

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    EdrContext,
    FileContext,
    FirewallContext,
    HostContext,
    HttpContext,
    IdsContext,
    KerberosContext,
    ProxyContext,
    RegistryContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent
from evidenceforge.generation.causal.engine import CausalExpansionEngine, ExpansionContext
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed

from .helpers import _get_os_category, _get_rng, _parameterize_command
from .network import (
    _AD_SRV_QUERIES,
    _IPV6_MAP,
    _SRV_PORT_MAP,
    EXTERNAL_IPS,
    REVERSE_DNS,
    _generate_internal_hostname,
    _generate_random_hostname,
    _generate_rdns_name,
    _get_http_status,
    _ipv4_to_fake_ipv6,
    _is_invalid_network_connection,
    _is_private_ip,
)

logger = logging.getLogger(__name__)


def _session_started_by(session: Any, time: datetime) -> bool:
    """Return whether a session exists at the given activity time."""
    session_start = session.start_time
    if session_start.tzinfo is None:
        session_start = session_start.replace(tzinfo=UTC)
    else:
        session_start = session_start.astimezone(UTC)
    activity_time = time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)
    return session_start <= activity_time


# Fixed baseline activity patterns (no LLM expansion)
# Format: (activity_type, probability)
# Phase 5.6: Widened probability gaps for user diversity scoring
BASELINE_PATTERNS = {
    "developer": [
        ("logon", 0.7),
        ("process_code", 0.75),  # Dominant: code editors
        ("connection_git", 0.5),  # Heavy git usage
        ("process_build", 0.45),  # Frequent builds
        ("process_user_apps", 0.15),  # Minimal app usage
    ],
    "executive": [
        ("logon", 0.9),
        ("connection_web", 0.8),  # Dominant: browsing
        ("connection_email", 0.75),  # Heavy email
        ("process_user_apps", 0.7),  # Heavy Office/apps
    ],
    "analyst": [
        ("logon", 0.85),
        ("process_query", 0.7),  # Dominant: database queries
        ("connection_db", 0.6),  # Heavy DB connections
        ("process_user_apps", 0.45),  # Moderate apps (Excel, etc.)
    ],
    "sysadmin": [
        ("logon", 0.9),
        ("process_system", 0.65),  # Dominant: system tools
        ("process_code", 0.35),
        ("process_query", 0.3),
        ("connection_web", 0.2),
        ("process_user_apps", 0.1),  # Minimal app usage
    ],
    "default": [
        ("logon", 0.75),
        ("connection_web", 0.5),
        ("process_user_apps", 0.35),
    ],
}

# Organic bash commands for noise injection between storyline events
# and baseline Linux user activity. Common admin/orientation commands.
# Process names and command lines for baseline activities (Windows)
PROCESS_TEMPLATES = {
    "process_code": [
        ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe --folder-uri {project_path}"),
        (
            "C:\\Program Files (x86)\\Notepad++\\notepad++.exe",
            "notepad++ {source_file}",
        ),
        ("C:\\Program Files\\JetBrains\\IntelliJ IDEA\\bin\\idea64.exe", "idea64.exe"),
        (
            "C:\\Program Files\\Sublime Text\\sublime_text.exe",
            "sublime_text.exe {source_file}",
        ),
    ],
    "process_build": [
        (
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
            "MSBuild.exe {solution_name} /t:Build /p:Configuration={build_config}",
        ),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c npm run {npm_script}"),
        (
            "C:\\Program Files\\dotnet\\dotnet.exe",
            "dotnet.exe build -c {build_config}",
        ),
        ("C:\\Program Files\\nodejs\\node.exe", "node.exe scripts/build.js"),
    ],
    "process_query": [
        (
            "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
            'sqlcmd.exe -S {db_server} -Q "{sql_query}"',
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            'powershell.exe -Command "{ps_command}"',
        ),
        (
            "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
            'sqlcmd.exe -S {db_server} -d {db_name} -Q "{sql_query}"',
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -ExecutionPolicy Bypass -File {ps_script}",
        ),
        ("C:\\Windows\\System32\\wbem\\WMIC.exe", "WMIC.exe {wmic_query}"),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            'powershell.exe -Command "{ps_command}"',
        ),
    ],
    "process_user_apps": [
        # Index 0: Chrome main process (child renderers spawned separately)
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
        # Index 1: Firefox main process (child content procs spawned separately)
        ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe"),
        # Index 2: Outlook
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
        # Index 3: Word
        (
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            'WINWORD.EXE /n "{doc_path}"',
        ),
        # Index 4: Excel
        (
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
            'EXCEL.EXE "{spreadsheet_path}"',
        ),
        # Index 5: Edge main process (child renderers spawned separately)
        ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe"),
        # Index 6: Teams main process (utility procs spawned separately)
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "Teams.exe",
        ),
        # Index 7: OneDrive main process (background proc spawned separately)
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "OneDrive.exe",
        ),
        # Index 8: Acrobat
        ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Acrobat.exe"),
        # Index 9: 7-Zip
        ("C:\\Program Files\\7-Zip\\7zFM.exe", "7zFM.exe"),
    ],
    "process_system": [
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
        (
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog",
        ),
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k DcomLaunch -p"),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe"),
        (
            "C:\\Windows\\System32\\RuntimeBroker.exe",
            "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        ),
        (
            "C:\\Windows\\System32\\SearchIndexer.exe",
            "C:\\Windows\\System32\\SearchIndexer.exe /Embedding",
        ),
        ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
        ("C:\\Windows\\System32\\conhost.exe", "conhost.exe 0x4"),
        (
            "C:\\Windows\\System32\\dllhost.exe",
            "dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
        ),
        ("C:\\Windows\\System32\\sihost.exe", "sihost.exe"),
    ],
}

# Process names and command lines for baseline activities (Linux) - Phase 2.10
PROCESS_TEMPLATES_LINUX = {
    "process_code": [
        ("/usr/bin/vim", "vim {linux_project}/{linux_source_file}"),
        ("/usr/bin/nano", "nano {linux_project}/{linux_source_file}"),
        ("/usr/bin/code", "code --no-sandbox {linux_project}"),
        ("/usr/bin/emacs", "emacs -nw {linux_project}/{linux_source_file}"),
    ],
    "process_build": [
        ("/usr/bin/make", "make -j4 -C {linux_project}"),
        ("/usr/bin/gcc", "gcc -o output {linux_source_file}"),
        ("/usr/bin/npm", "npm run {npm_script}"),
        ("/usr/bin/cargo", "cargo build --release"),
        ("/usr/bin/python3", "python3 -m pip install -e {linux_project}"),
    ],
    "process_query": [
        ("/usr/bin/mysql", "mysql -u root -p {mysql_db}"),
        ("/usr/bin/psql", "psql -U postgres -d {psql_db}"),
        ("/usr/bin/redis-cli", "{redis_cmd}"),
    ],
    "process_user_apps": [
        ("/usr/bin/firefox", "firefox --new-tab {internal_url}"),
        ("/usr/bin/thunderbird", "thunderbird"),
        ("/usr/bin/git", "git pull origin {git_branch}"),
        ("/usr/bin/docker", "docker ps"),
        ("/usr/bin/python3", "python3 -m pytest tests/"),
        ("/usr/bin/ssh", "ssh {username}@remote-host"),
        ("/usr/bin/curl", "curl -s https://api.example.com/status"),
        ("/usr/bin/kubectl", "kubectl get pods -n production"),
    ],
    "process_system": [
        ("/usr/lib/systemd/systemd", "systemd --user"),
        ("/usr/sbin/cron", "/usr/sbin/cron -f"),
        ("/usr/sbin/sshd", "/usr/sbin/sshd -D"),
        ("/usr/sbin/rsyslogd", "/usr/sbin/rsyslogd -n"),
        ("/usr/sbin/NetworkManager", "/usr/sbin/NetworkManager --no-daemon"),
        ("/usr/bin/dbus-daemon", "dbus-daemon --system --address=systemd:"),
        ("/usr/sbin/atd", "/usr/sbin/atd -f"),
    ],
}

# Per-persona process type weights (Phase 5.1)
# Maps persona name to relative probability of each process template category
PERSONA_PROCESS_WEIGHTS = {
    "developer": {
        "process_code": 0.5,
        "process_build": 0.3,
        "process_user_apps": 0.15,
        "process_system": 0.05,
    },
    "executive": {
        "process_code": 0.05,
        "process_build": 0.0,
        "process_user_apps": 0.8,
        "process_system": 0.15,
    },
    "analyst": {
        "process_code": 0.1,
        "process_build": 0.05,
        "process_query": 0.5,
        "process_user_apps": 0.3,
        "process_system": 0.05,
    },
    "sysadmin": {
        "process_code": 0.2,
        "process_build": 0.1,
        "process_query": 0.2,
        "process_user_apps": 0.1,
        "process_system": 0.4,
    },
    "default": {
        "process_code": 0.15,
        "process_build": 0.05,
        "process_user_apps": 0.6,
        "process_system": 0.2,
    },
}

# Per-persona app subsets for process_user_apps (Phase 5.6: user diversity)
# Each persona favors a different mix of applications from PROCESS_TEMPLATES['process_user_apps']
# Index references into PROCESS_TEMPLATES['process_user_apps']:
#   0=Chrome, 1=Firefox, 2=Outlook, 3=Word, 4=Excel, 5=Edge, 6=Teams, 7=OneDrive, 8=Acrobat, 9=7-Zip
PERSONA_APP_INDICES = {
    "developer": [0, 6, 7, 9],  # Chrome, Teams, OneDrive, 7-Zip
    "executive": [2, 3, 5, 6, 8],  # Outlook, Word, Edge, Teams, Acrobat
    "analyst": [0, 4, 2, 6, 8],  # Chrome, Excel, Outlook, Teams, Acrobat
    "sysadmin": [1, 5, 6, 9],  # Firefox, Edge, Teams, 7-Zip
    "default": [0, 2, 6, 7],  # Chrome, Outlook, Teams, OneDrive
}

# Per-persona app subsets for Linux process_user_apps
# Index references into PROCESS_TEMPLATES_LINUX['process_user_apps']:
#   0=firefox, 1=thunderbird, 2=git, 3=docker, 4=pytest, 5=ssh, 6=curl, 7=kubectl
PERSONA_APP_INDICES_LINUX = {
    "developer": [0, 2, 3, 4, 6],  # firefox, git, docker, pytest, curl
    "executive": [0, 1],  # firefox, thunderbird
    "analyst": [0, 5, 6],  # firefox, ssh, curl
    "sysadmin": [2, 3, 5, 6, 7],  # git, docker, ssh, curl, kubectl
    "default": [0, 2, 5, 6],  # firefox, git, ssh, curl
}

# Zeek TCP connection state distribution with matching history strings
# Format: (conn_state, weight, history_string)
# Rebalanced: SF ~62% (real enterprise: 55-75%), non-SF states expanded
TCP_CONN_STATE_DISTRIBUTION = [
    # Normal completions (SF) — ~62% total (real: 55-75%)
    ("SF", 21, "ShADadfF"),  # Standard: SYN→SYN-ACK→data→FIN
    ("SF", 11, "ShADaDadfF"),  # Multiple data exchanges before FIN
    ("SF", 6, "ShADadTtFf"),  # Normal with retransmissions (T=orig retx, t=resp retx)
    ("SF", 5, "ShADadfFa"),  # FIN-ACK with trailing ACK
    ("SF", 5, "ShADaDaDadfF"),  # Bulk transfer (many data rounds)
    ("SF", 4, "ShADadFf"),  # Originator FIN first (client closes)
    ("SF", 4, "ShADaDadfFa"),  # Multi-exchange with trailing ACK
    ("SF", 3, "ShADadTFf"),  # Retransmit then FIN
    ("SF", 2, "ShADaDadFf"),  # Multi data then client closes
    ("SF", 1, "ShADaDaTtdfF"),  # Multi data with retransmissions
    # Connection attempts (S0) — ~14% (timeouts, unreachable hosts, scanning)
    ("S0", 9, "S"),  # Single SYN, no reply
    ("S0", 5, "S"),  # SYN retransmit (Zeek deduplicates to single 'S')
    # Partial handshakes (S1) — ~3%
    ("S1", 2, "ShR"),  # SYN-ACK seen, RST
    ("S1", 1, "Sh"),  # SYN-ACK seen, no further data
    # Rejected connections (REJ) — ~5% (refused ports, firewall rejects)
    ("REJ", 3, "Sr"),  # RST from responder immediately
    ("REJ", 2, "Srr"),  # Multiple RSTs from responder
    # Reset by originator (RSTO) — ~8% (client aborts, load balancer health checks)
    ("RSTO", 4, "ShADaR"),  # Data exchange then originator RST
    ("RSTO", 2, "ShADadTR"),  # Data + retransmit then RST
    ("RSTO", 2, "ShAR"),  # Quick RST after handshake
    # Reset by responder (RSTR) — ~5% (server resets, IDS/WAF termination)
    ("RSTR", 3, "ShADadR"),  # Data exchange then responder RST
    ("RSTR", 2, "ShAdR"),  # Partial data then responder RST
    # Half-closed states — ~2% (one side closed, other didn't respond)
    ("S2", 1, "ShADadF"),  # Orig sent FIN, responder never replied
    ("S3", 1, "ShADadf"),  # Resp sent FIN, originator never replied
    # Midstream (OTH) — ~1% (partial captures, NAT state loss)
    ("OTH", 1, "Cc"),  # Midstream traffic (no SYN/SYN-ACK seen)
]

# Zeek UDP connection state distribution
# UDP has no TCP handshake — only D/d datagram flags
# Rebalanced: SF ~72% (more S0 timeouts for realistic DNS/NTP failures)
UDP_CONN_STATE_DISTRIBUTION = [
    ("SF", 55, "Dd"),  # Normal bidirectional exchange (query + response)
    ("SF", 8, "DdDd"),  # Multi-packet exchange
    ("SF", 5, "DdDdDd"),  # Extended multi-packet exchange
    ("SF", 4, "DdA"),  # Additional acknowledgment packet
    ("S0", 12, "D"),  # Originator only, no response (timeout)
    ("S0", 6, "DD"),  # Retransmitted datagram, no response
    ("OTH", 6, "Dd"),  # Midstream UDP exchange
    ("OTH", 4, "DdDdA"),  # Midstream multi-packet with ACK
]

# Pre-extract for random.choices — TCP (select full tuples, not just states)
_TCP_CONN_ENTRIES = TCP_CONN_STATE_DISTRIBUTION
_TCP_CONN_WEIGHTS = [s[1] for s in TCP_CONN_STATE_DISTRIBUTION]

# Pre-extract for random.choices — UDP
_UDP_CONN_ENTRIES = UDP_CONN_STATE_DISTRIBUTION
_UDP_CONN_WEIGHTS = [s[1] for s in UDP_CONN_STATE_DISTRIBUTION]

# Legacy aliases for backward compatibility
CONN_STATE_DISTRIBUTION = TCP_CONN_STATE_DISTRIBUTION
_CONN_STATES = [s[0] for s in TCP_CONN_STATE_DISTRIBUTION]
_CONN_WEIGHTS = _TCP_CONN_WEIGHTS
_CONN_HISTORY = {s[0]: s[2] for s in TCP_CONN_STATE_DISTRIBUTION}

# --- Network realism constants ---

# UDP header overhead: standard (93%), VLAN-tagged (5%), tunneled (2%)
_UDP_OVERHEAD_VALUES = (28, 32, 52, 60, 78)
_UDP_OVERHEAD_WEIGHTS = (93, 5, 1, 0.5, 0.5)

# TCP header overhead: bimodal around 40/52/60
# 40=no options (legacy), 52=timestamps (dominant), 60=SACK+ts, 64=full
_TCP_OVERHEAD_VALUES = (40, 52, 60, 64)
_TCP_OVERHEAD_WEIGHTS = (10, 75, 10, 5)

# NTP stratum-based timing: (mean_ms, sigma) for lognormal
_NTP_STRATUM_TIMING = {
    1: (2.0, 0.5),  # GPS-connected
    2: (10.0, 0.7),  # synced to stratum 1
    3: (30.0, 0.8),  # synced to stratum 2
}

# TLS cipher distributions (weighted)
_TLS_VERSION_VALUES = ("TLSv12", "TLSv13")
_TLS_VERSION_WEIGHTS = (45, 55)

_TLS12_CIPHER_DIST = (
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 60),
    ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 25),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 10),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 5),
)
_TLS12_CIPHER_VALUES = tuple(c[0] for c in _TLS12_CIPHER_DIST)
_TLS12_CIPHER_WEIGHTS = tuple(c[1] for c in _TLS12_CIPHER_DIST)

_TLS13_CIPHER_DIST = (
    ("TLS_AES_128_GCM_SHA256", 55),
    ("TLS_AES_256_GCM_SHA384", 30),
    ("TLS_CHACHA20_POLY1305_SHA256", 15),
)
_TLS13_CIPHER_VALUES = tuple(c[0] for c in _TLS13_CIPHER_DIST)
_TLS13_CIPHER_WEIGHTS = tuple(c[1] for c in _TLS13_CIPHER_DIST)

# SSL history patterns (weighted)
_SSL_HISTORY_SUCCESS = (
    ("CsiI", 55),  # normal full handshake
    ("CsijI", 25),  # handshake with session ticket
    ("CiI", 10),  # abbreviated/resumed
    ("CsiIa", 3),  # established then client abort
    ("CsI", 2),  # no server key exchange
)
_SSL_HIST_SUCCESS_VALUES = tuple(h[0] for h in _SSL_HISTORY_SUCCESS)
_SSL_HIST_SUCCESS_WEIGHTS = tuple(h[1] for h in _SSL_HISTORY_SUCCESS)

_SSL_HISTORY_FAILURE = (
    ("Cs", 60),  # client hello only, server didn't complete
    ("Ch", 40),  # client hello, no server response
)
_SSL_HIST_FAILURE_VALUES = tuple(h[0] for h in _SSL_HISTORY_FAILURE)
_SSL_HIST_FAILURE_WEIGHTS = tuple(h[1] for h in _SSL_HISTORY_FAILURE)

_SSL_FAILURE_RATE = 0.02  # ~2% handshake failure

# Proxy header overhead ranges (bytes)
_PROXY_CS_OVERHEAD = (80, 350)  # Via, X-Forwarded-For, etc.
_PROXY_SC_OVERHEAD = (50, 250)  # Via, X-Cache, Age, etc.
_EXPLICIT_PROXY_TUNNEL_TIMEOUT_S = 300

# Kerberos TGS service name distribution (weighted)
_KERBEROS_SVC_DIST = (
    ("cifs/{hostname}", 45),  # file share access dominates
    ("host/{hostname}", 20),  # generic host service
    ("http/{hostname}", 15),  # web services
    ("ldap/{hostname}", 10),  # directory queries
    ("krbtgt/{domain}", 5),  # TGT renewals
    ("DNS/{hostname}", 5),  # DNS service tickets
)
_KERBEROS_SVC_VALUES = tuple(s[0] for s in _KERBEROS_SVC_DIST)
_KERBEROS_SVC_WEIGHTS = tuple(s[1] for s in _KERBEROS_SVC_DIST)


def _ephemeral_port(rng: random.Random, os_category: str = "windows") -> int:
    """Generate a random ephemeral port appropriate for the OS.

    Linux uses 32768-60999 (net.ipv4.ip_local_port_range default).
    Windows uses 49152-65535 (IANA dynamic port range).
    """
    if os_category == "linux":
        return rng.randint(32768, 60999)
    return rng.randint(49152, 65535)


def _dns_rtt(rng: random.Random, resolver_ip: str | None = None) -> float:
    """Generate a realistic DNS round-trip time using a mixture model.

    Models real DNS traffic distribution:
    - Internal resolvers: cache/local responses can be sub-ms
    - Public resolvers: LAN-to-resolver RTT should rarely be sub-ms

    Returns:
        RTT in seconds.
    """
    if resolver_ip and not _is_private_ip(resolver_ip):
        roll = rng.random()
        if roll < 0.08:
            return rng.uniform(0.002, 0.008)  # Very close public resolver / warmed path
        if roll < 0.70:
            return rng.uniform(0.008, 0.035)  # Common enterprise egress latency
        if roll < 0.95:
            return rng.uniform(0.035, 0.120)  # Recursive/cache miss or distance
        return rng.uniform(0.120, 0.350)  # Slow/distant resolver response

    roll = rng.random()
    if roll < 0.60:
        return rng.uniform(0.0001, 0.001)  # Cache hit: 0.1-1ms
    elif roll < 0.85:
        return rng.uniform(0.001, 0.010)  # Local resolver: 1-10ms
    elif roll < 0.97:
        return rng.uniform(0.010, 0.080)  # Recursive lookup: 10-80ms
    else:
        return rng.uniform(0.080, 0.250)  # Slow/distant: 80-250ms


def _dns_registrable_domain(hostname: str) -> str:
    """Return a practical DNS owner name for mail/TXT companion lookups."""
    parts = [part for part in hostname.rstrip(".").split(".") if part]
    if len(parts) <= 2:
        return hostname.rstrip(".")
    return ".".join(parts[-2:])


def _dns_txt_query_and_answer(rng: random.Random, hostname: str) -> tuple[str, str]:
    """Build a plausible TXT lookup for mail/authentication background noise."""
    domain = _dns_registrable_domain(hostname)
    roll = rng.random()
    if roll < 0.45:
        return domain, f"v=spf1 include:_spf.{domain} ~all"
    if roll < 0.75:
        return f"_dmarc.{domain}", f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
    selector = rng.choice(["selector1", "selector2", "google", "k1"])
    return f"{selector}._domainkey.{domain}", "v=DKIM1; k=rsa; p=MIIBIjANBgkqh"


def _dns_hostname_allows_mx(hostname: str) -> bool:
    """Return whether a hostname is plausible owner context for MX lookups."""
    lowered = hostname.lower().rstrip(".")
    cdn_suffixes = (
        "cloudfront.net",
        "akamaiedge.net",
        "akamaitechnologies.com",
        "fastly.net",
        "global.ssl.fastly.net",
        "cdn.cloudflare.net",
    )
    if lowered.endswith(cdn_suffixes):
        return False
    service_labels = {"cdn", "static", "assets", "media", "img", "js", "css"}
    return lowered.split(".", 1)[0] not in service_labels


def _linux_uid_for_user(username: str) -> int:
    """Return a stable plausible Linux UID for a login username."""
    if username == "root":
        return 0
    well_known = {
        "ubuntu": 1000,
        "ec2-user": 1000,
        "admin": 1001,
        "ansible": 998,
        "deploy": 1002,
    }
    if username in well_known:
        return well_known[username]
    return 1000 + (_stable_seed(f"linux_uid_{username}") % 5000)


def _dns_base_ttl(query: str, is_internal: bool) -> int:
    """Return a stable authoritative TTL for a DNS query name."""
    domain_seed = random.Random(_stable_seed(f"dns_ttl_{query}"))
    if is_internal:
        return domain_seed.choice([300, 600, 1800, 3600, 7200, 86400])
    return domain_seed.choice([30, 60, 120, 300, 600, 1800, 3600])


def _dns_is_internal_name(query: str, ad_domain: str) -> bool:
    """Return whether a DNS query belongs to the scenario's internal namespace."""
    lowered = query.rstrip(".").lower()
    domain = ad_domain.rstrip(".").lower()
    return lowered.endswith(f".{domain}") or lowered == domain or lowered.endswith(".local")


def _tls_san_dns_names(cert_name: str) -> list[str]:
    """Build DNS SANs without wildcarding public suffixes."""
    from evidenceforge.generation.activity.tls_realism import multi_label_public_suffixes

    try:
        import ipaddress as _ipa

        _ipa.ip_address(cert_name)
        return []
    except ValueError:
        pass

    labels = [part for part in cert_name.rstrip(".").split(".") if part]
    if len(labels) < 2:
        return [cert_name]
    parent = ".".join(labels[1:])
    if len(labels) == 2 or parent in multi_label_public_suffixes():
        wildcard_base = cert_name
    else:
        wildcard_base = parent
    return [cert_name, f"*.{wildcard_base}"]


def _ocsp_status_for_certificate(cert_name: str, serial_number: str) -> str:
    """Pick a stable mostly-good OCSP status per certificate identity."""
    from evidenceforge.generation.activity.tls_realism import ocsp_config

    weights = ocsp_config().get("status_weights", {"good": 90, "unknown": 7, "revoked": 3})
    ordered = ("good", "unknown", "revoked")
    total = sum(max(0, int(weights.get(status, 0))) for status in ordered)
    if total <= 0:
        return "good"
    bucket = _stable_seed(f"ocsp_status:{cert_name}:{serial_number}") % total
    cumulative = 0
    for status in ordered:
        cumulative += max(0, int(weights.get(status, 0)))
        if bucket < cumulative:
            return status
    return "good"


class ActivityGenerator:
    """Generates specific activity events using StateManager and emitters.

    Coordinates event generation across multiple log formats to maintain
    cross-log consistency (LogonIDs, PIDs, timestamps, etc.).

    Attributes:
        state_manager: StateManager instance for state tracking
        emitters: Dict mapping format name to emitter instance
        event_record_counter: Counter for Windows EventRecordID generation
    """

    def __init__(
        self,
        state_manager: StateManager,
        emitters: dict[str, WindowsEventEmitter | ZeekEmitter],
        event_record_counter: int = 10000,
        network_visibility=None,
        sid_registry: dict[str, str] | None = None,
        dispatcher: EventDispatcher | None = None,
        causal_engine: CausalExpansionEngine | None = None,
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
            network_visibility: Optional NetworkVisibilityEngine for sensor-based filtering
            sid_registry: Optional dict mapping usernames to Windows SIDs
            dispatcher: Optional EventDispatcher for canonical event model (Phase 7)
            causal_engine: Optional CausalExpansionEngine for auto-generating
                prerequisite events (DNS before connections, Kerberos before
                logons, etc.)
        """
        self.state_manager = state_manager
        if dispatcher is None and emitters:
            # Auto-create dispatcher for backward compat with tests
            dispatcher = EventDispatcher(
                state_manager=state_manager,
                emitters=emitters,
            )
        self.dispatcher = dispatcher
        self._event_record_counters: dict[str, int] = {}
        self._counter_lock = Lock()  # Thread-safe counter for EventRecordID
        self.sid_registry = sid_registry or {}

        # IP→System lookup for HostContext resolution on connection events
        self._ip_to_system: dict[str, Any] = {}

        # Process tree tracking: recent user processes per (hostname, username)
        # Used by _select_parent_pid() for realistic parent-child relationships
        self._user_process_history: dict[tuple[str, str], list[tuple[int, str]]] = {}

        # Network visibility stored on dispatcher; keep local ref for fast-path check
        self._network_visibility = network_visibility
        self._proxy_mode = "transparent"
        self._proxy_listener_port = 8080
        self._explicit_proxy_tunnels: dict[
            tuple[str, str, str, str, int], tuple[datetime, str]
        ] = {}
        self._recent_connection_tuples: dict[tuple[str, int, str, int, str], float] = {}
        self._dns_cache: dict[tuple[str, str, str], float] = {}
        self._dns_cache_last_prune = 0.0
        self._tls_seen_server_names: set[str] = set()
        self._tls_cert_validity: dict[str, tuple[int, int]] = {}
        self._tls_ocsp_windows: dict[tuple[str, str, int], tuple[int, int]] = {}

        # Causal expansion engine (auto-created if not provided) and recursion guard
        self._causal_engine = causal_engine or CausalExpansionEngine()
        self._expanding_types: set[str] = set()

    def _build_host_context(self, system: System) -> HostContext:
        """Build a HostContext from a System model object.

        Precomputes FQDN and NetBIOS domain so render methods don't have to.
        """
        ad_domain = getattr(self, "_ad_domain", "")
        hostname = system.hostname
        return HostContext(
            hostname=hostname,
            ip=system.ip,
            os=system.os,
            os_category=_get_os_category(system.os),
            system_type=system.type,
            domain=ad_domain,
            fqdn=f"{hostname}.{ad_domain}" if ad_domain else hostname,
            netbios_domain=ad_domain.split(".")[0].upper() if ad_domain else "CORP",
            roles=list(system.roles),
        )

    def _remember_connection_tuple(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
    ) -> None:
        """Track recently allocated 5-tuples to avoid synthetic exact repeats."""
        if proto == "icmp":
            return
        ts_epoch = time.timestamp()
        if len(self._recent_connection_tuples) > 100_000:
            cutoff = ts_epoch - 86_400
            self._recent_connection_tuples = {
                key: seen_at
                for key, seen_at in self._recent_connection_tuples.items()
                if seen_at >= cutoff
            }
        self._recent_connection_tuples[(src_ip, src_port, dst_ip, dst_port, proto)] = ts_epoch

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Allocate an ephemeral port while avoiding exact 5-tuple reuse."""
        rng = _get_rng()
        ts_epoch = time.timestamp()
        reuse_window = 86_400.0
        for _ in range(128):
            src_port = _ephemeral_port(rng, os_category)
            key = (src_ip, src_port, dst_ip, dst_port, proto)
            last_seen = self._recent_connection_tuples.get(key)
            if last_seen is None or ts_epoch - last_seen > reuse_window:
                self._recent_connection_tuples[key] = ts_epoch
                return src_port
        src_port = _ephemeral_port(rng, os_category)
        self._recent_connection_tuples[(src_ip, src_port, dst_ip, dst_port, proto)] = ts_epoch
        return src_port

    def _infer_connection_pid(
        self,
        source_system: System | None,
        service: str | None,
        dst_port: int,
        proto: str,
    ) -> int:
        """Infer a durable system-service PID for infrastructure connections."""
        if source_system is None:
            return -1
        pids = getattr(self, "_system_pids", {}).get(source_system.hostname, {})
        if not pids:
            return -1

        service_name = (service or "").lower()
        roles = set(getattr(source_system, "roles", []) or [])
        os_category = _get_os_category(source_system.os)

        candidates: list[str] = []
        if proto == "udp" and dst_port == 53 or service_name == "dns":
            candidates = ["systemd_resolved", "svchost_netsvcs", "svchost_net_svc"]
        elif proto == "udp" and dst_port == 123 or service_name == "ntp":
            candidates = ["timesyncd", "chronyd", "svchost_netsvcs"]
        elif service_name in ("kerberos", "ldap") or dst_port in (88, 389):
            candidates = ["lsass", "svchost_netsvcs"]
        elif service_name == "smb" or dst_port == 445:
            return 4 if os_category == "windows" else pids.get("smbd", -1)
        elif service_name == "ssh" or dst_port == 22:
            candidates = ["sshd"]
        elif "forward_proxy" in roles and service_name in ("http", "ssl"):
            candidates = ["squid", "nginx", "apache2", "httpd"]

        for name in candidates:
            pid = pids.get(name)
            if pid and pid > 0:
                return pid
        return -1

    def _build_dc_host_context(self, dc_hostname: str) -> HostContext:
        """Build a HostContext for a domain controller from raw hostname string.

        DC methods receive raw strings (not System objects). Constructs a
        HostContext suitable for Windows event rendering (Computer field).
        """
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        return HostContext(
            hostname=dc_hostname,
            ip="",
            os="Windows Server 2019",
            os_category="windows",
            system_type="domain_controller",
            domain=ad_domain,
            fqdn=f"{dc_hostname}.{ad_domain}" if ad_domain else dc_hostname,
            netbios_domain=ad_domain.split(".")[0].upper() if ad_domain else "CORP",
        )

    def _proxy_fqdn(self, proxy_sys: "System") -> str:
        """Return the FQDN used to route proxy access logs."""
        proxy_fqdn = getattr(proxy_sys, "hostname", "")
        ad_domain = getattr(self, "_ad_domain", "")
        if ad_domain and "." not in proxy_fqdn:
            proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
        return proxy_fqdn

    def _build_proxy_context(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str | None,
        duration: float | None,
        orig_bytes: int | None,
        resp_bytes: int | None,
        hostname: str | None,
        source_system: Optional["System"],
        proxy_sys: "System",
        http: Optional["HttpContext"] = None,
        explicit_mode: bool = False,
    ) -> ProxyContext:
        """Build a proxy access context from the logical origin request."""
        rng = _get_rng()
        proxy_hostname = hostname
        if proxy_hostname is None:
            proxy_hostname = REVERSE_DNS.get(dst_ip)
        if proxy_hostname is None:
            proxy_hostname = _generate_random_hostname(rng, dst_ip)
        if proxy_hostname == "":
            proxy_hostname = dst_ip

        from evidenceforge.generation.activity.dns_registry import get_domain_tags
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri
        from evidenceforge.generation.activity.referrer import pick_referrer

        domain_tags = get_domain_tags(proxy_hostname)
        proxy_ua_override = None
        if explicit_mode and dst_port == 443:
            proxy_method = "CONNECT"
            url = f"{proxy_hostname}:443"
            proxy_content_type = ""
            proxy_referrer = ""
            user_agent = http.user_agent if http is not None else ""
        elif http is not None:
            scheme = "https" if dst_port == 443 or service == "ssl" else "http"
            proxy_method = http.method
            url = f"{scheme}://{proxy_hostname}{http.uri}"
            proxy_content_type = http.resp_mime_types[0] if http.resp_mime_types else "text/html"
            user_agent = http.user_agent
            proxy_referrer = http.referrer
        else:
            source_os = _get_os_category(source_system.os) if source_system else None
            path, proxy_content_type, proxy_method, proxy_ua_override = pick_proxy_uri(
                rng, proxy_hostname, domain_tags, source_os=source_os
            )
            scheme = "https" if dst_port == 443 or service == "ssl" else "http"
            url = f"{scheme}://{proxy_hostname}{path}"
            proxy_referrer = pick_referrer(rng, proxy_hostname, context="general", port=dst_port)
            user_agent = ""

        if not user_agent:
            if proxy_ua_override:
                user_agent = proxy_ua_override
            else:
                user_agent = pick_proxy_user_agent(
                    rng,
                    source_system,
                    hostname=proxy_hostname,
                    domain_tags=domain_tags,
                )

        cache_roll = rng.random()
        if explicit_mode and proxy_method == "CONNECT":
            if cache_roll < 0.975:
                cache_result = "NONE"
            elif cache_roll < 0.988:
                cache_result = "DENIED"
            elif cache_roll < 0.995:
                cache_result = "AUTH_REQUIRED"
            else:
                cache_result = "GATEWAY_ERROR"
        elif cache_roll < 0.30:
            cache_result = "HIT"
        elif cache_roll < 0.95:
            cache_result = "MISS"
        else:
            cache_result = "DENIED"

        cs_bytes = (orig_bytes or 0) + rng.randint(*_PROXY_CS_OVERHEAD)
        if cache_result == "DENIED":
            sc_bytes = rng.randint(500, 2000)
        elif cache_result == "AUTH_REQUIRED":
            sc_bytes = rng.randint(300, 1200)
        elif cache_result == "GATEWAY_ERROR":
            sc_bytes = rng.randint(250, 1800)
        elif cache_result == "HIT":
            response_bytes = max(1, resp_bytes or 0)
            sc_bytes = rng.randint(
                max(1, int(response_bytes * 0.4)), max(2, int(response_bytes * 1.1))
            )
        elif proxy_method == "CONNECT":
            host_len = len(proxy_hostname)
            cs_bytes = rng.randint(180 + host_len, 520 + host_len)
            sc_bytes = rng.randint(90, 260)
        else:
            sc_bytes = (resp_bytes or 0) + rng.randint(*_PROXY_SC_OVERHEAD)

        status_code = {
            "DENIED": 403,
            "AUTH_REQUIRED": 407,
            "GATEWAY_ERROR": rng.choice([502, 503, 504]),
        }.get(cache_result, 200)

        return ProxyContext(
            client_ip=src_ip,
            method=proxy_method,
            url=url,
            host=proxy_hostname,
            status_code=status_code,
            sc_bytes=sc_bytes,
            cs_bytes=cs_bytes,
            time_taken=int((duration or 0) * 1000),
            user_agent=user_agent,
            content_type=proxy_content_type,
            cache_result=cache_result,
            referrer=proxy_referrer,
            proxy_fqdn=self._proxy_fqdn(proxy_sys),
        )

    def _attach_ssl_context(
        self,
        event: SecurityEvent,
        *,
        hostname: str | None,
        dns: Optional["DnsContext"],
        dst_ip: str,
        rng: random.Random,
        allow_failure: bool = True,
    ) -> None:
        """Attach Zeek SSL and x509 contexts to an established TLS connection."""
        from evidenceforge.events.contexts import SslContext

        net = event.network
        if net is None or event.ssl is not None:
            return

        # Hostname is the SNI source of truth.  Do not invent SNI from a bare
        # destination IP or PTR; raw-IP TLS should either have no SNI or an
        # explicit/DNS-backed hostname.
        server_name = hostname
        if server_name is None and dns is not None and dns.query:
            server_name = dns.query
        # Suppressed hostname -> no SNI (raw-IP C2, etc.)
        if server_name == "":
            server_name = None

        # For suppressed hostnames (raw-IP C2), use the IP as the cert subject.
        cert_name = server_name or dst_ip

        # Issuer-aware certificate generation from YAML config.
        from evidenceforge.generation.activity.tls_issuers import pick_issuer, pick_key_type

        cert_rng = random.Random(_stable_seed(f"tls_cert_profile:{cert_name}"))
        issuer_cfg = pick_issuer(cert_rng, server_name=cert_name)
        key_type, key_length = pick_key_type(cert_rng, issuer_cfg)
        is_ecdsa = key_type == "ecdsa"

        modern_tls_domain = bool(server_name) and server_name.endswith(
            (
                ".google.com",
                ".gstatic.com",
                ".googleapis.com",
                ".microsoft.com",
                ".office.com",
                ".office365.com",
                ".microsoftonline.com",
                ".windowsupdate.com",
                ".cloudfront.net",
                ".github.com",
                ".slack.com",
                ".zoom.us",
            )
        )
        _tls_rng = random.Random(_stable_seed(f"tls:{server_name or dst_ip}:{net.src_ip}"))
        if modern_tls_domain:
            tls_version = _tls_rng.choices(("TLSv12", "TLSv13"), weights=(15, 85), k=1)[0]
        else:
            tls_version = _tls_rng.choices(_TLS_VERSION_VALUES, weights=_TLS_VERSION_WEIGHTS, k=1)[
                0
            ]
        if tls_version == "TLSv13":
            cipher = _tls_rng.choices(_TLS13_CIPHER_VALUES, weights=_TLS13_CIPHER_WEIGHTS, k=1)[0]
        elif is_ecdsa:
            cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        elif modern_tls_domain:
            cipher = _tls_rng.choices(
                (
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                ),
                weights=(75, 25),
                k=1,
            )[0]
        else:
            cipher = _tls_rng.choices(
                (
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                ),
                weights=(65, 28, 7),
                k=1,
            )[0]

        ssl_established = (rng.random() > _SSL_FAILURE_RATE) if allow_failure else True
        if ssl_established:
            ssl_hist = rng.choices(
                _SSL_HIST_SUCCESS_VALUES, weights=_SSL_HIST_SUCCESS_WEIGHTS, k=1
            )[0]
        else:
            ssl_hist = rng.choices(
                _SSL_HIST_FAILURE_VALUES, weights=_SSL_HIST_FAILURE_WEIGHTS, k=1
            )[0]
        tls_name_key = server_name or dst_ip
        first_observed_name = tls_name_key not in self._tls_seen_server_names
        resumed = (rng.random() < 0.45 and not first_observed_name) if ssl_established else False
        self._tls_seen_server_names.add(tls_name_key)

        event.ssl = SslContext(
            version=tls_version,
            cipher=cipher if ssl_established else "",
            server_name=server_name,
            resumed=resumed,
            established=ssl_established,
            ssl_history=ssl_hist,
        )
        if not ssl_established:
            net.conn_state = rng.choice(["S1", "SH"])
            net.history = "Sh" if net.conn_state == "SH" else "ShR"
            net.resp_bytes = 0
            net.orig_bytes = 0
            if net.duration is not None:
                net.duration = rng.uniform(0.0, 0.5)
            return

        import hashlib

        from evidenceforge.events.contexts import X509Context

        if resumed:
            return
        cert_hash = hashlib.sha256(f"cert_{cert_name}".encode()).hexdigest()
        cert_fuid_hash = hashlib.sha256(
            f"cert_fuid_{cert_name}:{net.zeek_uid}:{event.timestamp.timestamp()}".encode()
        ).hexdigest()
        cert_fuid = f"F{cert_fuid_hash[:16]}"
        # Support validity_days_min/max ranges; fall back to scalar validity_days
        _vd_fallback = issuer_cfg.get("validity_days", 397)
        _vd_min = issuer_cfg.get("validity_days_min", _vd_fallback)
        _vd_max = issuer_cfg.get("validity_days_max", _vd_fallback)
        validity = self._tls_cert_validity.get(cert_name)
        if validity is None:
            now_epoch = int(event.timestamp.timestamp())
            validity_days = cert_rng.randint(_vd_min, _vd_max)
            not_before_max = issuer_cfg.get("not_before_max_days", 300)
            not_before_days = cert_rng.randint(1, min(not_before_max, validity_days - 1))
            not_valid_before = now_epoch - not_before_days * 86400
            not_valid_after = not_valid_before + validity_days * 86400
            validity = (not_valid_before, not_valid_after)
            self._tls_cert_validity[cert_name] = validity
        san_dns_list = _tls_san_dns_names(cert_name)
        serial_number = (
            f"{random.Random(_stable_seed(f'tls_cert_serial:{cert_name}')).getrandbits(128):032X}"
        )
        event.x509 = X509Context(
            fuid=cert_fuid,
            fingerprint=cert_hash,
            certificate_version=3,
            certificate_serial=serial_number,
            certificate_subject=f"CN={cert_name}",
            certificate_issuer=issuer_cfg["name"],
            certificate_not_valid_before=validity[0],
            certificate_not_valid_after=validity[1],
            certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
            certificate_sig_alg="ecdsa-with-SHA256" if is_ecdsa else "sha256WithRSAEncryption",
            certificate_key_type=key_type,
            certificate_key_length=key_length,
            certificate_exponent="65537" if not is_ecdsa else "",
            san_dns=san_dns_list,
            basic_constraints_ca=False,
            host_cert=True,
            client_cert=False,
        )
        event.x509_chain = self._build_tls_certificate_chain(
            leaf=event.x509,
            cert_name=cert_name,
            issuer_name=issuer_cfg["name"],
            event_time=event.timestamp,
            connection_uid=net.zeek_uid,
            rng=rng,
        )
        event.ssl.cert_chain_fuids = [cert.fuid for cert in event.x509_chain]

        # OCSP response (cached/probabilistic; mostly good, with rare non-good statuses)
        if rng.random() < 0.18:
            from evidenceforge.events.contexts import FileTransferContext, OcspContext
            from evidenceforge.generation.activity.tls_realism import ocsp_config
            from evidenceforge.utils.ids import generate_zeek_uid as _gen_uid

            ocsp_settings = ocsp_config()
            ocsp_bucket_seconds = int(ocsp_settings.get("cache_bucket_seconds", 4 * 60 * 60))
            this_update_max_skew = int(ocsp_settings.get("this_update_max_skew_seconds", 3600))
            next_update_min = int(ocsp_settings.get("next_update_min_seconds", 8 * 3600))
            next_update_max = int(ocsp_settings.get("next_update_max_seconds", 7 * 86400))
            event_epoch = int(event.timestamp.timestamp())
            bucket_start = event_epoch - (event_epoch % ocsp_bucket_seconds)
            ocsp_window_key = (
                cert_name,
                event.x509.certificate_serial,
                bucket_start,
            )
            ocsp_window = self._tls_ocsp_windows.get(ocsp_window_key)
            if ocsp_window is None:
                ocsp_rng = random.Random(
                    _stable_seed(
                        f"ocsp_window:{cert_name}:{event.x509.certificate_serial}:{bucket_start}"
                    )
                )
                this_update = bucket_start - ocsp_rng.randint(0, max(0, this_update_max_skew))
                next_update = (
                    bucket_start
                    + ocsp_bucket_seconds
                    + ocsp_rng.randint(next_update_min, max(next_update_min, next_update_max))
                )
                ocsp_window = (this_update, next_update)
                self._tls_ocsp_windows[ocsp_window_key] = ocsp_window
            this_update, next_update = ocsp_window
            ocsp_id = _gen_uid("F")
            event.ocsp = OcspContext(
                id=ocsp_id,
                hash_algorithm="sha256",
                issuer_name_hash=hashlib.sha256(event.x509.certificate_issuer.encode()).hexdigest()[
                    :40
                ],
                issuer_key_hash=hashlib.sha256(
                    f"key_{event.x509.certificate_issuer}".encode()
                ).hexdigest()[:40],
                serial_number=event.x509.certificate_serial,
                cert_status=_ocsp_status_for_certificate(cert_name, event.x509.certificate_serial),
                this_update=this_update,
                next_update=next_update,
            )
            if event.file_transfer is None:
                ocsp_size = random.Random(_stable_seed(f"ocsp_file_size:{ocsp_id}")).randint(
                    900, 2500
                )
                event.file_transfer = FileTransferContext(
                    fuid=ocsp_id,
                    source="HTTP",
                    depth=0,
                    analyzers=[],
                    mime_type="application/ocsp-response",
                    duration=rng.uniform(0.001, 0.02),
                    local_orig=_is_private_ip(net.src_ip),
                    is_orig=False,
                    seen_bytes=ocsp_size,
                    total_bytes=ocsp_size,
                    missing_bytes=0,
                    overflow_bytes=0,
                    timedout=False,
                )

    def _build_tls_certificate_chain(
        self,
        *,
        leaf: Any,
        cert_name: str,
        issuer_name: str,
        event_time: datetime,
        connection_uid: str,
        rng: random.Random,
    ) -> list[Any]:
        """Build a configured leaf/intermediate certificate chain."""
        import hashlib

        from evidenceforge.events.contexts import X509Context
        from evidenceforge.generation.activity.tls_realism import (
            certificate_chain_config,
            chain_template_for_issuer,
        )

        chain = [leaf]
        config = certificate_chain_config()
        include_probability = float(config.get("include_intermediate_probability", 0.86))
        if rng.random() >= include_probability:
            return chain

        template = chain_template_for_issuer(issuer_name)
        intermediate_subjects = [
            str(subject) for subject in template.get("intermediates", []) if subject
        ]
        if not intermediate_subjects:
            return chain

        chain_rng = random.Random(_stable_seed(f"tls_chain:{cert_name}:{issuer_name}"))
        selected_subjects = [chain_rng.choice(intermediate_subjects)]
        second_probability = float(config.get("include_second_intermediate_probability", 0.08))
        remaining_subjects = [
            subject for subject in intermediate_subjects if subject != selected_subjects[0]
        ]
        if remaining_subjects and chain_rng.random() < second_probability:
            selected_subjects.append(chain_rng.choice(remaining_subjects))

        parent_issuer = selected_subjects[1] if len(selected_subjects) > 1 else selected_subjects[0]
        for idx, subject in enumerate(selected_subjects):
            certificate_issuer = (
                selected_subjects[idx + 1] if idx + 1 < len(selected_subjects) else subject
            )
            if idx == 0:
                subject = issuer_name
            serial_rng = random.Random(_stable_seed(f"tls_chain_serial:{subject}"))
            serial = f"{serial_rng.getrandbits(128):032X}"
            fuid_hash = hashlib.sha256(
                f"cert_chain_fuid:{subject}:{connection_uid}:{event_time.timestamp()}".encode()
            ).hexdigest()
            cert_hash = hashlib.sha256(f"cert_chain:{subject}:{serial}".encode()).hexdigest()
            validity = self._tls_cert_validity.get(subject)
            if validity is None:
                now_epoch = int(event_time.timestamp())
                min_days = int(config.get("intermediate_validity_days_min", 1825))
                max_days = int(config.get("intermediate_validity_days_max", 3650))
                max_not_before = int(config.get("intermediate_not_before_max_days", 1460))
                validity_days = chain_rng.randint(min_days, max(max_days, min_days))
                not_before_days = chain_rng.randint(30, min(max_not_before, validity_days - 1))
                not_valid_before = now_epoch - not_before_days * 86400
                not_valid_after = not_valid_before + validity_days * 86400
                validity = (not_valid_before, not_valid_after)
                self._tls_cert_validity[subject] = validity

            key_types = config.get(
                "key_types",
                [{"type": "rsa", "length": 2048, "weight": 100}],
            )
            weights = [int(entry.get("weight", 0)) for entry in key_types]
            selected_key = chain_rng.choices(key_types, weights=weights, k=1)[0]
            key_type = str(selected_key.get("type", "rsa"))
            key_length = int(selected_key.get("length", 2048))
            is_ecdsa = key_type == "ecdsa"
            chain.append(
                X509Context(
                    fuid=f"F{fuid_hash[:16]}",
                    fingerprint=cert_hash,
                    certificate_version=3,
                    certificate_serial=serial,
                    certificate_subject=subject,
                    certificate_issuer=certificate_issuer or parent_issuer,
                    certificate_not_valid_before=validity[0],
                    certificate_not_valid_after=validity[1],
                    certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
                    certificate_sig_alg="ecdsa-with-SHA256"
                    if is_ecdsa
                    else "sha256WithRSAEncryption",
                    certificate_key_type=key_type,
                    certificate_key_length=key_length,
                    certificate_exponent="65537" if not is_ecdsa else "",
                    san_dns=[],
                    basic_constraints_ca=True,
                    host_cert=False,
                    client_cert=False,
                )
            )
        return chain

    def _build_expansion_context(
        self,
        event_type: str,
        timestamp: datetime,
        **kwargs: Any,
    ) -> ExpansionContext:
        """Build an ExpansionContext from event parameters and engine state."""
        dns_server_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
        dc_hostnames = getattr(self, "_dc_hostnames", [])
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        if not hasattr(self, "_dns_cache"):
            self._dns_cache: dict[tuple[str, str, str], float] = {}
        if not hasattr(self, "_kerberos_cache"):
            self._kerberos_cache: dict[str, float] = {}

        dc_systems = getattr(self, "_dc_systems", [])
        if not hasattr(self, "_created_account_sids"):
            self._created_account_sids: dict[str, str] = {}

        return ExpansionContext(
            event_type=event_type,
            timestamp=timestamp,
            src_ip=kwargs.get("src_ip"),
            dst_ip=kwargs.get("dst_ip"),
            dst_port=kwargs.get("dst_port"),
            protocol=kwargs.get("protocol") or kwargs.get("proto"),
            service=kwargs.get("service"),
            logon_type=kwargs.get("logon_type"),
            auth_package=kwargs.get("auth_package"),
            command_line=kwargs.get("command_line"),
            process_name=kwargs.get("process_name"),
            os_category=kwargs.get("os_category"),
            hostname=kwargs.get("hostname"),
            source_system=kwargs.get("source_system"),
            target_system=kwargs.get("target_system"),
            actor=kwargs.get("actor"),
            source_pid=kwargs.get("source_pid"),
            source_image=kwargs.get("source_image"),
            target_pid=kwargs.get("target_pid"),
            target_image=kwargs.get("target_image"),
            skip_types=kwargs.get("skip_types", set()),
            dns_cache=self._dns_cache,
            kerberos_cache=self._kerberos_cache,
            dns_server_ips=dns_server_ips,
            dc_hostnames=dc_hostnames,
            dc_systems=dc_systems,
            ad_domain=ad_domain,
            sid_registry=self.sid_registry,
            created_account_sids=self._created_account_sids,
        )

    def _expand_and_emit(
        self,
        event_type: str,
        timestamp: datetime,
        **kwargs: Any,
    ) -> None:
        """Run causal expansion and emit all expanded prerequisite/consequent events.

        This is a no-op if:
        - No causal engine is configured.
        - We are already expanding the same event type (prevents same-type recursion).

        Cross-type expansion is allowed: a process_create expansion can trigger
        a connection expansion (which triggers DNS), but connection cannot
        recursively trigger another connection expansion.
        """
        if event_type in self._expanding_types:
            logger.debug("Skipping nested %s expansion (already expanding)", event_type)
            return

        ctx = self._build_expansion_context(event_type, timestamp, **kwargs)
        expanded = self._causal_engine.expand(event_type, ctx)
        if not expanded:
            return

        rng = _get_rng()
        self._expanding_types.add(event_type)
        try:
            for ev in expanded:
                offset_ms = rng.randint(ev.timing.min_ms, ev.timing.max_ms)
                offset = timedelta(milliseconds=offset_ms)
                if ev.timing.position == "before":
                    ev.kwargs["time"] = timestamp - offset
                else:
                    ev.kwargs["time"] = timestamp + offset

                method = getattr(self, ev.method)
                method(**ev.kwargs)
        finally:
            self._expanding_types.discard(event_type)

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: str | None = None,
        source_port: int | None = None,
        emit_transport_syslog: bool = True,
        logon_id: str | None = None,
    ) -> str:
        """Generate logon event across all applicable log formats.

        Creates or reuses a session in StateManager, builds a SecurityEvent,
        and dispatches to matching emitters (Windows 4624 + optional 4672,
        syslog auth, eCAR).

        Args:
            user: User logging on
            system: System being logged into
            time: Logon timestamp
            logon_type: Windows logon type (2=interactive, 3=network, 10=remote interactive)
            source_ip: Source IP address (defaults to system IP for interactive logons)

        Returns:
            LogonID (hex string format, e.g., "0x3e7")
        """
        # Use system IP for interactive logons, allow override for network logons
        if source_ip is None:
            source_ip = system.ip if logon_type != 3 else "127.0.0.1"

        # Linux type-10 remote logons are SSH, not RDP
        os_cat = _get_os_category(system.os)
        if logon_type == 10 and os_cat == "linux":
            session_kind = "ssh"
        else:
            session_kind = {
                3: "network",
                10: "rdp",
            }.get(logon_type, "interactive")

        # Phase 1: Allocate or resolve IDs from StateManager
        if logon_id is None:
            logon_id = self.state_manager.create_session(
                username=user.username,
                system=system.hostname,
                logon_type=logon_type,
                source_ip=source_ip,
                source_port=source_port or 0,
                session_kind=session_kind,
            )
        else:
            existing_session = self.state_manager.get_session(logon_id)
            if existing_session is None:
                self.state_manager.register_session(
                    logon_id=logon_id,
                    username=user.username,
                    system=system.hostname,
                    logon_type=logon_type,
                    source_ip=source_ip,
                    start_time=time,
                    source_port=source_port or 0,
                    session_kind=session_kind,
                )
            elif source_port is not None:
                self.state_manager.update_session_metadata(logon_id, source_port=source_port)

        # Select auth package (semantic data, not format-specific)
        auth_pkg = self._select_auth_package(logon_type)

        # Phase 2: Build SecurityEvent with all contexts
        # For network logons (type 3, 10), resolve source host from source_ip
        src_host_ctx = None
        if logon_type in (3, 10) and source_ip:
            if hasattr(self, "_ip_to_system") and source_ip in self._ip_to_system:
                src_host_ctx = self._build_host_context(self._ip_to_system[source_ip])

        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            src_host=src_host_ctx,
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                logon_type=logon_type,
                auth_package=auth_pkg.get("AuthenticationPackageName", "Negotiate"),
                source_ip=source_ip,
                elevated=self._should_elevate(user),
                logon_process=auth_pkg.get("LogonProcessName", ""),
                lm_package=auth_pkg.get("LmPackageName", "-"),
                logon_guid=auth_pkg.get("LogonGuid", "{00000000-0000-0000-0000-000000000000}"),
                subject_sid=self._get_sid("SYSTEM"),
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
                reporting_pid=self._get_system_pid(system.hostname, "lsass", 0x2E0),
            ),
            edr=EdrContext(object_id=session_obj_id),
        )

        # Attach SyslogContext for Linux SSH sessions only (not network/interactive)
        session_for_syslog = self.state_manager.get_session(logon_id) if logon_id else None
        is_ssh_session = (
            session_for_syslog and getattr(session_for_syslog, "session_kind", None) == "ssh"
        ) or logon_type == 10  # logon_type 10 = remote (SSH on Linux)
        if (
            event.dst_host
            and event.dst_host.os_category == "linux"
            and emit_transport_syslog
            and is_ssh_session
        ):
            from evidenceforge.events.contexts import SyslogContext

            session = self.state_manager.get_session(logon_id)
            effective_source_port = source_port or (session.source_port if session else 0)
            sshd_pid = (
                session.transport_pid
                if session and session.transport_pid is not None
                else 1000 + (_stable_seed(f"sshd_pid_{logon_id}") % 59000)
            )
            self.state_manager.update_session_metadata(
                logon_id,
                source_port=effective_source_port,
                transport_pid=sshd_pid,
            )
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=(
                    f"Accepted password for {user.username} from {source_ip} "
                    f"port {effective_source_port or _ephemeral_port(_get_rng(), 'linux')} ssh2"
                ),
            )

        # Emit DC-side Kerberos events for domain logons via causal expansion.
        # The KerberosBeforeLogon rule handles TGT (4768), TGS (4769), and
        # optional 4672 for elevated users.
        auth_package_name = auth_pkg.get("AuthenticationPackageName", "Negotiate")
        self._expand_and_emit(
            "logon",
            time,
            actor=user,
            target_system=system,
            auth_package=auth_package_name,
            src_ip=source_ip,
            os_category=_get_os_category(system.os),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        # Phase 4: Create per-session explorer.exe for interactive logons
        if logon_type in (2, 10, 11):
            session = self.state_manager.get_session(logon_id)
            if session is not None:
                os_cat = _get_os_category(system.os)
                if os_cat == "windows":
                    sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
                    if logon_type == 10:
                        # RDP: per-session winlogon → userinit → explorer chain
                        # Windows creates a new session subsystem for each RDP logon
                        smss_pid = sys_pids.get("smss")
                        parent_for_chain = smss_pid or sys_pids.get("wininit")
                        if parent_for_chain and self.state_manager.get_process(
                            system.hostname, parent_for_chain
                        ):
                            winlogon_pid = self.state_manager.create_process(
                                system.hostname,
                                parent_for_chain,
                                r"C:\Windows\System32\winlogon.exe",
                                "winlogon.exe",
                                "SYSTEM",
                                "System",
                                logon_id=logon_id,
                            )
                            session.session_winlogon_pid = winlogon_pid
                            userinit_pid = self.state_manager.create_process(
                                system.hostname,
                                winlogon_pid,
                                r"C:\Windows\System32\userinit.exe",
                                "userinit.exe",
                                user.username,
                                "Medium",
                                logon_id=logon_id,
                            )
                            explorer_pid = self.state_manager.create_process(
                                system.hostname,
                                userinit_pid,
                                r"C:\Windows\explorer.exe",
                                "explorer.exe",
                                user.username,
                                "Medium",
                                logon_id=logon_id,
                            )
                            session.explorer_pid = explorer_pid
                            session.process_tree_root = winlogon_pid
                    else:
                        # Interactive/cached: use system-wide userinit/winlogon
                        parent_pid = None
                        for candidate in ("userinit", "winlogon", "explorer", "services"):
                            pid = sys_pids.get(candidate)
                            if pid and self.state_manager.get_process(system.hostname, pid):
                                parent_pid = pid
                                break
                        if parent_pid is not None:
                            explorer_pid = self.state_manager.create_process(
                                system.hostname,
                                parent_pid,
                                r"C:\Windows\explorer.exe",
                                "explorer.exe",
                                user.username,
                                "Medium",
                                logon_id=logon_id,
                            )
                            session.explorer_pid = explorer_pid
                            session.process_tree_root = explorer_pid
                session.last_activity_time = time

        logger.debug(f"Generated logon: {user.username} on {system.hostname} (LogonID: {logon_id})")
        return logon_id

    def _emit_dc_kerberos_for_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        auth_package: str,
        source_ip: str,
    ) -> None:
        """Emit DC-side Kerberos TGT (4768) and service ticket (4769) for domain logons.

        In a real AD environment, when a user authenticates via Kerberos:
        1. Client requests TGT from DC (4768) ~50-200ms before logon
        2. Client requests service ticket for target host (4769) ~20-100ms after TGT
        3. Target host logs the 4624

        Only emits when:
        - Auth package is Kerberos (not NTLM)
        - Target system is Windows
        - System is not the DC itself
        - A DC is known in the scenario
        """
        # Only emit for explicit Kerberos auth on Windows systems.
        # "Negotiate" can fall back to NTLM, and CredSSP (RDP) uses its own
        # auth flow — only pure "Kerberos" auth triggers DC-side TGT/TGS.
        if auth_package != "Kerberos":
            return

        os_cat = _get_os_category(system.os)
        if os_cat != "windows":
            return

        dc_hostnames = getattr(self, "_dc_hostnames", [])
        dc_ips = getattr(self, "_dc_ips", [])
        if not dc_hostnames:
            return

        # Don't emit Kerberos events when logging onto the DC itself
        if system.hostname in dc_hostnames or system.ip in dc_ips:
            return

        rng = _get_rng()
        dc_idx = rng.randint(0, len(dc_hostnames) - 1)
        dc_hostname = dc_hostnames[dc_idx]

        # TGT request: 50-200ms before the 4624 on the target
        tgt_offset_ms = rng.randint(50, 200)
        tgt_time = time - timedelta(milliseconds=tgt_offset_ms)
        self.generate_kerberos_tgt(
            username=user.username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgt_time,
        )

        # Service ticket request: 20-100ms after TGT
        tgs_offset_ms = rng.randint(20, 100)
        tgs_time = tgt_time + timedelta(milliseconds=tgs_offset_ms)
        _svc_template = rng.choices(_KERBEROS_SVC_VALUES, weights=_KERBEROS_SVC_WEIGHTS, k=1)[0]
        service_name = _svc_template.format(
            hostname=system.hostname, domain=getattr(self, "_ad_domain", "CORP.LOCAL")
        )
        self.generate_kerberos_service_ticket(
            username=user.username,
            service_name=service_name,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgs_time,
        )

        # 4672 Special Privileges on DC for elevated users (domain admins)
        if self._should_elevate(user):
            priv_time = tgt_time + timedelta(milliseconds=rng.randint(1, 10))
            priv_event = SecurityEvent(
                timestamp=priv_time,
                event_type="special_privileges",
                dst_host=self._build_dc_host_context(dc_hostname),
                auth=AuthContext(
                    username=user.username,
                    user_sid=self._get_sid(user.username),
                    logon_id=self._get_user_logon_id(user.username, dc_hostname),
                    reporting_pid=self._get_system_pid(dc_hostname, "lsass", 0x2E0),
                ),
            )
            self.dispatcher.dispatch(priv_event)

    def generate_failed_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: str | None = None,
        target_username: str | None = None,
        dc_system: "System | None" = None,
    ) -> None:
        """Generate a failed logon event.

        Does NOT create a session in StateManager. Builds a SecurityEvent with
        result="failure" and dispatches to matching emitters (Windows 4625,
        syslog "Failed password", eCAR LOGIN with failure_reason).

        When dc_system is provided, also emits 4625 and 4776 (NTLM validation)
        on the domain controller, matching real AD authentication flow.

        Args:
            user: User attempting to log on (or performing the test)
            system: Target system
            time: Attempt timestamp
            logon_type: Logon type attempted
            source_ip: Source IP (defaults to system IP for interactive)
            target_username: If set, the logon targets this user instead of the actor
            dc_system: Domain controller to also emit 4625/4776 on (optional)
        """
        if source_ip is None:
            source_ip = system.ip if logon_type != 3 else "127.0.0.1"

        # Use target_username if provided, otherwise use the actor's username
        effective_username = target_username or user.username

        # Determine failure substatus with correct SID handling
        rng = _get_rng()
        substatus_roll = rng.random()
        if substatus_roll < 0.60:
            substatus = "0xc000006a"  # Wrong password
            user_sid = self._get_sid(effective_username)
            failure_reason = "%%2313"
        elif substatus_roll < 0.85:
            substatus = "0xc0000064"  # User not found: NULL SID
            user_sid = "S-1-0-0"
            failure_reason = "%%2313"
        elif substatus_roll < 0.95:
            substatus = "0xc0000234"  # Account locked out
            user_sid = self._get_sid(effective_username)
            failure_reason = "%%2304"
        else:
            substatus = "0xc0000072"  # Account disabled
            user_sid = self._get_sid(effective_username)
            failure_reason = "%%2307"

        event = SecurityEvent(
            timestamp=time,
            event_type="failed_logon",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=effective_username,
                user_sid=user_sid,
                logon_type=logon_type,
                auth_package="Negotiate",
                result="failure",
                failure_reason=failure_reason,
                failure_status="0xc000006d",
                failure_substatus=substatus,
                source_ip=source_ip,
                subject_sid=self._get_sid("SYSTEM"),
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
            ),
            edr=EdrContext(object_id=str(uuid.uuid4())),
        )

        # Attach SyslogContext for Linux hosts (sshd failed logon)
        if event.dst_host and event.dst_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            event.syslog = SyslogContext(
                app_name="sshd",
                pid=_get_rng().randint(5000, 60000),
                facility=10,
                severity=4,
                message=(
                    f"Failed password for {effective_username} from {source_ip} "
                    f"port {_ephemeral_port(_get_rng(), 'linux')} ssh2"
                ),
            )

        self.dispatcher.dispatch(event)

        # Domain controller side: 4625 + 4776 for domain account authentication
        if dc_system and dc_system.hostname != system.hostname:
            dc_event = SecurityEvent(
                timestamp=time,
                event_type="failed_logon",
                dst_host=self._build_dc_host_context(dc_system.hostname),
                auth=AuthContext(
                    username=effective_username,
                    user_sid=user_sid,
                    logon_type=3,  # Network logon on DC
                    auth_package="Negotiate",
                    result="failure",
                    failure_reason=failure_reason,
                    failure_status="0xc000006d",
                    failure_substatus=substatus,
                    source_ip=source_ip,
                    subject_sid=self._get_sid("SYSTEM"),
                    subject_username="SYSTEM",
                    subject_domain="NT AUTHORITY",
                    subject_logon_id="0x3e7",
                ),
            )
            self.dispatcher.dispatch(dc_event)

            # 4776 NTLM credential validation on DC
            self.generate_ntlm_validation(
                username=effective_username,
                workstation=system.hostname,
                dc_hostname=dc_system.hostname,
                time=time,
            )

            # 4771 Kerberos pre-authentication failure on DC
            # In real AD, Kerberos is tried first; 4771 fires before 4625/4776
            # for wrong-password failures.
            if substatus == "0xc000006a":  # Wrong password
                krb_time = time - timedelta(milliseconds=_get_rng().randint(5, 50))
                self.generate_kerberos_preauth_failed(
                    username=effective_username,
                    source_ip=source_ip,
                    dc_hostname=dc_system.hostname,
                    time=krb_time,
                    status="0x18",  # KDC_ERR_PREAUTH_FAILED
                )

        logger.debug(f"Generated failed logon: {user.username} on {system.hostname}")

    def generate_logoff(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        logon_type: int = 2,
    ) -> None:
        """Generate logoff event across all applicable log formats.

        Ends session in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4634, syslog session closed, eCAR LOGOUT).

        Args:
            user: User logging off
            system: System being logged off from
            time: Logoff timestamp
            logon_id: LogonID from the logon event
            logon_type: Logon type for the session being ended
        """
        # Terminate session-specific processes before ending session
        session = self.state_manager.get_session(logon_id)
        if session:
            if session.explorer_pid is not None:
                self.state_manager.end_process(session.system, session.explorer_pid)
            # Clean up per-RDP-session winlogon chain
            if session.session_winlogon_pid is not None:
                self.state_manager.end_process(session.system, session.session_winlogon_pid)
            # Clean up per-SSH-session bash
            if session.session_shell_pid is not None:
                self.state_manager.end_process(session.system, session.session_shell_pid)

        # Build SecurityEvent (StateManager.apply() handles end_session)
        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="logoff",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                logon_type=logon_type,
            ),
            edr=EdrContext(object_id=session_obj_id),
        )

        # Attach SyslogContext for Linux SSH sessions only (sshd session closed).
        # Non-SSH sessions (interactive, network) don't produce sshd evidence.
        is_ssh_session = session and session.session_kind == "ssh"
        if event.dst_host and event.dst_host.os_category == "linux" and is_ssh_session:
            from evidenceforge.events.contexts import SyslogContext

            sshd_pid = (
                session.transport_pid
                if session and session.transport_pid is not None
                else 1000 + (_stable_seed(f"sshd_pid_{logon_id}") % 59000)
            )
            source_port = session.source_port if session else 0
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=(
                    f"pam_unix(sshd:session): session closed for user {user.username}"
                    if source_port == 0
                    else (
                        f"Received disconnect from {session.source_ip} port {source_port}:11: "
                        "disconnected by user"
                    )
                ),
            )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        logger.debug(
            f"Generated logoff: {user.username} on {system.hostname} (LogonID: {logon_id})"
        )

    def generate_process(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        ensure_file_event: bool = False,
    ) -> int:
        """Generate process creation event across all applicable log formats.

        Creates process in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4688, eCAR PROCESS/CREATE). Also emits
        probabilistic EDR file/module/registry events.

        When ensure_file_event=True, always emits at least one FILE/CREATE for
        the process image (useful for storyline processes where FILE visibility
        is important for hunting).

        Args:
            user: User creating the process
            system: System where process is created
            time: Process creation timestamp
            logon_id: LogonID of the user's session
            process_name: Full path to executable
            command_line: Command line string
            parent_pid: Parent process PID (default 4 = System)

        Returns:
            PID of the new process
        """
        from evidenceforge.events.contexts import ProcessContext

        # Determine integrity level per UAC model:
        # - SYSTEM processes: "System" (handled in generate_system_process)
        # - Explicitly elevated (admin tools, installers): "High"
        # - Everything else (including admin users under UAC): "Medium"
        _HIGH_INTEGRITY_EXES = {
            "msiexec.exe",
            "regedit.exe",
            "mmc.exe",
            "dism.exe",
            "pkgmgr.exe",
            "setup.exe",
            "install.exe",
            "procdump64.exe",
            "procdump.exe",
            "mimikatz.exe",
            "psexec.exe",
            "psexesvc.exe",
        }
        _exe_lower = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if _exe_lower in _HIGH_INTEGRITY_EXES:
            _integrity = "High"
        else:
            _integrity = "Medium"
            # Browser child processes (renderers) run at Low integrity.
            # ~65% of browser children are sandboxed renderers (Low),
            # ~35% are GPU/utility processes (Medium).
            _BROWSER_EXES = {"chrome.exe", "msedge.exe", "firefox.exe"}
            if _exe_lower in _BROWSER_EXES:
                _parent_image = (
                    self._lookup_process_name(
                        system.hostname, parent_pid, _get_os_category(system.os)
                    )
                    or ""
                )
                _parent_exe = _parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if _parent_exe in _BROWSER_EXES:
                    rng = _get_rng()
                    _integrity = "Low" if rng.random() < 0.65 else "Medium"

        # Phase 1: Allocate IDs from StateManager
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=user.username,
            integrity_level=_integrity,
            logon_id=logon_id,
        )

        # Phase 2: Build SecurityEvent
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        parent_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_create",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=user.username,
                integrity_level=_integrity,
                logon_id=logon_id,
                parent_image=self._lookup_process_name(
                    system.hostname, parent_pid, _get_os_category(system.os)
                ),
                parent_command_line=self._lookup_parent_command_line(system.hostname, parent_pid),
                token_elevation="%%1938",
                mandatory_label="S-1-16-8192",
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        # Guaranteed FILE/CREATE for the process image when requested (storyline processes).
        # Skip for pre-existing binaries in System32/SysWOW64/Program Files — Event 11
        # should only fire for genuinely new files written to disk (malware drops, downloads).
        if ensure_file_event:
            _lower = process_name.lower().replace("/", "\\")
            _is_system_binary = (
                _lower.startswith("c:\\windows\\system32\\")
                or _lower.startswith("c:\\windows\\syswow64\\")
                or _lower.startswith("c:\\program files\\")
                or _lower.startswith("c:\\program files (x86)\\")
            )
            if not _is_system_binary:
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time,
                        event_type="file_create",
                        src_host=self._build_host_context(system),
                        auth=AuthContext(username=user.username),
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=user.username,
                        ),
                        file=FileContext(path=process_name, action="create", pid=pid),
                        edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                    )
                )

        # Phase 8.2: Probabilistic EDR object diversity via canonical SecurityEvent
        rng = _get_rng()
        os_category = _get_os_category(system.os)
        host_ctx = self._build_host_context(system)
        auth_ctx = AuthContext(username=user.username)
        if rng.random() < 0.40:
            action = rng.choice(["CREATE", "MODIFY", "MODIFY", "DELETE"])
            from evidenceforge.generation.activity.edr_pools import get_file_paths

            pool = get_file_paths(os_category)
            path = (
                rng.choice(pool)
                .replace("{user}", user.username)
                .replace("{rand}", f"{rng.randint(10000, 99999)}")
            )
            event_type = {
                "CREATE": "file_create",
                "MODIFY": "file_modify",
                "DELETE": "file_delete",
            }[action]
            self.dispatcher.dispatch(
                SecurityEvent(
                    timestamp=time,
                    event_type=event_type,
                    src_host=host_ctx,
                    auth=auth_ctx,
                    process=ProcessContext(
                        pid=pid,
                        parent_pid=parent_pid,
                        image=process_name,
                        command_line=command_line,
                        username=user.username,
                    ),
                    file=FileContext(path=path, action=action.lower(), pid=pid),
                    edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                )
            )
        if os_category == "windows" and rng.random() < 0.30:
            from evidenceforge.generation.activity.edr_pools import get_dll_pool

            dll_path = rng.choice(get_dll_pool())
            self.dispatcher.dispatch(
                SecurityEvent(
                    timestamp=time,
                    event_type="module_load",
                    src_host=host_ctx,
                    auth=auth_ctx,
                    file=FileContext(path=dll_path, action="load", pid=pid),
                    edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                )
            )
        # Only emit registry events for processes that realistically modify registry
        # (services, shells, installers) — NOT command-line recon tools like net.exe/dsquery.exe
        _REGISTRY_WRITERS = {
            "svchost.exe",
            "services.exe",
            "explorer.exe",
            "powershell.exe",
            "rundll32.exe",
            "msiexec.exe",
            "reg.exe",
            "regedit.exe",
            "taskhostw.exe",
            "usoclient.exe",
            "dllhost.exe",
        }
        _exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if os_category == "windows" and _exe in _REGISTRY_WRITERS and rng.random() < 0.50:
            # Service-level processes can write HKLM; user processes only HKCU
            _HKLM_WRITERS = {"svchost.exe", "services.exe", "reg.exe", "regedit.exe", "msiexec.exe"}
            # Emit 1-3 registry events per process (registry activity is high-volume)
            _reg_count = rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
            from evidenceforge.generation.activity.edr_pools import (
                get_registry_keys_hkcu,
                get_registry_keys_hklm,
                materialize_edr_template,
            )

            _pool_hkcu = get_registry_keys_hkcu()
            _pool_hklm = get_registry_keys_hklm()
            for _ in range(_reg_count):
                if _exe in _HKLM_WRITERS:
                    _key, _vname, _details = rng.choice(_pool_hklm + _pool_hkcu)
                else:
                    _key, _vname, _details = rng.choice(_pool_hkcu)
                _template_user = user.username if user else "SYSTEM"
                _key = materialize_edr_template(_key, rng, _template_user)
                _vname = materialize_edr_template(_vname, rng, _template_user)
                _details = materialize_edr_template(_details, rng, _template_user)
                # TargetObject = key\value_name (full path as Sysmon shows it)
                _target = f"{_key}\\{_vname}"
                # 85% SetValue (Event 13), 15% DeleteValue (Event 12)
                reg_action = "delete" if rng.random() < 0.15 else "modify"
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time,
                        event_type="registry_modify",
                        src_host=host_ctx,
                        auth=auth_ctx,
                        registry=RegistryContext(
                            key=_target, value=_details, action=reg_action, pid=pid
                        ),
                        edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                    )
                )

        logger.debug(f"Generated process: {process_name} (PID: {pid}) on {system.hostname}")
        return pid

    def generate_process_termination(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
    ) -> None:
        """Generate process termination event across all applicable log formats.

        Builds a SecurityEvent and dispatches to matching emitters (Windows 4689,
        eCAR PROCESS/TERMINATE). StateManager.apply() handles end_process.

        Args:
            user: User who owned the process
            system: System where process ran
            time: Termination timestamp
            pid: PID of the terminated process
            process_name: Full path of the terminated process
            logon_id: LogonID of the owning session
        """
        from evidenceforge.events.contexts import ProcessContext

        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_terminate",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=process_name,
                command_line="",
                username=user.username,
                logon_id=logon_id,
            ),
            edr=EdrContext(object_id=proc_obj_id),
        )

        self.dispatcher.dispatch(event)

        logger.debug(
            f"Generated process termination: {process_name} (PID: {pid}) on {system.hostname}"
        )

    def generate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        dst_port: int = 443,
        proto: str = "tcp",
        service: str | None = None,
        duration: float | None = None,
        orig_bytes: int | None = None,
        resp_bytes: int | None = None,
        src_port: int | None = None,
        emit_dns: bool = False,
        pid: int = -1,
        source_system: Optional["System"] = None,
        conn_state: str | None = None,
        dns: Optional["DnsContext"] = None,
        ids: Optional["IdsContext"] = None,
        http: Optional["HttpContext"] = None,
        proxy: Optional["ProxyContext"] = None,
        firewall: FirewallContext | None = None,
        hostname: str | None = None,
        proxy_bypass: bool = False,
    ) -> str:
        """Generate network connection across all applicable log formats.

        Opens connection in StateManager, builds a SecurityEvent with
        NetworkContext, and dispatches to matching emitters (Zeek conn,
        Snort, eCAR FLOW). Dispatcher handles network visibility filtering.

        Optional context overrides (ids, http) are attached to the
        SecurityEvent, enabling correlated rendering by format-specific
        emitters (e.g., Snort from IdsContext, web_access from HttpContext).

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            time: Connection start timestamp
            dst_port: Destination port
            proto: Protocol (tcp/udp/icmp)
            service: Application protocol (http, https, ssh, dns, etc.)
            duration: Connection duration in seconds
            orig_bytes: Bytes sent by originator
            resp_bytes: Bytes sent by responder
            src_port: Source port (auto-assigned ephemeral if None)
            emit_dns: If True, emit a DNS lookup for dst_ip before the connection
            ids: Optional IdsContext for IDS alert correlation (Snort emitter)
            http: Optional HttpContext override (skips auto-generation)

        Returns:
            Zeek UID (18-character string)
        """
        from evidenceforge.events.contexts import NetworkContext

        # Resolve hostname ONCE for DNS/proxy consistency.
        # All downstream uses (causal DNS expansion, proxy hostname)
        # share this single resolved value instead of doing independent lookups.
        #
        # hostname semantics (preserved through all downstream builders):
        #   None  → auto-resolve from REVERSE_DNS or generate random
        #   ""    → suppress resolution (raw-IP C2, exposed hosts w/o public_hostnames)
        #   "x.y" → use this hostname explicitly
        hostname_was_explicit = hostname not in (None, "")
        hostname_from_reverse_dns = False
        if hostname is None:
            if emit_dns and proto == "tcp" and dst_port not in (53,) and _is_private_ip(dst_ip):
                hostname = _generate_internal_hostname(
                    _get_rng(), dst_ip, getattr(self, "_ad_domain", "corp.local")
                )
            else:
                hostname = REVERSE_DNS.get(dst_ip)
                hostname_from_reverse_dns = hostname is not None
        if hostname is None and emit_dns and proto == "tcp" and dst_port not in (53,):
            if not _is_private_ip(dst_ip):
                hostname = _generate_random_hostname(_get_rng(), dst_ip)

        if hostname and hostname_was_explicit:
            from evidenceforge.generation.activity.dns_registry import (
                get_domain_ips,
                resolve_domain_ip,
            )

            domain_ips = get_domain_ips(hostname)
            if domain_ips and dst_ip not in domain_ips:
                src_host = source_system.hostname if source_system else src_ip
                dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        ad_domain = getattr(self, "_ad_domain", "corp.local")
        hostname_is_external = (
            bool(hostname)
            and "." in hostname
            and not hostname.endswith(f".{ad_domain}")
            and not hostname.endswith(".local")
        )
        proxyable_external_destination = hostname_is_external or not _is_private_ip(dst_ip)
        dns_server_ips = set(getattr(self, "_dns_server_ips", []))
        if (
            proto == "tcp"
            and dst_port in (80, 443)
            and hostname_is_external
            and dst_ip in dns_server_ips
        ):
            from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

            src_host = source_system.hostname if source_system else src_ip
            dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        # Infer common payload service from destination port before proxy
        # routing and DNS expansion. Some callers provide only port/protocol;
        # explicit proxy semantics still need to catch 80/443 before a
        # client-side origin DNS lookup is emitted.
        if proto == "tcp" and dst_port in (80, 443) and service not in ("http", "ssl"):
            service = "http" if dst_port == 80 else "ssl"

        tls_hostname = hostname
        if hostname_from_reverse_dns and not emit_dns and dns is None and http is None:
            # A PTR/reverse-DNS-style fallback is useful for proxy URL rendering
            # but should not become TLS SNI unless the client actually resolved
            # or was explicitly configured to use that hostname.
            tls_hostname = ""

        proxy_routes = getattr(self, "_proxy_routes", {})
        proxy_chain = proxy_routes.get(src_ip)
        explicit_proxy = (
            not proxy_bypass
            and getattr(self, "_proxy_mode", "transparent") == "explicit"
            and proxy_chain
            and proto == "tcp"
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and proxyable_external_destination
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        )
        if explicit_proxy:
            proxy_sys = proxy_chain[0]
            listener_port = int(getattr(self, "_proxy_listener_port", 8080))
            proxy_context = proxy or self._build_proxy_context(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                hostname=hostname,
                source_system=source_system,
                proxy_sys=proxy_sys,
                http=http,
                explicit_mode=True,
            )
            tunnel_key = (
                src_ip,
                proxy_sys.ip,
                proxy_context.host,
                dst_ip,
                dst_port,
            )
            reuse_safe = (
                dst_port == 443
                and http is not None
                and dns is None
                and ids is None
                and firewall is None
                and proxy is None
                and proxy_context.status_code < 400
            )
            if reuse_safe:
                active_tunnel = self._explicit_proxy_tunnels.get(tunnel_key)
                if active_tunnel is not None:
                    last_activity, cached_uid = active_tunnel
                    elapsed = (time - last_activity).total_seconds()
                    if 0 <= elapsed < _EXPLICIT_PROXY_TUNNEL_TIMEOUT_S:
                        self._explicit_proxy_tunnels[tunnel_key] = (time, cached_uid)
                        return cached_uid

            client_http: HttpContext | None = None
            if dst_port == 443:
                connect_status_messages = {
                    200: "Connection Established",
                    403: "Forbidden",
                    407: "Proxy Authentication Required",
                    502: "Bad Gateway",
                    503: "Service Unavailable",
                    504: "Gateway Timeout",
                }
                client_http = HttpContext(
                    method="CONNECT",
                    host=proxy_context.host,
                    uri=f"{proxy_context.host}:443",
                    version="1.1",
                    user_agent=proxy_context.user_agent,
                    request_body_len=0,
                    response_body_len=0,
                    status_code=proxy_context.status_code,
                    status_msg=connect_status_messages.get(
                        proxy_context.status_code,
                        "Connection Established"
                        if proxy_context.status_code < 400
                        else "Proxy Error",
                    ),
                    tags=[],
                )
            elif http is not None:
                client_http = HttpContext(
                    method=http.method,
                    host=proxy_context.host,
                    uri=proxy_context.url,
                    version=http.version,
                    user_agent=http.user_agent,
                    request_body_len=http.request_body_len,
                    response_body_len=http.response_body_len,
                    status_code=http.status_code,
                    status_msg=http.status_msg,
                    referrer=http.referrer,
                    trans_depth=http.trans_depth,
                    tags=list(http.tags),
                    resp_mime_types=list(http.resp_mime_types),
                )
            else:
                request_body_len = 0
                if proxy_context.method not in ("GET", "HEAD", "CONNECT", "OPTIONS"):
                    request_body_len = proxy_context.cs_bytes
                client_http = HttpContext(
                    method=proxy_context.method,
                    host=proxy_context.host,
                    uri=proxy_context.url,
                    version="1.1",
                    user_agent=proxy_context.user_agent,
                    request_body_len=request_body_len,
                    response_body_len=proxy_context.sc_bytes,
                    status_code=proxy_context.status_code,
                    status_msg="OK" if proxy_context.status_code == 200 else "Forbidden",
                    referrer=proxy_context.referrer,
                    tags=[],
                    resp_mime_types=[proxy_context.content_type]
                    if proxy_context.content_type
                    else [],
                )

            client_orig_bytes = max(1, proxy_context.cs_bytes or orig_bytes or 1)
            client_resp_bytes = max(0, proxy_context.sc_bytes or 0)
            client_duration = min(duration or 0.2, 2.0)
            if dst_port == 443 and proxy_context.status_code < 400:
                rng = _get_rng()
                client_orig_bytes += max(orig_bytes or 0, rng.randint(180, 900))
                client_resp_bytes += max(resp_bytes or 0, rng.randint(900, 4500))
                client_duration = duration or rng.uniform(0.5, 10.0)

            client_uid = self.generate_connection(
                src_ip=src_ip,
                dst_ip=proxy_sys.ip,
                time=time,
                dst_port=listener_port,
                proto="tcp",
                service="http",
                duration=client_duration,
                orig_bytes=client_orig_bytes,
                resp_bytes=client_resp_bytes,
                src_port=src_port,
                emit_dns=False,
                pid=pid,
                source_system=source_system,
                conn_state=conn_state or "SF",
                http=client_http,
                proxy=proxy_context,
                hostname=self._proxy_fqdn(proxy_sys),
                proxy_bypass=True,
            )

            if proxy_context.status_code >= 400:
                return client_uid

            egress_http = http if dst_port == 80 and service == "http" else None
            egress_delay = timedelta(
                milliseconds=random.Random(
                    _stable_seed(f"proxy_egress_delay:{src_ip}:{dst_ip}:{time.timestamp()}")
                ).lognormvariate(3.0, 0.65)
            )
            if hostname:
                self._emit_dns_lookup(
                    proxy_sys.ip,
                    dst_ip,
                    time + egress_delay,
                    hostname=hostname,
                )
            self.generate_connection(
                src_ip=proxy_sys.ip,
                dst_ip=dst_ip,
                time=time + egress_delay,
                dst_port=dst_port,
                proto=proto,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                emit_dns=False,
                pid=-1,
                source_system=proxy_sys,
                conn_state=conn_state,
                dns=dns,
                ids=ids,
                http=egress_http,
                firewall=firewall,
                hostname=hostname,
                proxy_bypass=True,
            )
            if dst_port == 443:
                self._explicit_proxy_tunnels[tunnel_key] = (time, client_uid)
            return client_uid

        # Emit DNS lookup before connection via causal expansion.
        # The DnsBeforeConnection rule handles caching, SERVFAIL, multi-answer, etc.
        # Only internal hosts generate DNS lookups — external source IPs (e.g.,
        # attacker IPs in storylines) don't query the victim's internal resolver.
        if emit_dns and proto == "tcp" and dst_port not in (53,) and _is_private_ip(src_ip):
            self._expand_and_emit(
                "connection",
                time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                service=service,
                hostname=hostname,
            )

        # Same-host connections are valid for host-based logs (eCAR FLOW)
        # but invisible to network sensors (Zeek/Snort)
        local_only = src_ip == dst_ip

        # Validate connection is not fundamentally invalid (localhost, link-local, multicast)
        is_invalid, reason = _is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            logger.warning(
                "Skipping invalid network connection: %s:%s -> %s:%s proto=%s. "
                "Reason: %s. Check that all systems have routable IPs in the scenario.",
                src_ip,
                src_port or "?",
                dst_ip,
                dst_port,
                proto,
                reason,
            )
            return ""

        # Phase 2.5: Check network topology visibility (skip for local-only)
        # Firewall-denied connections bypass this check — the dispatcher
        # handles source-only visibility for denied traffic (packets never
        # reach the destination, so only source-side sensors see the attempt).
        is_fw_deny = firewall is not None and firewall.action == "deny"
        if not local_only and not is_fw_deny:
            visibility = self._network_visibility or (
                self.dispatcher.visibility_engine if self.dispatcher else None
            )
            if visibility and not visibility.is_connection_visible(src_ip, dst_ip):
                logger.debug(
                    f"Skipping connection {src_ip} -> {dst_ip}: "
                    f"not observable by any configured sensor"
                )
                return ""

        resolved_source_system = source_system
        if (
            resolved_source_system is None
            and hasattr(self, "_ip_to_system")
            and src_ip in self._ip_to_system
        ):
            resolved_source_system = self._ip_to_system[src_ip]

        if proto == "icmp":
            src_port = 0
            dst_port = 0
        elif src_port is None:
            # Determine source OS for correct ephemeral port range
            _src_os = "windows"
            if resolved_source_system:
                _src_os = _get_os_category(resolved_source_system.os)
            src_port = self._allocate_ephemeral_port(src_ip, dst_ip, dst_port, proto, time, _src_os)
        else:
            self._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)

        if pid <= 0:
            pid = self._infer_connection_pid(resolved_source_system, service, dst_port, proto)

        if pid > 0 and resolved_source_system:
            process = self.state_manager.get_process(resolved_source_system.hostname, pid)
            if process and process.start_time and time < process.start_time:
                time = process.start_time + timedelta(milliseconds=1)

        if (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is None
            and hostname
        ):
            ad_domain = getattr(self, "_ad_domain", "corp.local")
            dns_cache_key = (src_ip, hostname, "A")
            ts_epoch = time.timestamp()
            cache_ttl = _dns_base_ttl(hostname, _dns_is_internal_name(hostname, ad_domain))
            last_query = self._dns_cache.get(dns_cache_key, 0)
            if last_query and ts_epoch - last_query < cache_ttl:
                return ""
            self._dns_cache[dns_cache_key] = ts_epoch

        state_source_system = resolved_source_system.hostname if resolved_source_system else ""
        state_source_hostname = ""
        if resolved_source_system:
            state_source_hostname = self._build_host_context(resolved_source_system).fqdn
        close_time = time + timedelta(seconds=duration) if duration is not None else None

        # Phase 1: Allocate IDs from StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto,
            source_system=state_source_system,
            source_hostname=state_source_hostname,
            hostname=hostname or "",
            initiating_pid=pid,
            close_time=close_time,
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        if orig_bytes is not None and resp_bytes is not None:
            self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Protocol-aware connection state selection
        rng = _get_rng()

        # ICMP is connectionless — always OTH regardless of what the caller passed
        if proto == "icmp":
            conn_state = "OTH"
            history = "-"
            src_port = 0  # ICMP has no ports; Zeek emits 0
            dst_port = 0
        elif conn_state is not None:
            # Explicit conn_state for TCP/UDP (e.g., UFW BLOCK → REJ)
            history = {
                "REJ": "Sr",
                "S0": "S",
                "SF": "ShADadfF",
                "OTH": "Cc",
                "S2": "ShADadF",
                "S3": "ShADadf",
                "RSTO": "ShADaR",
                "RSTR": "ShADadR",
                "S1": "ShR",
            }.get(conn_state, "ShADadfF")
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                orig_bytes = 0
            elif conn_state in ("S2", "S3"):
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
        elif proto == "udp":
            # DNS connections with responses must not be S0 (no-response)
            if service == "dns" and resp_bytes and resp_bytes > 0:
                # ~5% retransmissions, ~2% multi-packet responses (large TXT/DNSSEC)
                dns_roll = rng.random()
                if dns_roll < 0.05:
                    conn_state, history = "SF", "DDd"  # Retransmitted query
                elif dns_roll < 0.07:
                    conn_state, history = "SF", "Ddd"  # Multi-packet response
                else:
                    conn_state, history = "SF", "Dd"
            else:
                entry = rng.choices(_UDP_CONN_ENTRIES, weights=_UDP_CONN_WEIGHTS, k=1)[0]
                conn_state, _, history = entry
            if conn_state == "S0":
                duration = None
                resp_bytes = 0
        else:
            if duration is not None:
                entry = rng.choices(_TCP_CONN_ENTRIES, weights=_TCP_CONN_WEIGHTS, k=1)[0]
                conn_state, _, history = entry
            else:
                conn_state = "S0"
                history = "S"
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                # S0/REJ: Zeek orig_bytes/resp_bytes are payload (application
                # data), not packet overhead.  No handshake completed → zero payload.
                orig_bytes = 0
            elif conn_state in ("S1", "SH", "SHR"):
                # S1/SH/SHR = partial handshake, no application data transferred.
                # Zeek orig_bytes/resp_bytes are payload bytes (always 0 for
                # handshake-only states); IP-byte totals are computed from packet
                # counts + header overhead downstream.
                orig_bytes = 0
                resp_bytes = 0
                if duration is not None:
                    duration = rng.uniform(0.0, 0.5)
            elif conn_state in ("S2", "S3"):
                # S2/S3 = half-closed: connection established, one side sent FIN
                # but the other never replied. Some data transferred before close.
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
            elif conn_state == "OTH":
                # OTH/Cc = midstream capture fragment — minimal data visible
                orig_bytes = rng.randint(0, 200)
                resp_bytes = rng.randint(0, 200)
                if duration is not None:
                    duration = rng.uniform(0.001, 0.5)

        if proto == "tcp" and service == "ssl" and conn_state == "SF":
            # A completed TLS session with ssl.log/SNI evidence must include
            # at least a ClientHello and server handshake payload at conn.log
            # accounting level, even when the logical request body is empty.
            orig_bytes = max(orig_bytes or 0, rng.randint(180, 900))
            resp_bytes = max(resp_bytes or 0, rng.randint(900, 4500))

        # Calculate packet counts — enforce consistency with history
        if proto == "udp" and history:
            orig_pkts = history.count("D")
            resp_pkts = history.count("d")
            if orig_pkts > 0 and orig_bytes:
                orig_bytes = max(orig_bytes, orig_pkts * 28)
            if resp_pkts > 0 and resp_bytes:
                resp_bytes = max(resp_bytes, resp_pkts * 28)
            elif resp_pkts == 0:
                resp_bytes = 0
        elif proto == "tcp" and history and history != "-":
            hist_orig = sum(1 for c in history if c.isupper())
            hist_resp = sum(1 for c in history if c.islower())
            byte_orig = max(1, (orig_bytes // 1460) + 1) if orig_bytes else 1
            byte_resp = max(1, (resp_bytes // 1460) + 1) if resp_bytes else 0
            orig_pkts = max(hist_orig, byte_orig)
            resp_pkts = max(hist_resp, byte_resp) if resp_bytes else hist_resp
            # Enforce consistency: resp_pkts > 0 requires resp_bytes > 0
            # (orig always has at least the SYN, so orig_pkts stays from history)
            if resp_pkts > 0 and resp_bytes == 0:
                resp_pkts = 0
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0

        if proto == "udp":
            overhead = rng.choices(_UDP_OVERHEAD_VALUES, weights=_UDP_OVERHEAD_WEIGHTS, k=1)[0]
        else:
            overhead = rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
        # IP bytes = payload + (packets * header overhead). Handshake-only states
        # have 0 payload bytes but still have packet-level IP bytes from SYN/SYN-ACK.
        orig_ip_bytes = ((orig_bytes or 0) + orig_pkts * overhead) if orig_pkts else None
        resp_ip_bytes = ((resp_bytes or 0) + resp_pkts * overhead) if resp_pkts else None

        ip_proto = 6 if proto == "tcp" else 17 if proto == "udp" else 1

        # Probabilistic missed_bytes for long TCP connections (~3% chance, more for bulk transfers)
        missed_bytes = 0
        if proto == "tcp" and duration and duration > 10.0 and rng.random() < 0.03:
            missed_bytes = rng.randint(500, 50000)

        # Port-based service correction (Zeek detects service from payload, not scenario labels)
        _PORT_SERVICE = {
            80: "http",
            443: "ssl",
            22: "ssh",
            53: "dns",
            25: "smtp",
            587: "smtp",
            88: "kerberos",
            389: "ldap",
            445: "smb",
        }
        if service and dst_port in _PORT_SERVICE and service != _PORT_SERVICE[dst_port]:
            service = _PORT_SERVICE[dst_port]

        # Phase 2: Build SecurityEvent with NetworkContext + HostContext
        # Resolve source system for src_host (needed by eCAR emitter for hostname/routing)
        src_host_ctx = None
        if resolved_source_system:
            src_host_ctx = self._build_host_context(resolved_source_system)

        # Resolve destination system for dst_host
        dst_host_ctx = None
        if hasattr(self, "_ip_to_system") and dst_ip in self._ip_to_system:
            dst_host_ctx = self._build_host_context(self._ip_to_system[dst_ip])
        elif self.dispatcher and self.dispatcher.visibility_engine:
            real_dst_ip = self.dispatcher.visibility_engine._vip_to_real_ip.get(dst_ip)
            if real_dst_ip and real_dst_ip in self._ip_to_system:
                dst_host_ctx = self._build_host_context(self._ip_to_system[real_dst_ip])

        # Resolve eCAR actor_id from initiating process (if pid is known)
        conn_actor_id = ""
        if pid > 0 and resolved_source_system:
            conn_actor_id = self.state_manager.get_process_object_id(
                resolved_source_system.hostname, pid
            )

        event = SecurityEvent(
            timestamp=time,
            event_type="connection",
            src_host=src_host_ctx,
            dst_host=dst_host_ctx,
            local_only=local_only,
            network=NetworkContext(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=service or "",
                zeek_uid=uid,
                conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes,
                resp_ip_bytes=resp_ip_bytes,
                conn_state=conn_state,
                history=history,
                local_orig=_is_private_ip(src_ip),
                local_resp=_is_private_ip(dst_ip),
                ip_proto=ip_proto,
                missed_bytes=missed_bytes,
                initiating_pid=pid,
            ),
            edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=conn_actor_id),
        )

        # Caller-provided context overrides
        if ids is not None:
            event.ids = ids
        if http is not None:
            event.http = http
        if proxy is not None:
            event.proxy = proxy
        if firewall is not None:
            event.firewall = firewall

        # DNS context for Zeek dns.log fan-out
        if dns is not None:
            event.dns = dns
        elif service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            dns_query = hostname or REVERSE_DNS.get(dst_ip) or f"host-{dst_ip.replace('.', '-')}"
            event.dns = DnsContext(
                query=dns_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NOERROR" if resp_bytes else "SERVFAIL",
                rcode_num=0 if resp_bytes else 2,
                answers=[dst_ip] if resp_bytes else [],
                TTLs=[
                    float(
                        _dns_base_ttl(
                            dns_query,
                            _dns_is_internal_name(dns_query, getattr(self, "_ad_domain", "")),
                        )
                    )
                ]
                if resp_bytes
                else [],
                rtt=_dns_rtt(rng, dst_ip) if resp_bytes else None,
            )

        # Proxy context: attach only for established outbound internet traffic.
        # Forward proxies only see egress that completes (not blocked/denied flows).
        if (
            not local_only
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and event.proxy is None
            and not _is_private_ip(dst_ip)
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        ):
            proxy_routes = getattr(self, "_proxy_routes", {})
            chain = proxy_routes.get(src_ip)
            if chain:
                from evidenceforge.events.contexts import ProxyContext

                proxy_sys = chain[0]
                proxy_fqdn = getattr(proxy_sys, "hostname", "")
                # Build proxy FQDN from hostname + domain
                ad_domain = getattr(self, "_ad_domain", "")
                if ad_domain and "." not in proxy_fqdn:
                    proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
                # Hostname was resolved once at the top of generate_connection().
                proxy_hostname = hostname
                if proxy_hostname is None and dns is not None and dns.query:
                    proxy_hostname = dns.query
                if proxy_hostname is None:
                    proxy_hostname = REVERSE_DNS.get(dst_ip)
                if proxy_hostname is None:
                    proxy_hostname = _generate_random_hostname(_get_rng(), dst_ip)
                # Suppressed hostname → use raw IP for proxy logging
                if proxy_hostname == "":
                    proxy_hostname = dst_ip
                from evidenceforge.generation.activity.dns_registry import get_domain_tags
                from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

                domain_tags = get_domain_tags(proxy_hostname)

                # When a pre-built HttpContext exists (from browsing session
                # generator), derive proxy fields from it.  The proxy emitter
                # handles CONNECT tunnel deduplication automatically.
                if event.http is not None:
                    scheme = "https" if dst_port == 443 else "http"
                    proxy_method = event.http.method
                    url = f"{scheme}://{proxy_hostname}{event.http.uri}"
                    proxy_content_type = (
                        event.http.resp_mime_types[0] if event.http.resp_mime_types else "text/html"
                    )
                    proxy_ua_override = None  # session UA is already on HttpContext
                    user_agent = event.http.user_agent
                    proxy_referrer = event.http.referrer
                elif dst_port == 443:
                    # Legacy single-connection HTTPS path
                    _src_os = _get_os_category(source_system.os) if source_system else None
                    path, proxy_content_type, proxy_method, proxy_ua_override = pick_proxy_uri(
                        _get_rng(), proxy_hostname, domain_tags, source_os=_src_os
                    )
                    url = f"https://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = pick_referrer(rng, proxy_hostname, context="general", port=443)
                else:
                    _src_os = _get_os_category(source_system.os) if source_system else None
                    path, proxy_content_type, proxy_method, proxy_ua_override = pick_proxy_uri(
                        _get_rng(), proxy_hostname, domain_tags, source_os=_src_os
                    )
                    url = f"http://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = pick_referrer(rng, proxy_hostname, context="general", port=80)
                # OS-aware proxy User-Agent selection (skip when session set it)
                if event.http is None:
                    if proxy_ua_override:
                        user_agent = proxy_ua_override
                    else:
                        user_agent = pick_proxy_user_agent(
                            rng,
                            source_system,
                            hostname=proxy_hostname,
                            domain_tags=domain_tags,
                        )
                cache_roll = rng.random()
                if cache_roll < 0.30:
                    cache_result = "HIT"
                elif cache_roll < 0.95:
                    cache_result = "MISS"
                else:
                    cache_result = "DENIED"
                # Proxy byte counts differ from wire bytes: header overhead,
                # cache effects, and proxy error pages.
                _cs = (orig_bytes or 0) + rng.randint(*_PROXY_CS_OVERHEAD)
                if cache_result == "DENIED":
                    _sc = rng.randint(500, 2000)  # proxy error page
                elif cache_result == "HIT":
                    _rb = max(1, resp_bytes or 0)
                    _sc = rng.randint(max(1, int(_rb * 0.4)), max(2, int(_rb * 1.1)))
                else:
                    _sc = (resp_bytes or 0) + rng.randint(*_PROXY_SC_OVERHEAD)
                event.proxy = ProxyContext(
                    client_ip=src_ip,
                    method=proxy_method,
                    url=url,
                    host=proxy_hostname,
                    status_code=200 if cache_result != "DENIED" else 403,
                    sc_bytes=_sc,
                    cs_bytes=_cs,
                    time_taken=int((duration or 0) * 1000),
                    user_agent=user_agent,
                    content_type=proxy_content_type,
                    cache_result=cache_result,
                    referrer=proxy_referrer,
                    proxy_fqdn=proxy_fqdn,
                )

        # Zeek protocol-layer contexts: populate SSL/HTTP/files for fan-out
        # Skip for local-only events (no network sensor will see them)
        rng = _get_rng()
        if not local_only and service == "ssl" and proto == "tcp" and conn_state == "SF":
            self._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=True,
            )

        elif (
            not local_only
            and service == "http"
            and proto == "tcp"
            and conn_state == "SF"
            and event.http is None  # Skip auto-generation if caller provided HttpContext
        ):
            _USER_AGENTS_WINDOWS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ]
            _USER_AGENTS_LINUX = [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "curl/7.88.1",
                "python-requests/2.31.0",
                "Wget/1.21.3",
            ]
            if source_system and _get_os_category(source_system.os) == "linux":
                ua = rng.choice(_USER_AGENTS_LINUX)
            else:
                ua = rng.choice(_USER_AGENTS_WINDOWS)
            # Use the already-resolved hostname for HTTP Host header and URI templates.
            # Honor hostname="" (suppressed) — use raw IP instead of REVERSE_DNS.
            host = hostname if hostname is not None else REVERSE_DNS.get(dst_ip, dst_ip)
            if host == "":
                host = dst_ip
            if dst_port not in (80, 443):
                host = f"{host}:{dst_port}"
            from evidenceforge.generation.activity.dns_registry import get_domain_tags
            from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

            web_host = hostname if hostname is not None else REVERSE_DNS.get(dst_ip, dst_ip)
            if web_host == "":
                web_host = dst_ip
            web_domain_tags = get_domain_tags(web_host)
            _src_os_http = _get_os_category(source_system.os) if source_system else None
            uri, mime_type, http_method, http_ua_override = pick_proxy_uri(
                rng, web_host, web_domain_tags, source_os=_src_os_http
            )
            if http_ua_override:
                ua = http_ua_override
            status_code, status_msg = _get_http_status(dst_ip, uri)
            resp_body_len = resp_bytes or rng.randint(200, 50000)
            if status_code in (301, 302):
                resp_body_len = rng.randint(100, 300)
            elif status_code == 304:
                resp_body_len = 0
            from evidenceforge.generation.activity.referrer import pick_referrer

            _http_referer = pick_referrer(rng, host, context="general", port=dst_port)
            event.http = HttpContext(
                method=http_method,
                host=host,
                uri=uri,
                version="1.1",
                user_agent=ua,
                request_body_len=rng.randint(50, 2000) if http_method == "POST" else 0,
                response_body_len=resp_body_len,
                status_code=status_code,
                status_msg=status_msg,
                referrer=_http_referer,
                resp_mime_types=[mime_type] if status_code == 200 else [],
                tags=[],
            )
            # Probabilistic file transfer for HTTP responses with content
            if resp_body_len > 100 and rng.random() < 0.3:
                from evidenceforge.events.contexts import FileTransferContext
                from evidenceforge.utils.ids import generate_zeek_uid

                fuid = generate_zeek_uid("F")
                event.file_transfer = FileTransferContext(
                    fuid=fuid,
                    source="HTTP",
                    depth=0,
                    analyzers=[],
                    mime_type=mime_type,
                    duration=rng.uniform(0.0, 0.01),
                    local_orig=_is_private_ip(dst_ip),
                    is_orig=False,
                    seen_bytes=resp_body_len,
                    total_bytes=resp_body_len,
                    missing_bytes=0,
                    overflow_bytes=0,
                    timedout=False,
                )
                event.http.resp_fuids = [fuid]
                event.http.resp_mime_types = [event.file_transfer.mime_type]

                # PE analysis for Windows executables in file transfers
                if (
                    mime_type in ("application/x-dosexec", "application/octet-stream")
                    and rng.random() < 0.1
                ):
                    from evidenceforge.events.contexts import PeContext

                    is_64 = rng.random() < 0.7
                    event.pe = PeContext(
                        id=fuid,
                        machine="AMD64" if is_64 else "I386",
                        compile_ts=event.timestamp.timestamp()
                        - rng.randint(86400, 86400 * 365 * 3),
                        is_exe=True,
                        is_64bit=is_64,
                        uses_aslr=rng.random() < 0.8,
                        uses_dep=rng.random() < 0.9,
                        uses_code_integrity=rng.random() < 0.1,
                        has_import_table=True,
                        has_export_table=rng.random() < 0.2,
                        has_cert_table=rng.random() < 0.3,
                        has_debug_data=rng.random() < 0.4,
                    )

        if (
            event.file_transfer is None
            and service == "smb"
            and proto == "tcp"
            and dst_port == 445
            and event.network.conn_state == "SF"
        ):
            from evidenceforge.events.contexts import FileTransferContext
            from evidenceforge.generation.activity.smb_file_transfers import (
                load_smb_file_transfers,
            )
            from evidenceforge.utils.ids import generate_zeek_uid

            smb_config = load_smb_file_transfers()
            min_transfer_bytes = int(smb_config.get("min_transfer_bytes", 32768))
            transfer_bytes = max(event.network.orig_bytes or 0, event.network.resp_bytes or 0)
            if transfer_bytes >= min_transfer_bytes:
                mime_entries = smb_config.get("mime_types", [])
                analyzer_entries = smb_config.get("analyzer_sets", [])
                mime_type = "application/octet-stream"
                if mime_entries:
                    mime_values = [
                        str(entry.get("mime_type", "application/octet-stream"))
                        for entry in mime_entries
                    ]
                    mime_weights = [int(entry.get("weight", 1)) for entry in mime_entries]
                    mime_type = rng.choices(
                        mime_values,
                        weights=mime_weights,
                        k=1,
                    )[0]
                analyzers: list[str] = []
                if analyzer_entries:
                    analyzer_values = [entry.get("analyzers", []) for entry in analyzer_entries]
                    analyzer_weights = [int(entry.get("weight", 1)) for entry in analyzer_entries]
                    analyzers = list(
                        rng.choices(
                            analyzer_values,
                            weights=analyzer_weights,
                            k=1,
                        )[0]
                    )
                missing_probability = float(smb_config.get("missing_bytes_probability", 0.0))
                timeout_probability = float(smb_config.get("timeout_probability", 0.0))
                missing_bytes = (
                    rng.randint(1, max(1, min(65536, transfer_bytes // 20)))
                    if rng.random() < missing_probability
                    else 0
                )
                event.file_transfer = FileTransferContext(
                    fuid=generate_zeek_uid("F"),
                    source="SMB",
                    depth=0,
                    analyzers=analyzers,
                    mime_type=mime_type,
                    duration=max(0.0, (event.network.duration or 0.0) * rng.uniform(0.6, 0.98)),
                    local_orig=_is_private_ip(event.network.src_ip),
                    is_orig=(event.network.orig_bytes or 0) >= (event.network.resp_bytes or 0),
                    seen_bytes=max(0, transfer_bytes - missing_bytes),
                    total_bytes=transfer_bytes,
                    missing_bytes=missing_bytes,
                    overflow_bytes=0,
                    timedout=rng.random() < timeout_probability,
                )

        # NTP context for Zeek ntp.log fan-out
        if not local_only and service == "ntp" and proto == "udp":
            from evidenceforge.events.contexts import NtpContext

            ntp_rng = _get_rng()
            ntp_epoch = time.timestamp()
            # Stratum-aware timing via log-normal distribution
            stratum = (_stable_seed(f"ntp_stratum_{dst_ip}") % 3) + 1
            _ntp_mean_ms, _ntp_sigma = _NTP_STRATUM_TIMING.get(stratum, (10.0, 0.7))
            _ntp_mu = math.log(_ntp_mean_ms) - (_ntp_sigma**2) / 2
            rtt_sec = ntp_rng.lognormvariate(_ntp_mu, _ntp_sigma) / 1000.0
            proc_sec = ntp_rng.lognormvariate(math.log(0.5) - 0.3**2 / 2, 0.3) / 1000.0
            ntp_jitter = ntp_rng.uniform(-0.005, 0.005)
            event.ntp = NtpContext(
                version=ntp_rng.choice([3, 4]),
                mode=4,  # server response
                stratum=stratum,
                poll=float(ntp_rng.choice([64, 128, 256, 512, 1024])),
                precision=float(ntp_rng.randint(-25, -18)),
                root_delay=ntp_rng.uniform(0.0, 0.1),
                root_disp=ntp_rng.uniform(0.0, 0.05),
                ref_id=random.Random(_stable_seed(f"ntp_refid_{dst_ip}")).choice(
                    [".GPS.", ".PPS.", ".GOES.", ".DCFa.", ".ACTS."]
                ),
                ref_ts=round(ntp_epoch - ntp_rng.uniform(30, 300), 6),
                org_ts=round(ntp_epoch + ntp_jitter, 6),
                rec_ts=round(ntp_epoch + ntp_jitter + rtt_sec, 6),
                xmt_ts=round(ntp_epoch + ntp_jitter + rtt_sec + proc_sec, 6),
            )

        # Enforce conn_state/HTTP consistency: if HTTP context exists,
        # the connection must have completed successfully (SF). A connection
        # with a handshake-only, reset, or half-close state cannot have served
        # a Zeek HTTP transaction with request/response body accounting.
        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state != "SF"
        ):
            event.network.conn_state = "SF"
            event.network.history = "ShADadfF"
            if event.network.duration is None:
                event.network.duration = rng.uniform(0.01, 2.0)

        if event.network.protocol == "tcp" and event.network.conn_state == "SF":
            if event.http is not None:
                event.network.orig_bytes = max(
                    event.network.orig_bytes or 0,
                    event.http.request_body_len or 0,
                    rng.randint(180, 520),
                )
                event.network.resp_bytes = max(
                    event.network.resp_bytes or 0,
                    event.http.response_body_len or 0,
                    rng.randint(90, 450),
                )
            if event.network.service == "ssl":
                event.network.orig_bytes = max(event.network.orig_bytes or 0, rng.randint(180, 900))
                event.network.resp_bytes = max(
                    event.network.resp_bytes or 0, rng.randint(900, 4500)
                )
            hist_orig = sum(1 for c in (event.network.history or "") if c.isupper())
            hist_resp = sum(1 for c in (event.network.history or "") if c.islower())
            event.network.orig_pkts = max(
                hist_orig, max(1, ((event.network.orig_bytes or 0) // 1460) + 1)
            )
            event.network.resp_pkts = max(
                hist_resp, max(1, ((event.network.resp_bytes or 0) // 1460) + 1)
            )
            overhead = rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
            orig_extra = rng.choices((0, 20, 40, 52, 104), weights=(70, 8, 8, 10, 4), k=1)[0]
            resp_extra = rng.choices((0, 20, 40, 52, 104), weights=(70, 8, 8, 10, 4), k=1)[0]
            event.network.orig_ip_bytes = (
                (event.network.orig_bytes or 0) + event.network.orig_pkts * overhead + orig_extra
            )
            event.network.resp_ip_bytes = (
                (event.network.resp_bytes or 0) + event.network.resp_pkts * overhead + resp_extra
            )

        if (
            not local_only
            and event.network.service == "ssl"
            and event.network.conn_state == "SF"
            and event.ssl is None
        ):
            self._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=False,
            )

        # Zeek weird.log: condition-driven network anomalies. Select after
        # HTTP/TLS consistency adjustments so partial/reset weirds cannot remain
        # attached to connections later normalized to clean SF application logs.
        weird_candidates: list[tuple[str, str, float]] = []
        final_state = event.network.conn_state
        final_service = event.network.service
        if event.network.protocol == "tcp":
            if final_state in ("S0", "S1", "SH", "SHR"):
                weird_candidates.extend(
                    [
                        ("connection_originator_SYN_ack", "TCP", 0.03),
                        ("truncated_header", "TCP", 0.015),
                    ]
                )
            elif final_state in ("RSTO", "RSTR"):
                weird_candidates.extend(
                    [
                        ("inappropriate_FIN", "TCP", 0.035),
                        ("above_hole_data_without_any_acks", "TCP", 0.02),
                    ]
                )
            elif event.network.missed_bytes:
                weird_candidates.append(("above_hole_data_without_any_acks", "TCP", 0.20))
            elif (
                final_state == "SF"
                and event.network.duration
                and event.network.duration > 60
                and (event.network.orig_bytes or 0) + (event.network.resp_bytes or 0) > 500_000
            ):
                weird_candidates.append(("window_recision", "TCP", 0.003))
            elif final_state != "SF" and final_service != "ssl":
                weird_candidates.append(("bad_TCP_checksum", "TCP", 0.0015))
        elif event.network.protocol == "udp":
            if final_service == "dns":
                weird_candidates.extend(
                    [
                        ("DNS_truncated_len_lt_hdr_len", "UDP", 0.002),
                        ("DNS_RR_unknown_type", "UDP", 0.0015),
                    ]
                )
            else:
                weird_candidates.extend(
                    [
                        ("bad_UDP_checksum", "UDP", 0.001),
                        ("UDP_datagram_length_mismatch", "UDP", 0.0008),
                    ]
                )

        weird_roll = rng.random()
        cumulative = 0.0
        selected_weird: tuple[str, str] | None = None
        for name, source, probability in weird_candidates:
            cumulative += probability
            if weird_roll < cumulative:
                selected_weird = (name, source)
                break
        if not local_only and selected_weird is not None:
            from evidenceforge.events.contexts import WeirdContext

            event.weird = WeirdContext(name=selected_weird[0], source=selected_weird[1])

        # Phase 3: Dispatch to matching emitters (visibility handled by dispatcher)
        self.dispatcher.dispatch(event)
        logger.debug(f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})")

        # Emit 5156 (WFP connection) on Windows source hosts
        if source_system and _get_os_category(source_system.os) == "windows":
            self.generate_wfp_connection(
                system=source_system,
                time=time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                pid=pid if pid > 0 else 4,
            )

        return uid

    def generate_ssh_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_system: Optional["System"] = None,
        source_port: int | None = None,
        sshd_pid: int | None = None,
        logon_id: str = "",
        session_obj_id: str = "",
    ) -> str:
        """Generate an SSH session as a compound event (Zeek conn + syslog auth + eCAR).

        Builds a single SecurityEvent with Auth+Host+Network contexts and dispatches
        to all matching emitters. Each emitter renders its format-specific view:
        - SyslogEmitter: "Accepted password for user from ip port N ssh2"
        - ZeekEmitter: conn.log record with service=ssh, port 22
        - EcarEmitter: USER_SESSION/LOGIN event

        Args:
            user: User initiating the SSH connection
            target_system: Target Linux system
            time: Connection timestamp
            source_ip: Source IP of the SSH client

        Returns:
            Zeek UID for the connection
        """
        from evidenceforge.events.contexts import NetworkContext

        rng = _get_rng()
        _src_os = "windows"
        if source_system is not None:
            _src_os = _get_os_category(source_system.os)
        elif hasattr(self, "_ip_to_system") and source_ip in self._ip_to_system:
            _src_os = _get_os_category(self._ip_to_system[source_ip].os)
        src_port = source_port or _ephemeral_port(rng, _src_os)
        duration = rng.uniform(30.0, 3600.0)
        orig_bytes = rng.randint(2000, 50000)
        resp_bytes = rng.randint(5000, 200000)
        visibility = self._network_visibility or (
            self.dispatcher.visibility_engine if self.dispatcher else None
        )
        network_visible = (
            True
            if visibility is None
            else visibility.is_connection_visible(source_ip, target_system.ip)
        )

        src_host_ctx = None
        if source_system is not None:
            src_host_ctx = self._build_host_context(source_system)
        elif hasattr(self, "_ip_to_system") and source_ip in self._ip_to_system:
            src_host_ctx = self._build_host_context(self._ip_to_system[source_ip])

        if sshd_pid is None:
            sshd_key = logon_id or f"{user.username}_{target_system.hostname}_{time.isoformat()}"
            sshd_pid = 1000 + (_stable_seed(f"sshd_pid_{sshd_key}") % 59000)
        if logon_id and not session_obj_id:
            session_obj_id = self.state_manager.get_session_object_id(logon_id)
            self.state_manager.update_session_metadata(
                logon_id,
                source_port=src_port,
                session_kind="ssh",
                transport_pid=sshd_pid,
            )

        # Allocate connection in StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=source_ip,
            src_port=src_port,
            dst_ip=target_system.ip,
            dst_port=22,
            protocol="tcp",
            source_system=src_host_ctx.hostname if src_host_ctx else "",
            source_hostname=src_host_ctx.fqdn if src_host_ctx else "",
            hostname=self._build_host_context(target_system).fqdn,
            close_time=time + timedelta(seconds=duration),
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Emit DNS for SSH target — only when source is internal (external
        # attacker IPs don't query the victim's internal resolver).
        if _is_private_ip(source_ip):
            self._emit_dns_lookup(source_ip, target_system.ip, time)

        # Build compound SSH session event
        event = SecurityEvent(
            timestamp=time,
            event_type="ssh_session",
            src_host=src_host_ctx,
            dst_host=self._build_host_context(target_system),
            auth=AuthContext(
                username=user.username,
                source_ip=source_ip,
                source_port=src_port,
                logon_id=logon_id,
                logon_type=10,
            ),
            network=NetworkContext(
                src_ip=source_ip,
                src_port=src_port,
                dst_ip=target_system.ip,
                dst_port=22,
                protocol="tcp",
                service="ssh",
                zeek_uid=uid,
                conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                conn_state="SF",
                history="ShADadfF",
                orig_pkts=max(4, orig_bytes // 1460 + 1),
                resp_pkts=max(4, resp_bytes // 1460 + 1),
                local_orig=_is_private_ip(source_ip),
                local_resp=_is_private_ip(target_system.ip),
                ip_proto=6,
            ),
            edr=EdrContext(object_id=session_obj_id),
        )

        # Attach SyslogContext for Linux hosts: 3 syslog entries for SSH session
        if event.dst_host and event.dst_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            # Session ID: monotonic + unique per host. Derived from epoch seconds
            # for call-order independence, with collision handling for same-second sessions.
            hostname = target_system.hostname
            if not hasattr(self, "_session_id_state"):
                self._session_id_state: dict[str, tuple[int, int]] = {}
            if hostname not in self._session_id_state:
                self._session_id_state[hostname] = (0, rng.randint(50, 500))
            _last_epoch, _last_id = self._session_id_state[hostname]
            _epoch_sec = int(time.timestamp())
            _candidate = rng.randint(50, 500) + (_epoch_sec - 1700000000)
            session_id = max(_candidate, _last_id + 1)
            self._session_id_state[hostname] = (_epoch_sec, session_id)

            # sshd connection message (precedes auth in real SSH lifecycle)
            conn_msg_event = SecurityEvent(
                timestamp=time - timedelta(microseconds=rng.randint(1000, 5000)),
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"Connection from {source_ip} port {src_port}"
                        f' on {target_system.ip} port 22 rdomain ""'
                    ),
                ),
            )
            self.dispatcher.dispatch(conn_msg_event)

            # Primary event: sshd Accepted password
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=(
                    f"Accepted password for {user.username} from {source_ip} port {src_port} ssh2"
                ),
            )

        self.dispatcher.dispatch(event)

        # Emit follow-up syslog entries (pam_unix + systemd-logind)
        if event.dst_host and event.dst_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            # pam_unix session opened (syslog-only, no eCAR/Zeek correlation)
            pam_event = SecurityEvent(
                timestamp=time + timedelta(microseconds=rng.randint(1000, 50000)),
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"pam_unix(sshd:session): session opened for user "
                        f"{user.username}(uid={_linux_uid_for_user(user.username)}) by (uid=0)"
                    ),
                ),
            )
            self.dispatcher.dispatch(pam_event)

            # systemd-logind new session (syslog-only)
            logind_event = SecurityEvent(
                timestamp=time + timedelta(microseconds=rng.randint(50000, 80000)),
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="systemd-logind",
                    pid=1000 + (_stable_seed("logind_pid") % 59000),
                    facility=10,
                    severity=6,
                    message=f"New session {session_id} of user {user.username}.",
                ),
            )
            self.dispatcher.dispatch(logind_event)

        logger.debug(
            f"Generated SSH session: {user.username} → {target_system.hostname} (UID: {uid})"
        )
        return uid if network_visible else ""

    def generate_bash_command(
        self, user: User, system: System, time: datetime, activity_type_or_command: str = "default"
    ) -> None:
        """Generate bash command history entry via dispatch.

        Builds a SecurityEvent with ShellContext and dispatches.
        BashHistoryEmitter.can_handle() filters for Linux-only.

        Args:
            user: User executing command
            system: Linux system
            time: Command execution time
            activity_type_or_command: Either an activity type key (process_code, etc.)
                or a direct command string (if it contains spaces or '/')
        """
        from evidenceforge.events.contexts import ShellContext

        # Activity type pools: if the arg matches a known key, pick from pool.
        # Otherwise treat as a literal command (supports typos, direct strings, etc.)
        _activity_type_commands = {
            "process_code": [
                "vim script.py",
                "nano config.conf",
                "code .",
                "git status",
                "git diff",
                "python3 -m pytest",
                "cat README.md",
            ],
            "process_build": [
                "make",
                "gcc -o output source.c",
                "npm run build",
                "docker build -t app .",
                "cargo build --release",
            ],
            "connection_web": [
                "curl https://example.com",
                "wget https://github.com/repo/file.tar.gz",
                "curl -I https://api.example.com/health",
            ],
            "process_query": [
                "mysql -u root -p -e 'SHOW DATABASES'",
                "psql -c '\\l'",
                "redis-cli info",
                "mysql -u root -p -e 'SHOW PROCESSLIST'",
                "psql -c 'SELECT pg_size_pretty(pg_database_size(current_database()))'",
                "sqlite3 /var/lib/app/data.db '.tables'",
            ],
            "process_system": [
                "systemctl status sshd",
                "journalctl -u cron --since '1 hour ago'",
                "top -bn1 | head -20",
                "ss -tulnp",
                "df -h",
                "free -m",
                "dmesg | tail -20",
                "last -10",
            ],
            "process_user_apps": [
                "ls -la",
                "cd /var/www/html",
                "tail -f /var/log/syslog",
                'grep -r "error" /var/log/',
                "systemctl status apache2",
                "free -m",
                "uptime",
                "cat /etc/hostname",
                "netstat -tlnp",
                "du -sh /var/log/*",
                "w",
                'journalctl -u apache2 --since "1 hour ago"',
                "htop",
                "ss -tulnp",
                "ip addr show",
            ],
            "default": [
                "ls -la",
                "ps aux",
                "top",
                "df -h",
                "whoami",
                "pwd",
                "cat /etc/os-release",
                "uptime",
                "free -m",
                "w",
                "tail -20 /var/log/syslog",
                "history",
                "date",
                "ls /tmp",
                "mount | grep -v tmpfs",
            ],
        }

        if activity_type_or_command in _activity_type_commands:
            command_list = _activity_type_commands[activity_type_or_command]
            command = _get_rng().choice(command_list)
        else:
            # Literal command string (direct commands, typos, etc.)
            command = activity_type_or_command

        event = SecurityEvent(
            timestamp=time,
            event_type="bash_command",
            src_host=self._build_host_context(system),
            auth=AuthContext(username=user.username),
            shell=ShellContext(command=command),
        )

        self.dispatcher.dispatch(event)
        logger.debug(f"Generated bash command: {command} by {user.username} on {system.hostname}")

    def generate_bash_command_with_noise(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Generate a bash command with organic noise commands around it.

        Emits the primary command plus 0-3 organic noise commands at
        slight time offsets, simulating an attacker or admin who types
        ls, pwd, id etc. between deliberate actions.
        """
        # Emit the primary command
        self.generate_bash_command(user, system, time, command)

        # Probabilistically emit 0-3 noise commands (role-aware)
        from evidenceforge.generation.activity.bash_commands import pick_bash_command

        rng = _get_rng()
        n_noise = rng.choices([0, 1, 1, 2, 2, 3], k=1)[0]
        # Complexity-aware inter-command delays
        _COMPLEX_PREFIXES = ("nmap", "find ", "tar ", "rsync", "make", "docker", "ansible")
        _MEDIUM_PREFIXES = ("curl", "wget", "scp", "ssh ", "mysql", "psql", "pip", "apt", "yum")
        cumulative_delay = 0.0
        prev_cmd = command
        for _ in range(n_noise):
            # Delay based on complexity of previous command
            if any(prev_cmd.startswith(p) for p in _COMPLEX_PREFIXES):
                delay = rng.uniform(10.0, 60.0)
            elif any(prev_cmd.startswith(p) for p in _MEDIUM_PREFIXES):
                delay = rng.uniform(3.0, 15.0)
            else:
                delay = rng.uniform(1.0, 5.0)
            cumulative_delay += delay
            noise_time = time + timedelta(seconds=cumulative_delay)
            noise_cmd = pick_bash_command(
                rng, user.persona or "", system.hostname, system.services, username=user.username
            )
            self.generate_bash_command(user, system, noise_time, noise_cmd)
            prev_cmd = noise_cmd

    def generate_system_process(
        self,
        system: System,
        time: datetime,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        username: str = "SYSTEM",
        syslog_message: str | None = None,
    ) -> int:
        """Generate a system process creation event (no user session required).

        Used for scheduled tasks, service spawns, and other system-initiated
        processes that don't have an associated user logon session.

        Args:
            system: System where process is created
            time: Process creation timestamp
            process_name: Full path to executable
            command_line: Command line string
            parent_pid: Parent process PID
            username: System account name (SYSTEM, root, etc.)
            syslog_message: Custom syslog message (overrides auto-generated message)

        Returns:
            PID of the new process
        """
        from evidenceforge.events.contexts import ProcessContext

        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=username,
            integrity_level="System",
        )

        # Determine system-level SID and logon ID
        sid = self.sid_registry.get(username, "S-1-5-18") if self.sid_registry else "S-1-5-18"
        system_logon_ids = {"SYSTEM": "0x3e7", "LOCAL SERVICE": "0x3e5", "NETWORK SERVICE": "0x3e4"}
        logon_id = system_logon_ids.get(username, "0x3e7")

        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        parent_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="system_process_create",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=username,
                user_sid=sid,
                logon_id=logon_id,
                subject_sid=sid,
                subject_username=username,
                subject_domain="NT AUTHORITY",
                subject_logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=username,
                integrity_level="System",
                logon_id=logon_id,
                parent_image=self._lookup_parent_image(system.hostname, parent_pid),
                parent_command_line=self._lookup_parent_command_line(system.hostname, parent_pid),
                token_elevation="%%1936",
                mandatory_label="S-1-16-16384",
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
        )

        # Attach SyslogContext for Linux hosts
        if event.src_host and event.src_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            if syslog_message:
                event.syslog = SyslogContext(
                    app_name="systemd",
                    pid=1,
                    facility=3,
                    severity=6,
                    message=syslog_message,
                )
            elif "cron" in (process_name or "").lower():
                event.syslog = SyslogContext(
                    app_name="CRON",
                    pid=pid,
                    facility=9,
                    severity=6,
                    message=f"({username}) CMD ({command_line})",
                )
            else:
                app_name = process_name.split("/")[-1]
                event.syslog = SyslogContext(
                    app_name=app_name,
                    pid=pid,
                    facility=3,
                    severity=6,
                    message=f"started: {command_line}",
                )

        self.dispatcher.dispatch(event)

        return pid

    def generate_system_process_termination(
        self,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        parent_pid: int = 0,
        username: str = "root",
        syslog_message: str | None = None,
    ) -> None:
        """Terminate a system process, emitting eCAR PROCESS/TERMINATE + optional syslog.

        Unlike generate_process_termination(), this doesn't require a user session.
        Used for short-lived system service processes (systemd units, etc.).
        """
        from evidenceforge.events.contexts import ProcessContext

        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_terminate",
            src_host=self._build_host_context(system),
            auth=AuthContext(username=username),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line="",
                username=username,
            ),
            edr=EdrContext(object_id=proc_obj_id),
        )

        if syslog_message and event.src_host and event.src_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            event.syslog = SyslogContext(
                app_name="systemd",
                pid=1,
                facility=3,
                severity=6,
                message=syslog_message,
            )

        self.dispatcher.dispatch(event)

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        hostname: str | None = None,
    ) -> None:
        """Emit a DNS lookup preceding a TCP connection.

        Generates both a Zeek conn.log UDP/53 record and a Zeek dns.log record
        with consistent fields. The dns.log answers field contains the dst_ip
        that the subsequent TCP connection will use.

        Args:
            src_ip: IP of the system making the query
            dst_ip: IP that will be resolved (the "answer")
            time: Timestamp of the DNS query (should precede TCP connection)
            hostname: Explicit domain name to use (bypasses REVERSE_DNS lookup)
        """
        rng = _get_rng()

        # Use explicit hostname if provided (domain-first selection),
        # otherwise fall back to REVERSE_DNS lookup
        if not hostname:
            hostname = REVERSE_DNS.get(dst_ip)
        if not hostname:
            if _is_private_ip(dst_ip):
                hostname = _generate_internal_hostname(
                    rng, dst_ip, getattr(self, "_ad_domain", "corp.local")
                )
            else:
                hostname = _generate_random_hostname(rng, dst_ip)

        # DNS caching: skip re-emission if this (src, hostname) was queried recently.
        # Real clients cache DNS responses (TTL typically 60-3600s), so not every
        # connection is preceded by a DNS query.
        if not hasattr(self, "_dns_cache"):
            self._dns_cache: dict[tuple[str, str], float] = {}
        if not hasattr(self, "_dns_cache_last_prune"):
            self._dns_cache_last_prune = 0.0

        cache_key = (src_ip, hostname)
        ts_epoch = time.timestamp()

        # Keep the cache bounded: drop entries older than the max TTL horizon,
        # and enforce a hard cap under high-cardinality/adversarial inputs.
        if ts_epoch - self._dns_cache_last_prune >= 60 or len(self._dns_cache) > 50_000:
            max_ttl_window = 86_400
            cutoff = ts_epoch - max_ttl_window
            self._dns_cache = {
                key: cached_at for key, cached_at in self._dns_cache.items() if cached_at >= cutoff
            }
            if len(self._dns_cache) > 50_000:
                sorted_items = sorted(
                    self._dns_cache.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
                self._dns_cache = dict(sorted_items[:50_000])
            self._dns_cache_last_prune = ts_epoch

        ad_domain = getattr(self, "_ad_domain", "corp.local")
        is_internal = _dns_is_internal_name(hostname, ad_domain)
        authoritative_ttl = _dns_base_ttl(hostname, is_internal)

        last_query = self._dns_cache.get(cache_key, 0)
        cache_ttl = authoritative_ttl if is_internal else min(authoritative_ttl, 600)
        if last_query and ts_epoch - last_query < cache_ttl:
            return  # Cache hit — skip DNS emission

        # Determine DNS server IP from network visibility or use default. Forward
        # proxies often use upstream resolvers for Internet destinations; this
        # also keeps explicit-proxy DNS visible when the proxy and DC share a
        # same-segment TAP that would not observe local resolver traffic.
        dns_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
        src_system = getattr(self, "_ip_to_system", {}).get(src_ip)
        if src_system and "forward_proxy" in (src_system.roles or []) and not is_internal:
            dns_server_ip = _get_rng().choice(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        else:
            dns_server_ip = _get_rng().choice(dns_ips)

        _src_os = "windows"
        if src_system is not None:
            _src_os = _get_os_category(src_system.os)
        dns_time = time - timedelta(milliseconds=rng.randint(10, 50))
        src_port = self._allocate_ephemeral_port(
            src_ip, dns_server_ip, 53, "udp", dns_time, _src_os
        )

        from evidenceforge.events.contexts import DnsContext

        # Phase 6.3: 0.2% chance of SERVFAIL (transient failures)
        if rng.random() < 0.002:
            dns_ctx = DnsContext(
                query=hostname,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="SERVFAIL",
                rcode_num=2,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=dns_server_ip,
                time=dns_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.03),
                orig_bytes=rng.randint(40, 100),
                resp_bytes=rng.randint(80, 400),
                src_port=src_port,
                dns=dns_ctx,
            )
            return

        # Determine query type, query string, and answer
        qtype_roll = rng.random()

        if qtype_roll < 0.65:
            # A record: hostname → IPv4
            qtype, qtype_name = 1, "A"
            query = hostname
            # Multi-answer: CDNs/clouds return multiple A records (40% chance)
            if not is_internal and rng.random() < 0.40:
                from evidenceforge.generation.activity.dns_registry import get_domain_ips

                domain_ips = get_domain_ips(hostname) if hostname else []
                sibling_ips = [ip for ip in domain_ips if ip != dst_ip]
                if sibling_ips:
                    extra = rng.sample(sibling_ips, min(rng.randint(1, 2), len(sibling_ips)))
                    answers = [dst_ip] + extra
                else:
                    answers = [dst_ip]
            else:
                answers = [dst_ip]
        elif qtype_roll < 0.85:
            # AAAA record: hostname → IPv6
            qtype, qtype_name = 28, "AAAA"
            query = hostname
            ipv6_answer = _IPV6_MAP.get(dst_ip)
            if ipv6_answer is not None:
                answers = [ipv6_answer]
            elif ":" in dst_ip:
                # Already IPv6 (not present in registry map) — use as-is.
                answers = [dst_ip]
            else:
                answers = [_ipv4_to_fake_ipv6(dst_ip)]
        elif qtype_roll < 0.93:
            # PTR record: reversed IP → rDNS name
            qtype, qtype_name = 12, "PTR"
            octets = dst_ip.split(".")
            query = ".".join(reversed(octets)) + ".in-addr.arpa"
            if _is_private_ip(dst_ip):
                answers = [hostname]
            else:
                answers = [_generate_rdns_name(rng, dst_ip, hostname)]
        elif qtype_roll < 0.98:
            # SRV record: AD service discovery — must resolve to DCs only
            qtype, qtype_name = 33, "SRV"
            domain = ad_domain
            query = rng.choice(_AD_SRV_QUERIES).format(domain=domain)
            dc_systems = getattr(self, "_dc_systems", [])
            if dc_systems:
                dc_sys = _get_rng().choice(dc_systems)
                dc_ip = dc_sys.ip
            else:
                dc_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
                dc_ip = _get_rng().choice(dc_ips)
            dc_hostname = REVERSE_DNS.get(dc_ip, f"dc-01.{domain}")
            svc_prefix = query.split(".")[0]
            port = _SRV_PORT_MAP.get(svc_prefix, 389)
            answers = [f"0 100 {port} {dc_hostname}"]
            is_internal = True
        elif qtype_roll < 0.995:
            # TXT record: SPF/DKIM/DMARC-style mail/authentication lookups.
            qtype, qtype_name = 16, "TXT"
            query, txt_answer = _dns_txt_query_and_answer(rng, hostname)
            answers = [txt_answer]
        else:
            # MX record: domain → mail server
            if _dns_hostname_allows_mx(hostname):
                qtype, qtype_name = 15, "MX"
                query = _dns_registrable_domain(hostname)
                answers = [f"10 mail.{query}"]
            else:
                qtype, qtype_name = 16, "TXT"
                query, txt_answer = _dns_txt_query_and_answer(rng, hostname)
                answers = [txt_answer]

        query_is_internal = qtype_name == "SRV" or _dns_is_internal_name(query, ad_domain)
        if query_is_internal and not _is_private_ip(dns_server_ip):
            dns_server_ip = _get_rng().choice(dns_ips)
            src_port = self._allocate_ephemeral_port(
                src_ip, dns_server_ip, 53, "udp", dns_time, _src_os
            )
        is_internal = query_is_internal

        # Internal authoritative names use stable TTLs. External answers may be
        # observed through a resolver cache, so expose realistic countdown TTLs.
        base_ttl = _dns_base_ttl(query, is_internal)
        if is_internal:
            shared_ttl = float(base_ttl)
        else:
            cache_age = rng.randint(0, max(1, base_ttl - 1))
            shared_ttl = float(max(1, base_ttl - cache_age))
        ttls = [shared_ttl] * len(answers)

        # Only address lookups for the requested hostname populate the client
        # DNS cache. PTR/SRV/MX companions should not hide future A/AAAA
        # evidence for high-volume proxy or browser destinations.
        if query == hostname and qtype in (1, 28):
            self._dns_cache[cache_key] = ts_epoch

        # Build DnsContext and emit connection + dns.log via fan-out
        dns_ctx = DnsContext(
            query=query,
            trans_id=rng.randint(1, 65535),
            qtype=qtype,
            query_type=qtype_name,
            rcode="NOERROR",
            rcode_num=0,
            answers=answers,
            TTLs=ttls,
            rtt=_dns_rtt(rng, dns_server_ip),
            AA=is_internal,
            RD=True,
            RA=True,
        )
        self.generate_connection(
            src_ip=src_ip,
            dst_ip=dns_server_ip,
            time=dns_time,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(40, 100),
            resp_bytes=rng.randint(80, 400),
            src_port=src_port,
            dns=dns_ctx,
        )

        # Occasional resolver search-suffix mistakes/background discovery probes.
        # Keep this low-volume and avoid doubling an already-qualified internal name.
        if rng.random() < 0.05:
            suffix_queries: list[str] = []
            if (
                hostname
                and "." in hostname
                and not hostname.endswith(f".{ad_domain}")
                and not hostname.endswith(".local")
            ):
                suffix_queries.append(f"{hostname}.{ad_domain}")
            nxdomain_queries = [
                f"wpad.{ad_domain}",
                "wpad.local",
                "wpad",
                f"isatap.{ad_domain}",
                "isatap",
                f"_ldap._tcp.Default-First-Site-Name._sites.{ad_domain}",
                f"oldserver.{ad_domain}",
                f"printer01.{ad_domain}",
            ]
            nxdomain_queries = suffix_queries + nxdomain_queries
            nx_query = rng.choice(nxdomain_queries)
            nx_time = dns_time - timedelta(milliseconds=rng.randint(1, 10))
            nx_is_internal = _dns_is_internal_name(nx_query, ad_domain) or nx_query in {
                "wpad",
                "wpad.local",
                "isatap",
            }
            nx_dns_server_ip = dns_server_ip
            if nx_is_internal and not _is_private_ip(nx_dns_server_ip):
                nx_dns_server_ip = _get_rng().choice(dns_ips)
            nx_src_port = self._allocate_ephemeral_port(
                src_ip, nx_dns_server_ip, 53, "udp", nx_time, _src_os
            )
            nx_ctx = DnsContext(
                query=nx_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NXDOMAIN",
                rcode_num=3,
                rtt=_dns_rtt(rng, nx_dns_server_ip),
                AA=nx_is_internal,
                RD=True,
                RA=True,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=nx_dns_server_ip,
                time=nx_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.01),
                orig_bytes=rng.randint(40, 80),
                resp_bytes=rng.randint(80, 200),
                src_port=nx_src_port,
                dns=nx_ctx,
            )

    def get_baseline_pattern(
        self,
        persona_name: str | None,
        persona=None,
    ) -> list[tuple[str, float]]:
        """Get baseline activity pattern for persona.

        Phase 2.6: If persona has activity_intensity overrides, builds
        dynamic pattern from those. Otherwise falls back to hardcoded patterns.

        Args:
            persona_name: Persona name string (or None for default)
            persona: Optional resolved Persona object for dynamic patterns

        Returns:
            List of (activity_type, probability) tuples
        """
        # Phase 2.6: Use activity_intensity overrides if provided
        if persona and persona.activity_intensity:
            return self._build_pattern_from_intensity(persona.activity_intensity)

        # Fall back to hardcoded patterns (Phase 1 behavior)
        if persona_name and persona_name.lower() in BASELINE_PATTERNS:
            return BASELINE_PATTERNS[persona_name.lower()]
        return BASELINE_PATTERNS["default"]

    def _build_pattern_from_intensity(self, intensity: dict[str, int]) -> list[tuple[str, float]]:
        """Convert activity_intensity dict to baseline pattern.

        Maps intensity values to probabilities. Higher intensity = higher probability.

        Args:
            intensity: Dict mapping activity_type to events/hour intensity

        Returns:
            List of (activity_type, probability) tuples
        """
        # Always include logon
        pattern: list[tuple[str, float]] = [("logon", 0.9)]

        if not intensity:
            return pattern

        # Normalize intensities to probabilities (cap at 0.95).
        # Ignore non-positive values when determining the denominator so an
        # all-zero (or all-negative) map cannot trigger divide-by-zero.
        positive_values = [
            value for activity, value in intensity.items() if activity != "logon" and value > 0
        ]
        if not positive_values:
            for activity, _ in intensity.items():
                if activity == "logon":
                    continue  # Already added
                pattern.append((activity, 0.1))
            return pattern

        max_val = max(positive_values)
        for activity, value in intensity.items():
            if activity == "logon":
                continue  # Already added
            normalized = max(value, 0) / max_val
            prob = min(0.95, normalized * 0.8 + 0.1)
            pattern.append((activity, prob))

        return pattern

    # Process→network correlation loaded from config/activity/process_network_map.yaml.
    # See generation/activity/process_network.py for the loader.

    def _emit_process_network_correlation(
        self,
        system: Any,
        process_name: str,
        command_line: str,
        time: datetime,
        pid: int,
        rng: random.Random,
    ) -> None:
        """Emit network connections correlated with a process creation.

        When a baseline process is one that normally generates network
        traffic (browsers, Office apps, dev tools, DB clients), emit
        a corresponding connection shortly after process creation.
        """
        # Extract executable basename
        exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        # Strip .exe for Linux lookups
        exe_base = exe.replace(".exe", "") if exe.endswith(".exe") else exe

        from evidenceforge.generation.activity.process_network import get_exe_to_service

        _exe_map = get_exe_to_service()
        conn_info = _exe_map.get(exe) or _exe_map.get(exe_base)
        if conn_info is None:
            return

        # Only emit ~60% of the time (not every process invocation connects)
        if rng.random() > 0.60:
            return

        conn_time = time + timedelta(milliseconds=rng.randint(50, 500))
        ext_hostname = None

        if conn_info["external"]:
            # External connection: domain-first selection. App-specific mappings
            # can constrain destinations via DNS registry tags (e.g., Teams →
            # Teams/M365 endpoints instead of arbitrary web/CDN domains).
            from evidenceforge.generation.activity.dns_registry import (
                _domain_to_ip as _d2ip,
            )
            from evidenceforge.generation.activity.dns_registry import (
                generate_long_tail_domain as _gen_lt_domain,
            )
            from evidenceforge.generation.activity.dns_registry import (
                pick_domain_and_ip as _pick_domain_and_ip,
            )

            dns_tags = conn_info.get("dns_tags") or []
            if dns_tags:
                tag = rng.choice(dns_tags)
                ext_hostname, dst_ip = _pick_domain_and_ip(
                    rng,
                    tag,
                    src_host=system.hostname,
                    include_os=_get_os_category(system.os),
                )
            else:
                ext_hostname = _gen_lt_domain(rng)
                dst_ip = _d2ip(ext_hostname)
        else:
            # Internal connection: use DB server or any internal server
            db_servers = getattr(self, "_db_servers", [])
            all_ips = getattr(self, "_all_system_ips", [])
            if conn_info["service"] in ("mssql", "mysql", "postgresql") and db_servers:
                # Filter to DB servers that match the requested service
                svc = conn_info["service"]
                compatible = [
                    e
                    for e in db_servers
                    if (isinstance(e, dict) and e.get("service") == svc) or not isinstance(e, dict)
                ]
                if not compatible:
                    return  # No service-compatible DB host — skip
                db_entry = rng.choice(compatible)
                dst_ip = db_entry["ip"] if isinstance(db_entry, dict) else db_entry
            elif all_ips:
                dst_ip = rng.choice([ip for ip in all_ips if ip != system.ip] or all_ips)
            else:
                return  # No internal targets available

        self.generate_connection(
            src_ip=system.ip,
            dst_ip=dst_ip,
            time=conn_time,
            dst_port=conn_info["dst_port"],
            proto="tcp",
            service=conn_info["service"],
            duration=rng.uniform(0.3, 15.0),
            orig_bytes=rng.randint(200, 5000),
            resp_bytes=rng.randint(500, 50000),
            emit_dns=conn_info["external"],
            pid=pid,
            hostname=ext_hostname if conn_info["external"] else None,
        )

    def execute_baseline_activity(
        self, user: User, system: System, time: datetime, activity_type: str
    ) -> None:
        """Execute a specific baseline activity type.

        Args:
            user: User performing the activity
            system: System where activity occurs
            time: Activity timestamp
            activity_type: Type of activity to execute
        """
        # Logon activity (10% chance of failure — bad password)
        if activity_type == "logon":
            if _get_rng().random() < 0.10:
                self.generate_failed_logon(user, system, time)
                return

            # Phase 6.2: Realistic logon type distribution by system type
            # Type 3 (network) should dominate in AD; Type 5 only for service accounts
            rng = _get_rng()
            sys_type = (system.type or "workstation").lower()
            is_service_account = user.username.endswith("$") or user.username.lower().startswith(
                "svc"
            )

            if sys_type in ("server", "domain_controller"):
                # Servers/DCs: Type 3 (network) dominates
                logon_type = rng.choices(
                    [3, 5, 10, 4, 2, 8, 9], weights=[70, 15, 8, 4, 1, 1, 1], k=1
                )[0]
            elif is_service_account:
                # Service accounts on workstations: network + service logons
                logon_type = rng.choices([3, 5, 10], weights=[70, 25, 5], k=1)[0]
            else:
                # Regular users on workstations: Type 3 dominant, no Type 5
                logon_type = rng.choices([3, 2, 7, 11, 10], weights=[55, 20, 10, 10, 5], k=1)[0]

            # Type 3 (network) logons are standalone events, not interactive sessions
            if logon_type in (3, 4, 5, 8, 9):
                # Pick a source IP from another system for network logons
                source_ip = None
                if logon_type == 3 and hasattr(self, "_all_system_ips"):
                    # ~30% of Type 3 logons are local services authenticating to themselves
                    if rng.random() < 0.30:
                        source_ip = rng.choice([system.ip, "127.0.0.1"])
                    else:
                        other_ips = [ip for ip in self._all_system_ips if ip != system.ip]
                        if other_ips:
                            source_ip = rng.choice(other_ips)
                logon_id = self.generate_logon(
                    user,
                    system,
                    time,
                    logon_type=logon_type,
                    source_ip=source_ip if source_ip else system.ip,
                )
                # Type 3/5 are short-lived — generate paired logoff after brief delay
                logoff_delay = _get_rng().uniform(1.0, 60.0)
                logoff_time = time + timedelta(seconds=logoff_delay)
                self.generate_logoff(user, system, logoff_time, logon_id, logon_type)
                return

            # Interactive logon types (2, 7, 10, 11) — create sessions
            if logon_type == 7:
                source_ip = "127.0.0.1"
            elif logon_type in (10, 11):
                # Remote interactive (RDP/VNC) — pick a realistic remote IP
                other_ips = getattr(self, "_all_system_ips", [])
                remote_ips = [ip for ip in other_ips if ip != system.ip]
                source_ip = _get_rng().choice(remote_ips) if remote_ips else system.ip
            elif logon_type == 2 and _get_os_category(system.os) == "linux":
                # Console logon on Linux servers often comes via SSH from another host
                other_ips = getattr(self, "_all_system_ips", [])
                remote_ips = [ip for ip in other_ips if ip != system.ip]
                source_ip = _get_rng().choice(remote_ips) if remote_ips else system.ip
            else:
                source_ip = None  # Local console on Windows — defaults to system.ip

            # For Linux hosts with remote logon, emit SSH session (network-side evidence)
            # before the host-side auth event — matches real-world ordering.
            if (
                _get_os_category(system.os) == "linux"
                and logon_type in (2, 10)
                and source_ip
                and source_ip != system.ip
            ):
                ssh_time = time - timedelta(seconds=_get_rng().uniform(0.5, 2.0))
                self.generate_ssh_session(
                    user=user,
                    target_system=system,
                    time=ssh_time,
                    source_ip=source_ip,
                )

            self.generate_logon(user, system, time, logon_type=logon_type, source_ip=source_ip)

        # Process activities
        elif activity_type in PROCESS_TEMPLATES:
            # Get or create session for this user (with login cooldown)
            sessions = self.state_manager.get_sessions_for_user(user.username)
            active_session = (
                next(
                    (
                        s
                        for s in sessions
                        if s.system == system.hostname and _session_started_by(s, time)
                    ),
                    None,
                )
                if sessions
                else None
            )

            if active_session:
                logon_id = active_session.logon_id
                active_session.last_activity_time = time
            else:
                # No active session on this system — create logon slightly before
                # the process to maintain causal ordering
                logon_time = time - timedelta(seconds=_get_rng().uniform(0.5, 2.0))
                logon_id = self.generate_logon(user, system, logon_time)

            # Phase 2.10: OS-aware process template selection
            os_category = _get_os_category(system.os)

            # Map activity_type to catalog category
            _CATEGORY_MAP = {
                "process_user_apps": "user_app",
                "process_code": "code",
                "process_build": "build",
                "process_query": "query",
            }
            catalog_category = _CATEGORY_MAP.get(activity_type)

            if catalog_category in ("user_app", "browser", "office") and system.type in (
                "server",
                "domain_controller",
            ):
                return

            # Try unified application catalog first (persona-aware, PE-metadata-rich)
            if catalog_category:
                from evidenceforge.generation.activity.application_catalog import (
                    pick_app_and_command,
                )

                rng = _get_rng()
                result = pick_app_and_command(
                    rng,
                    user.persona or "default",
                    os_category,
                    catalog_category,
                    username=user.username,
                    system_type=system.type,
                )
                if result:
                    process_name, command_line = result
                    command_line = _parameterize_command(rng, command_line, username=user.username)
                    parent_pid = self._resolve_parent(system, user, time, logon_id, process_name)
                    pid = self.generate_process(
                        user,
                        system,
                        time,
                        logon_id,
                        process_name,
                        command_line,
                        parent_pid=parent_pid,
                    )
                    self._record_user_process(system, user, pid, process_name)

                    # Spawn child/utility processes for apps that have them
                    if activity_type == "process_user_apps":
                        from evidenceforge.generation.activity.application_catalog import (
                            get_child_processes,
                        )

                        exe_lower = process_name.rsplit("\\", 1)[-1].lower()
                        if "/" in process_name:
                            exe_lower = process_name.rsplit("/", 1)[-1].lower()
                        child_entries = get_child_processes(os_category, exe_lower)
                        if child_entries:
                            num_children = rng.randint(1, min(3, len(child_entries)))
                            for entry in rng.sample(child_entries, num_children):
                                child_time = time + timedelta(seconds=rng.uniform(0.5, 3.0))
                                child_image = entry["image"]
                                child_cmd = entry["command_line"]
                                if "{username}" in child_image:
                                    child_image = child_image.replace("{username}", user.username)
                                if "{username}" in child_cmd:
                                    child_cmd = child_cmd.replace("{username}", user.username)
                                self.generate_process(
                                    user,
                                    system,
                                    child_time,
                                    logon_id,
                                    child_image,
                                    child_cmd,
                                    parent_pid=pid,
                                )

                    # Emit correlated network connection for network-active apps
                    # (tight PID+timestamp coupling alongside profile-driven volume)
                    self._emit_process_network_correlation(
                        system, process_name, command_line, time, pid, rng
                    )

                    # Also generate bash history for Linux processes
                    if os_category == "linux":
                        self.generate_bash_command(user, system, time, activity_type)

            # Legacy PROCESS_TEMPLATES only for process_system (not user apps/code/build/query)
            elif activity_type == "process_system":
                if os_category == "windows" and activity_type in PROCESS_TEMPLATES:
                    rng = _get_rng()
                    process_name, command_line = rng.choice(PROCESS_TEMPLATES[activity_type])
                    process_name = process_name.replace("{username}", user.username)
                    command_line = _parameterize_command(rng, command_line, username=user.username)
                    parent_pid = self._resolve_parent(system, user, time, logon_id, process_name)
                    pid = self.generate_process(
                        user,
                        system,
                        time,
                        logon_id,
                        process_name,
                        command_line,
                        parent_pid=parent_pid,
                    )
                    self._record_user_process(system, user, pid, process_name)
                elif os_category == "linux" and activity_type in PROCESS_TEMPLATES_LINUX:
                    rng = _get_rng()
                    process_name, command_line = rng.choice(PROCESS_TEMPLATES_LINUX[activity_type])
                    command_line = _parameterize_command(rng, command_line, username=user.username)
                    parent_pid = self._resolve_parent(system, user, time, logon_id, process_name)
                    pid = self.generate_process(
                        user,
                        system,
                        time,
                        logon_id,
                        process_name,
                        command_line,
                        parent_pid=parent_pid,
                    )
                    self._record_user_process(system, user, pid, process_name)
                    self.generate_bash_command(user, system, time, activity_type)

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            rng = _get_rng()
            conn_hostname = None  # Domain name for DNS/SNI consistency

            # Domain-first selection: pick a domain, resolve to its IP.
            # Uses pick_domain_and_ip() which maintains correct per-domain IP
            # pools and per-host deterministic selection (simulates DNS cache).
            from evidenceforge.generation.activity.dns_registry import (
                _domain_to_ip,
                generate_long_tail_domain,
                pick_domain_and_ip,
            )

            _tag_for_activity = {
                "connection_web": "web",
                "connection_saas": "saas",
                "connection_email": "email",
                "connection_git": "git",
                "connection_db": "internal",
            }
            tag = _tag_for_activity.get(activity_type, "web")

            if activity_type in ("connection_web", "connection_saas") and rng.random() < 0.30:
                # 30% chance: long-tail domain for CDN/SaaS/analytics diversity
                conn_hostname = generate_long_tail_domain(rng)
                dst_ip = _domain_to_ip(conn_hostname)
            else:
                # Known domain with correct per-domain IP pairing
                conn_hostname, dst_ip = pick_domain_and_ip(rng, tag, src_host=system.hostname)
                if dst_ip == system.ip:
                    return  # Skip self-connections

            # Set service and port based on activity type
            if activity_type in ("connection_web", "connection_saas"):
                service = rng.choice(["http", "ssl"])
                dst_port = 443 if service == "ssl" else 80
            elif activity_type == "connection_email":
                service = "smtp"
                # Route through internal Exchange if detected (P1-15)
                exchange_ip = getattr(self, "_exchange_ip", None)
                if exchange_ip:
                    dst_ip = exchange_ip
                    dst_port = 25  # Internal SMTP relay uses port 25
                else:
                    dst_port = 587
            elif activity_type == "connection_git":
                service = "ssl"
                dst_port = 443
            elif activity_type == "connection_db":
                db_servers = getattr(self, "_db_servers", [])
                if db_servers:
                    db = _get_rng().choice(db_servers)
                    dst_ip = db["ip"]
                    service = db["service"]
                    dst_port = db["port"]
                    conn_hostname = None
                else:
                    # No DB servers detected from scenario; skip DB connection
                    return
            else:
                service = None
                dst_port = 443

            # Generate realistic traffic sizes
            orig_bytes = rng.randint(500, 5000)
            resp_bytes = rng.randint(1000, 50000)
            duration = rng.uniform(0.1, 5.0)

            self.generate_connection(
                src_ip=system.ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                service=service,
                emit_dns=True,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                hostname=conn_hostname,
            )

    def generate_machine_account_logon(
        self,
        hostname: str,
        machine_username: str,
        dc_hostname: str,
        source_ip: str,
        dc_ip: str,
        time: datetime,
        domain: str = "",
    ) -> None:
        """Generate machine account logon event (4624 type 3) on the DC.

        Machine accounts (COMPUTERNAME$) authenticate to DCs constantly for
        GPO updates, Kerberos renewal, LDAP queries, etc. The event is logged
        on the DC, not on the source machine.
        """
        domain = domain or getattr(self, "_netbios_domain", "CORP")
        rng = _get_rng()

        logon_id = f"0x{rng.randint(0x10000, 0xFFFFF):x}"
        event = SecurityEvent(
            timestamp=time,
            event_type="machine_logon",
            dst_host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=logon_id,
                logon_type=3,
                auth_package="Kerberos",
                source_ip=source_ip,
                logon_process="Kerberos",
                lm_package="-",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid=self._get_sid("SYSTEM"),
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
            ),
        )
        self.dispatcher.dispatch(event)

        # Paired logoff for short-lived type 3 machine logon (1-30 seconds)
        logoff_delay = rng.uniform(1.0, 30.0)
        logoff_event = SecurityEvent(
            timestamp=time + timedelta(seconds=logoff_delay),
            event_type="logoff",
            dst_host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=logon_id,
                logon_type=3,
            ),
        )
        self.dispatcher.dispatch(logoff_event)

        # Also generate the Kerberos network connection to DC
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=dc_ip,
            time=time,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(200, 1000),
            resp_bytes=rng.randint(200, 1500),
        )

    def generate_kerberos_tgt(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
    ) -> None:
        """Generate Kerberos TGT request event (4768) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        # Kerberos realm is always the DNS FQDN in uppercase, never NetBIOS short name
        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options=rng.choices(
                    ["0x40810010", "0x40810000", "0x40000010", "0x50800000", "0x10"],
                    weights=[60, 20, 10, 5, 5],
                    k=1,
                )[0],
                encryption_type=rng.choices(["0x12", "0x11", "0x17"], weights=[70, 15, 15], k=1)[0],
                pre_auth_type=15,
                source_ip=f"::ffff:{source_ip}",
                source_port=_ephemeral_port(rng, self._os_for_ip(source_ip)),
            ),
        )

        self.dispatcher.dispatch(event)

    def generate_kerberos_tgt_renewal(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
    ) -> None:
        """Generate Kerberos TGT renewal event (4770) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt_renewal",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options=rng.choices(["0x2", "0x60810010"], weights=[80, 20], k=1)[0],
                encryption_type=rng.choices(["0x12", "0x11", "0x17"], weights=[70, 15, 15], k=1)[0],
                source_ip=f"::ffff:{source_ip}",
                source_port=_ephemeral_port(rng, self._os_for_ip(source_ip)),
            ),
        )

        self.dispatcher.dispatch(event)

    def generate_kerberos_service_ticket(
        self,
        username: str,
        service_name: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
    ) -> None:
        """Generate Kerberos service ticket request event (4769) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_service",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=f"{username}@{domain}",
                target_domain=domain,
                service_name=service_name,
                service_sid=self._get_sid(
                    f"{service_name.split('/')[1]}$" if "/" in service_name else service_name
                ),
                ticket_options=rng.choices(
                    ["0x40810000", "0x40810010", "0x40000000", "0x10"],
                    weights=[50, 25, 15, 10],
                    k=1,
                )[0],
                encryption_type=rng.choices(["0x12", "0x11", "0x17"], weights=[70, 15, 15], k=1)[0],
                source_ip=f"::ffff:{source_ip}",
                source_port=_ephemeral_port(rng, self._os_for_ip(source_ip)),
            ),
        )

        self.dispatcher.dispatch(event)

    def generate_ntlm_validation(
        self,
        username: str,
        workstation: str,
        dc_hostname: str,
        time: datetime,
    ) -> None:
        """Generate NTLM credential validation event (4776) on the DC."""
        event = SecurityEvent(
            timestamp=time,
            event_type="ntlm_validation",
            dst_host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=username,
                source_ip=workstation,  # SourceWorkstation stored in source_ip
            ),
        )

        self.dispatcher.dispatch(event)

    def generate_explicit_credentials(
        self,
        user: User,
        system: System,
        time: datetime,
        target_username: str,
        target_server: str,
        process_name: str,
        process_pid: int,
        source_ip: str = "",
        source_port: int = 0,
    ) -> None:
        """Generate explicit credentials event (4648) on source system.

        Fires when a process uses RunAs, scheduled tasks, PsExec, WMIC,
        or other explicit credential usage.
        """
        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        # System accounts have canonical LogonIds — don't look up sessions
        _CANONICAL_LOGON_IDS = {
            "SYSTEM": "0x3e7",
            "LOCAL SERVICE": "0x3e5",
            "NETWORK SERVICE": "0x3e4",
        }
        if user.username in _CANONICAL_LOGON_IDS:
            subject_logon_id = _CANONICAL_LOGON_IDS[user.username]
        else:
            subject_logon_id = self._get_user_logon_id(user.username, system.hostname)
        event = SecurityEvent(
            timestamp=time,
            event_type="explicit_credentials",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=target_username,
                user_sid=self._get_sid(target_username),
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=self._build_host_context(system).netbios_domain,
                subject_logon_id=subject_logon_id,
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                reporting_pid=reporting_pid,
                process_pid=process_pid,
                target_server=target_server,
                process_name=process_name,
                source_ip=source_ip or "-",
                source_port=source_port,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_workstation_lock(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> None:
        """Generate workstation lock event (4800)."""
        event = SecurityEvent(
            timestamp=time,
            event_type="workstation_locked",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_workstation_unlock(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> None:
        """Generate workstation unlock event (4801 + 4624 type 7)."""
        event = SecurityEvent(
            timestamp=time,
            event_type="workstation_unlocked",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
            ),
        )
        self.dispatcher.dispatch(event)
        # Unlock is a re-authentication — emit 4624 type 7 with same session
        self.generate_logon(
            user=user,
            system=system,
            time=time + timedelta(milliseconds=50),
            logon_type=7,
            source_ip=system.ip,
            logon_id=logon_id,
        )

    def generate_wfp_connection(
        self,
        system: System,
        time: datetime,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        pid: int = 4,
        application: str = r"C:\Windows\System32\svchost.exe",
    ) -> None:
        """Generate WFP connection permitted event (5156) on Windows host.

        Records the Windows Filtering Platform firewall allow decision.
        """
        from evidenceforge.events.contexts import NetworkContext, ProcessContext

        ip_proto = 6 if protocol == "tcp" else 17 if protocol == "udp" else 1
        event = SecurityEvent(
            timestamp=time,
            event_type="wfp_connection",
            src_host=self._build_host_context(system),
            network=NetworkContext(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                ip_proto=ip_proto,
                initiating_pid=pid,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=application,
                command_line="",
                username="",
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_rdp_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_system: Optional["System"] = None,
        source_pid: int = -1,
        logon_id: str | None = None,
    ) -> str:
        """Generate RDP session: Zeek conn + 4624 type 10 + eCAR on target.

        Compound event ensuring network and host evidence are always paired.
        Returns Zeek UID.
        """
        rng = _get_rng()

        # 1. Network connection (Zeek conn.log port 3389)
        # emit_dns=True so the causal engine generates DNS evidence for the
        # RDP destination, matching real-world behavior where the client
        # resolves the target hostname before connecting.
        uid = self.generate_connection(
            src_ip=source_ip,
            dst_ip=target_system.ip,
            time=time,
            dst_port=3389,
            proto="tcp",
            service="rdp",
            duration=rng.uniform(60.0, 3600.0),
            orig_bytes=rng.randint(50000, 500000),
            resp_bytes=rng.randint(100000, 2000000),
            emit_dns=True,
            source_system=source_system,
            pid=source_pid,
        )

        # 2. Host logon on target (4624 type 10 + 4672 if elevated)
        logon_time = time + timedelta(milliseconds=rng.randint(50, 200))
        self.generate_logon(
            user=user,
            system=target_system,
            time=logon_time,
            logon_type=10,
            source_ip=source_ip,
            logon_id=logon_id,
        )

        return uid

    def generate_service_logon(
        self,
        system: System,
        time: datetime,
        service_account: str = "SYSTEM",
    ) -> str:
        """Generate a service logon (type 5) for system accounts.

        Unlike generate_logon(), does not require a User object.
        Emits 4624 (type 5) + 4672 (special privileges) via normal pipeline.
        Each call gets a unique LogonID (real Windows allocates new sessions for service restarts).
        """
        _ACCOUNT_SIDS = {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
        }

        sid = _ACCOUNT_SIDS.get(service_account, "S-1-5-18")
        # Allocate unique LogonID via StateManager (same as regular logons)
        logon_id = self.state_manager.create_session(
            username=service_account,
            system=system.hostname,
            logon_type=5,
            source_ip="-",
        )
        host = self._build_host_context(system)
        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)

        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username=service_account,
                user_sid=sid,
                logon_id=logon_id,
                logon_type=5,
                auth_package="Negotiate",
                source_ip="-",
                elevated=True,
                logon_process="Advapi",
                lm_package="-",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid="S-1-5-18",
                subject_username=system.hostname + "$",
                subject_domain=host.netbios_domain,
                subject_logon_id="0x3e7",
                reporting_pid=reporting_pid,
            ),
        )
        self.dispatcher.dispatch(event)
        return logon_id

    def generate_kerberos_preauth_failed(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        status: str = "0x18",
    ) -> None:
        """Generate Kerberos pre-authentication failed event (4771) on DC."""
        rng = _get_rng()
        dc_host = self._build_dc_host_context(dc_hostname)
        reporting_pid = self._get_system_pid(dc_hostname, "lsass", 0x2E0)
        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_preauth_failed",
            dst_host=dc_host,
            kerberos=KerberosContext(
                target_username=username,
                target_domain=getattr(self, "_ad_domain", "corp.local").upper(),
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                ticket_options="0x40810010",
                ticket_status=status,
                pre_auth_type=0,
                source_ip=f"::ffff:{source_ip}" if ":" not in source_ip else source_ip,
                source_port=_ephemeral_port(rng, self._os_for_ip(source_ip)),
                reporting_pid=reporting_pid,
            ),
        )
        self.dispatcher.dispatch(event)

    def _get_user_logon_id(self, username: str, hostname: str) -> str:
        """Look up the user's active session LogonID on the given host.

        Returns the session LogonID if found, or '0x3e7' (SYSTEM) as fallback.
        """
        sessions = self.state_manager.get_sessions_for_user(username)
        if sessions:
            active = next((s for s in sessions if s.system == hostname), None)
            if active:
                return active.logon_id
        return "0x3e7"

    def generate_log_cleared(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> None:
        """Generate security log cleared event (1102) on target system."""
        event = SecurityEvent(
            timestamp=time,
            event_type="log_cleared",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=self._build_host_context(system).netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname),
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_service_installed(
        self,
        user: User,
        system: System,
        time: datetime,
        service_name: str,
        service_file_name: str,
        service_type: str = "0x10",
        service_start_type: str = "2",
        service_account: str = "LocalSystem",
    ) -> None:
        """Generate service installed event (4697) on target system."""
        from evidenceforge.events.contexts import ServiceContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        event = SecurityEvent(
            timestamp=time,
            event_type="service_installed",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=self._build_host_context(system).netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            service=ServiceContext(
                service_name=service_name,
                service_file_name=service_file_name,
                service_type=service_type,
                service_start_type=service_start_type,
                service_account=service_account,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_scheduled_task(
        self,
        user: User,
        system: System,
        time: datetime,
        task_name: str,
        action: str = "created",
        task_content: str = "",
    ) -> None:
        """Generate scheduled task event (4698/4699/4700/4701) on target system."""
        from evidenceforge.events.contexts import ScheduledTaskContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        event = SecurityEvent(
            timestamp=time,
            event_type=f"scheduled_task_{action}",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=self._build_host_context(system).netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            scheduled_task=ScheduledTaskContext(
                task_name=task_name,
                task_content=task_content,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_group_membership_change(
        self,
        actor: User,
        system: System,
        time: datetime,
        action: str,
        scope: str,
        group_name: str,
        group_sid: str,
        member_username: str,
        member_sid: str,
    ) -> None:
        """Generate group membership change event on DC.

        Args:
            action: "add" or "remove"
            scope: "global", "local", or "universal"
        """
        from evidenceforge.events.contexts import GroupMembershipContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event_type = f"group_member_{'added' if action == 'add' else 'removed'}_{scope}"
        event = SecurityEvent(
            timestamp=time,
            event_type=event_type,
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(actor.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            group_membership=GroupMembershipContext(
                member_name="-",
                member_sid=member_sid,
                group_name=group_name,
                group_domain=host.netbios_domain,
                group_sid=group_sid,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_account_created(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate user account created event (4720) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="account_created",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(actor.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
                sam_account_name=target_username,
                password_last_set="%%1794",
                new_uac_value="0x15",
                user_account_control="\n\t\t\t%%2080\n\t\t\t%%2082\n\t\t\t%%2084",
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_account_deleted(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate user account deleted event (4726) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="account_deleted",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(actor.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_password_reset(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate password reset event (4724) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="password_reset",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(actor.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_password_change(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> None:
        """Generate password change event (4723) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="password_change",
            dst_host=host,
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=user.username,
                target_domain=host.netbios_domain,
                target_sid=self._get_sid(user.username),
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_create_remote_thread(
        self,
        user: User,
        system: System,
        time: datetime,
        source_pid: int,
        source_image: str,
        target_pid: int,
        target_image: str,
    ) -> None:
        """Generate Sysmon Event 8 (CreateRemoteThread) for process injection."""
        # Entity lifecycle: validate target PID exists
        self.state_manager.validate_target_pid(system.hostname, target_pid)

        from evidenceforge.events.contexts import ProcessContext

        event = SecurityEvent(
            timestamp=time,
            event_type="create_remote_thread",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=source_pid,
                parent_pid=0,
                image=source_image,
                command_line="",
                username=user.username,
            ),
            auth=AuthContext(
                username=user.username,
                target_server=target_image,
                source_port=target_pid,  # Pack target PID into source_port for emitter
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_process_access(
        self,
        user: User,
        system: System,
        time: datetime,
        source_pid: int,
        source_image: str,
        target_pid: int,
        target_image: str = r"C:\Windows\System32\lsass.exe",
        granted_access: str = "0x1010",
    ) -> None:
        """Generate Sysmon Event 10 (ProcessAccess) for credential dumping detection.

        Emits when a process accesses another process's memory (e.g., mimikatz
        reading lsass.exe for credential extraction).

        Args:
            user: User running the source process
            system: System where the access occurs
            time: Event timestamp
            source_pid: PID of the process doing the access
            source_image: Full path of the source process image
            target_pid: PID of the target process (typically lsass.exe)
            target_image: Full path of the target process image
            granted_access: Access mask (0x1010=VM_READ, 0x1FFFFF=ALL_ACCESS)
        """
        # Entity lifecycle: validate target PID exists
        self.state_manager.validate_target_pid(system.hostname, target_pid)

        from evidenceforge.events.contexts import ProcessContext

        event = SecurityEvent(
            timestamp=time,
            event_type="process_access",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=source_pid,
                parent_pid=0,
                image=source_image,
                command_line="",
                username=user.username,
            ),
            auth=AuthContext(
                username=user.username,
                target_server=target_image,
                source_port=target_pid,  # Pack target PID (same pattern as create_remote_thread)
                failure_status=granted_access,  # Pack access mask into failure_status
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_image_load(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        image: str,
        dll_path: str,
        signed: bool = True,
        signature: str = "Microsoft Windows",
        signature_status: str = "Valid",
    ) -> None:
        """Generate Sysmon Event 7 (ImageLoaded) for DLL/module loading.

        Args:
            user: User running the process that loaded the DLL
            system: System where the load occurs
            time: Event timestamp
            pid: PID of the process loading the DLL
            image: Full path of the process image
            dll_path: Full path of the loaded DLL
            signed: Whether the DLL is signed
            signature: Signer name (e.g., "Microsoft Windows")
            signature_status: Signature validation status (Valid, Expired, etc.)
        """
        from evidenceforge.events.contexts import ImageLoadContext, ProcessContext

        event = SecurityEvent(
            timestamp=time,
            event_type="image_load",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=image,
                command_line="",
                username=user.username,
            ),
            image_load=ImageLoadContext(
                image_loaded=dll_path,
                signed=signed,
                signature=signature,
                signature_status=signature_status,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_account_changed(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate user account changed event (4738) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="account_changed",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(actor.username, system.hostname),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
                sam_account_name=target_username,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_dhcp_lease(
        self,
        system: "System",
        time: datetime,
        mac: str,
        server_addr: str = "10.0.0.1",
        lease_time: float = 3600.0,
        uid: str = "",
        msg_types: list[str] | None = None,
    ) -> None:
        """Generate a DHCP lease event via canonical SecurityEvent dispatch."""
        from evidenceforge.events.contexts import DhcpContext

        if msg_types is None:
            msg_types = ["DISCOVER", "OFFER", "REQUEST", "ACK"]

        from evidenceforge.events.contexts import NetworkContext

        event = SecurityEvent(
            timestamp=time,
            event_type="dhcp_lease",
            src_host=self._build_host_context(system),
            network=NetworkContext(
                src_ip=system.ip,
                dst_ip=server_addr,
                src_port=68,
                dst_port=67,
                protocol="udp",
                service="dhcp",
                zeek_uid=uid,
                duration=0.01,
                orig_bytes=300 if "DISCOVER" in msg_types else 180,
                resp_bytes=300,
                orig_pkts=2 if "DISCOVER" in msg_types else 1,
                resp_pkts=2 if "OFFER" in msg_types else 1,
                orig_ip_bytes=356 if "DISCOVER" in msg_types else 208,
                resp_ip_bytes=356,
                conn_state="SF",
                history="DdDd" if "DISCOVER" in msg_types else "Dd",
                local_orig=True,
                local_resp=True,
                ip_proto=17,
            ),
            dhcp=DhcpContext(
                client_addr=system.ip,
                server_addr=server_addr,
                mac=mac,
                host_name=system.hostname,
                assigned_addr=system.ip,
                lease_time=lease_time,
                uids=[uid] if uid else [],
                msg_types=msg_types,
                duration=_get_rng().uniform(0.01, 0.5),
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_anonymous_logon(
        self,
        system: "System",
        time: datetime,
    ) -> None:
        """Generate an anonymous logon event (4624 type 3) without creating a session.

        Used for Windows server/DC background SMB enumeration traffic.
        """
        rng = _get_rng()
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username="ANONYMOUS LOGON",
                user_sid="S-1-5-7",
                logon_id=f"0x{rng.randint(0x10000, 0xFFFFFFFF):x}",
                logon_type=3,
                auth_package="NTLM",
                logon_process="NtLmSsp",
                lm_package="NTLM V2",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid="S-1-0-0",
                subject_username="-",
                subject_domain="-",
                subject_logon_id="0x0",
                source_ip="-",
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_syslog_event(
        self,
        system: "System",
        time: datetime,
        app_name: str,
        message: str,
        pid: int | None = None,
        facility: int = 3,
        severity: int = 6,
    ) -> None:
        """Generate a standalone syslog event via canonical SecurityEvent dispatch.

        For daemon status messages, kernel logs, and other syslog-only entries
        that don't correlate with other event types. The SecurityEvent carries
        HostContext + SyslogContext and dispatches to the syslog emitter.
        """
        from evidenceforge.events.contexts import SyslogContext

        event = SecurityEvent(
            timestamp=time,
            event_type="syslog",
            src_host=self._build_host_context(system),
            syslog=SyslogContext(
                app_name=app_name,
                message=message,
                pid=pid,
                facility=facility,
                severity=severity,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_raw(
        self,
        time: datetime,
        target_format: str,
        fields: dict,
        system: "System | None" = None,
    ) -> None:
        """Emit a raw event through the SecurityEvent pipeline.

        Unlike dispatch_raw(), this goes through state management,
        visibility filtering, and local_only checks.
        Automatically injects _host_fqdn for host-based emitter routing.
        """
        from evidenceforge.events.contexts import RawContext

        host_ctx = self._build_host_context(system) if system else None
        # Inject timestamp if not provided (format templates need it for rendering)
        if "timestamp" not in fields:
            fields["timestamp"] = time
        # Inject host FQDN for HostMultiplexEmitter routing
        if host_ctx and "_host_fqdn" not in fields:
            fields["_host_fqdn"] = (
                host_ctx.fqdn if hasattr(host_ctx, "fqdn") and host_ctx.fqdn else host_ctx.hostname
            )
        if host_ctx and "hostname" not in fields:
            fields["hostname"] = host_ctx.hostname
        event = SecurityEvent(
            timestamp=time,
            event_type="raw",
            src_host=host_ctx,
            raw=RawContext(target_format=target_format, fields=fields),
        )
        self.dispatcher.dispatch(event)

    def generate_sensor_startup(
        self,
        sensor_hostname: str,
        time: datetime,
        reporter_messages: list[tuple[str, str]] | None = None,
    ) -> None:
        """Generate sensor startup events (packet_filter.log + reporter.log).

        Emits a SecurityEvent with event_type="sensor_startup" that routes
        to ZeekPacketFilterEmitter and ZeekReporterEmitter.

        Args:
            sensor_hostname: Hostname of the sensor
            time: Startup timestamp
            reporter_messages: Optional list of (level, message) tuples for reporter.log
        """
        from evidenceforge.events.contexts import ShellContext

        # Packet filter startup
        event = SecurityEvent(
            timestamp=time,
            event_type="sensor_startup",
            src_host=HostContext(
                hostname=sensor_hostname,
                ip="",
                os="",
                os_category="",
                system_type="sensor",
            ),
        )
        self.dispatcher.dispatch(event)

        # Reporter startup messages
        if reporter_messages:
            for i, (level, msg) in enumerate(reporter_messages):
                reporter_event = SecurityEvent(
                    timestamp=time + timedelta(milliseconds=i * 50),
                    event_type="sensor_startup",
                    src_host=HostContext(
                        hostname=sensor_hostname,
                        ip="",
                        os="",
                        os_category="",
                        system_type="sensor",
                    ),
                    shell=ShellContext(command=f"{level}|{msg}"),
                )
                self.dispatcher.dispatch(reporter_event)

    def _get_next_event_record_id(self, hostname: str = "") -> int:
        """Get next EventRecordID for a specific computer (thread-safe).

        Real Windows event logs have per-computer sequential IDs. Each host
        starts at a random offset (1000-50000) to simulate uptime history.

        Args:
            hostname: Computer hostname for per-machine counter
        """
        with self._counter_lock:
            if hostname not in self._event_record_counters:
                rng = random.Random(_stable_seed(f"erid_{hostname}"))
                self._event_record_counters[hostname] = rng.randint(1000, 50000)
            self._event_record_counters[hostname] += 1
            return self._event_record_counters[hostname]

    # Well-known Windows SIDs (always available regardless of registry)
    _WELL_KNOWN_SIDS = {
        "SYSTEM": "S-1-5-18",
        "LOCAL SERVICE": "S-1-5-19",
        "NETWORK SERVICE": "S-1-5-20",
    }

    # Personas that represent admin/operator roles (get elevated privileges)
    _ADMIN_PERSONAS = {"sysadmin", "security_analyst", "help_desk"}

    def _should_elevate(self, user: User) -> bool:
        """Determine if a logon should generate 4672 (Special Privileges).

        Role-based: admins ~80%, machine accounts always, regular users ~5%.
        """
        rng = _get_rng()
        username = user.username
        # Machine accounts always elevated
        if username.endswith("$"):
            return True
        # System service accounts always elevated
        if username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return True
        # Admin personas: ~80% elevated
        persona = getattr(user, "persona", None)
        if persona and str(persona) in self._ADMIN_PERSONAS:
            return rng.random() < 0.80
        # Regular users: ~5% (occasional admin task)
        return rng.random() < 0.05

    def _select_auth_package(self, logon_type: int) -> dict[str, str]:
        """Select auth package, LogonProcessName, and LogonGuid based on logon type.

        In real AD: Kerberos dominates for network logons, NTLM as fallback,
        Negotiate for interactive logons.
        """
        rng = _get_rng()
        if logon_type == 2:
            # Interactive: Negotiate (local login)
            return {
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "LmPackageName": "-",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }
        elif logon_type in (3, 4, 5, 8, 9):
            # Network/batch/service: Kerberos dominates in AD
            roll = rng.random()
            if roll < 0.70:
                return {
                    "LogonProcessName": "Kerberos",
                    "AuthenticationPackageName": "Kerberos",
                    "LmPackageName": "-",
                    "LogonGuid": f"{{{uuid.uuid4()}}}",
                }
            elif roll < 0.90:
                return {
                    "LogonProcessName": "NtLmSsp",
                    "AuthenticationPackageName": "NTLM",
                    "LmPackageName": "NTLM V2",
                    "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                }
            else:
                return {
                    "LogonProcessName": "NtLmSsp",
                    "AuthenticationPackageName": "Negotiate",
                    "LmPackageName": "-",
                    "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                }
        elif logon_type == 10:
            # RDP: NtLmSsp/CredSSP
            return {
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": rng.choice(["CredSSP", "Negotiate"]),
                "LmPackageName": "-",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }
        else:
            # Type 7 (unlock), 11 (cached), etc.: Negotiate
            return {
                "LogonProcessName": "Negotiate",
                "AuthenticationPackageName": "Negotiate",
                "LmPackageName": "-",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }

    def _get_system_pid(self, hostname: str, role: str, fallback: int) -> int:
        """Get a seeded system process PID by role name."""
        pids = getattr(self, "_system_pids", {}).get(hostname, {})
        return pids.get(role, fallback)

    def _lookup_process_name(self, hostname: str, pid: int, os_category: str = "windows") -> str:
        """Look up the image path of a running process by PID.

        Falls back to an OS-appropriate shell if PID not tracked.
        PID 4 is always the Windows System process (ntoskrnl.exe).
        """
        if pid == 4 and os_category == "windows":
            return r"C:\Windows\System32\ntoskrnl.exe"
        key = (hostname, pid)
        proc = self.state_manager.state.running_processes.get(key)
        if proc:
            return proc.image
        if os_category == "linux":
            return "/usr/bin/bash"
        return r"C:\Windows\explorer.exe"

    # Process names that can spawn child processes
    _WINDOWS_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "WindowsTerminal.exe"}
    _WINDOWS_SPAWNERS = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "WindowsTerminal.exe",
        "outlook.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "iexplore.exe",
    }
    # GUI apps that users launch from Start Menu / desktop — always parent=explorer.exe
    _WINDOWS_GUI_APPS = {
        "outlook.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "iexplore.exe",
        "teams.exe",
        "onedrive.exe",
        "acrobat.exe",
        "7zfm.exe",
        "notepad++.exe",
        "idea64.exe",
        "sublime_text.exe",
        "code.exe",
    }
    _LINUX_SHELLS = {"/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/bash", "/usr/bin/zsh"}

    def _is_pid_alive(self, system: System, pid: int) -> bool:
        """Check if a PID is still running in state manager."""
        return self.state_manager.get_process(system.hostname, pid) is not None

    def _lookup_parent_image(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process image from StateManager, with fallback."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.image
        return "-"

    def _lookup_parent_command_line(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process command line from StateManager."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.command_line
        return "-"

    def _get_session_explorer_pid(self, system: System, user: User) -> int | None:
        """Get the explorer.exe PID for the user's active interactive session.

        Returns None if no interactive session exists or explorer PID not set.
        """
        sessions = self.state_manager.get_sessions_for_user(user.username)
        for session in sessions:
            if session.system == system.hostname and session.explorer_pid is not None:
                if self._is_pid_alive(system, session.explorer_pid):
                    return session.explorer_pid
        return None

    def _select_parent_pid(self, system: System, user: User, process_name: str) -> int:
        """Select a realistic parent PID based on process type and history.

        Builds process trees with depth by tracking recent user processes.
        Windows GUI apps always spawn from explorer.exe.
        CLI/script processes can spawn from shells.
        Linux user processes typically spawn from login shells.

        Only returns PIDs that are still alive in the state manager.
        """
        rng = _get_rng()
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        os_cat = _get_os_category(system.os)
        key = (system.hostname, user.username)
        history = self._user_process_history.get(key, [])
        # Filter history to only include still-running processes
        alive_history = [(pid, name) for pid, name in history if self._is_pid_alive(system, pid)]

        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )

            # Check if the user's active session on this system is a network
            # logon (type 3). Network logons never spawn explorer.exe — processes
            # are parented by svchost.exe or services.exe instead.
            sessions = self.state_manager.get_sessions_for_user(user.username)
            active_session = (
                next((s for s in sessions if s.system == system.hostname), None)
                if sessions
                else None
            )
            is_network_logon = active_session and active_session.logon_type == 3

            if is_network_logon:
                # Network logon: parent is services.exe or svchost.exe
                # (processes arrive via PsExec, WMI, or SMB)
                # CLI/script processes: check for a running shell as parent first
                shells = [
                    (pid, name)
                    for pid, name in alive_history
                    if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SHELLS
                ]
                if shells and rng.random() < 0.6:
                    return shells[-1][0]
                return sys_pids.get(
                    "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )

            # Prefer session-specific explorer PID over system-wide default
            session_explorer = self._get_session_explorer_pid(system, user)
            explorer_pid = session_explorer or sys_pids.get(
                "explorer", sys_pids.get("winlogon", sys_pids.get("services", 4))
            )

            # Shells and terminals spawn from explorer.exe
            if exe_name in self._WINDOWS_SHELLS:
                return explorer_pid

            # GUI apps always spawn from explorer.exe (user launches via Start Menu/desktop)
            if exe_name in self._WINDOWS_GUI_APPS:
                return explorer_pid

            # CLI/script processes: check for a running shell as parent
            shells = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SHELLS
            ]
            if shells and rng.random() < 0.6:
                return shells[-1][0]

            # Check for a browser/app that could spawn this process (e.g. download+run)
            spawners = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SPAWNERS
            ]
            if spawners and rng.random() < 0.3:
                return spawners[-1][0]

            # Default: session-specific or system-wide explorer.exe
            return explorer_pid
        else:
            # Linux: most user commands spawn from a shell
            shells = [(pid, name) for pid, name in alive_history if name in self._LINUX_SHELLS]
            if shells:
                return shells[-1][0]
            # Prefer per-session bash from the user's SSH session
            for sess in self.state_manager.get_sessions_for_user(user.username):
                if (
                    sess.system == system.hostname
                    and sess.session_shell_pid is not None
                    and self._is_pid_alive(system, sess.session_shell_pid)
                ):
                    return sess.session_shell_pid
            return sys_pids.get("bash", sys_pids.get("sshd", 1))

    def _resolve_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
    ) -> int:
        """Resolve the parent PID for a process using spawn rules.

        Transparently finds an existing valid parent or auto-creates the
        parent chain (with realistic timing) using the spawn rules YAML.
        Falls back to the legacy _select_parent_pid() for unknown processes.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        os_cat = _get_os_category(system.os)
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})

        # Extract basename for rule lookup
        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
        else:
            exe_name = (
                process_name.rsplit("/", 1)[-1].lower()
                if "/" in process_name
                else process_name.lower()
            )

        # Special override: SYSTEM user or network logon → svchost (not services.exe directly)
        # Real Windows: services.exe → svchost.exe → cmd.exe (never services.exe → cmd.exe)
        _SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe"}
        is_shell = exe_name in _SHELLS
        if user.username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            if is_shell:
                # Shells get svchost as parent (realistic: service host spawns shell)
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        sessions = self.state_manager.get_sessions_for_user(user.username)
        # Match by logon_id when available to avoid picking the wrong session
        # when a user has both interactive (type 2) and network (type 3) sessions
        # on the same host.
        if logon_id and sessions:
            active_session = next(
                (s for s in sessions if s.system == system.hostname and s.logon_id == logon_id),
                None,
            )
        else:
            active_session = (
                next((s for s in sessions if s.system == system.hostname), None)
                if sessions
                else None
            )
        is_network_logon = active_session and active_session.logon_type == 3
        if is_network_logon:
            if is_shell:
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        # Look up valid parents from spawn rules
        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        possible_parents = reverse.get(exe_name, [])

        if not possible_parents:
            # No rules for this exe — fall back to legacy logic
            return self._select_parent_pid(system, user, process_name)

        # Check alive_history for a matching parent
        key = (system.hostname, user.username)
        history = self._user_process_history.get(key, [])
        alive_parents = []
        for pid, name in history:
            if not self._is_pid_alive(system, pid):
                continue
            hist_exe = (
                name.rsplit("\\", 1)[-1].lower()
                if "\\" in name
                else name.rsplit("/", 1)[-1].lower()
            )
            if hist_exe in possible_parents:
                alive_parents.append((pid, name))

        # Also check seeded system processes as potential parents
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc:
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe in possible_parents:
                    alive_parents.append((pid, proc.image))

        if alive_parents:
            # Deduplicate by PID
            seen = set()
            unique = []
            for pid, name in alive_parents:
                if pid not in seen:
                    seen.add(pid)
                    unique.append((pid, name))
            return rng.choice(unique)[0]

        # No valid parent alive — auto-create the chain
        return self._ensure_parent_chain(system, user, time, logon_id, exe_name, os_cat, depth=0)

    def _ensure_parent_chain(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        child_exe: str,
        os_cat: str,
        depth: int = 0,
    ) -> int:
        """Recursively create parent processes needed for child_exe.

        Builds the chain up to the nearest seeded system process (explorer,
        services, sshd, systemd). Depth-limited to 3 to prevent infinite
        recursion.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_parent_config,
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})

        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        # Safety limit
        if depth > 3:
            if os_cat == "windows":
                return sys_pids.get(
                    "explorer", sys_pids.get("winlogon", sys_pids.get("services", 4))
                )
            return sys_pids.get("bash", sys_pids.get("sshd", 1))

        # Pick a parent for child_exe from the rules
        possible_parents = reverse.get(child_exe, [])
        if not possible_parents:
            if os_cat == "windows":
                return sys_pids.get(
                    "explorer", sys_pids.get("winlogon", sys_pids.get("services", 4))
                )
            return sys_pids.get("bash", sys_pids.get("sshd", 1))

        # Prefer shells for CLI tools on Windows, sshd→bash for Linux
        chosen_parent = rng.choice(possible_parents)

        # Check if chosen parent is already a seeded system process
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc:
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe == chosen_parent:
                    return pid

        # Not a seeded process — need to create it, but first ensure ITS parent
        grandparent_pid = self._ensure_parent_chain(
            system, user, time, logon_id, chosen_parent, os_cat, depth=depth + 1
        )

        # Get command template for the parent we're creating
        config = get_parent_config(os_cat, chosen_parent)
        cmd_templates = config.get("command_templates", [chosen_parent])
        cmd_line = rng.choice(cmd_templates)

        # Derive image path from command_templates (which have correct full paths)
        # rather than blindly prefixing C:\Windows\System32\
        image = None
        from evidenceforge.generation.activity.application_catalog import resolve_image_path

        if os_cat == "windows":
            for tmpl in cmd_templates:
                if "\\" in tmpl:
                    cleaned = tmpl.strip('"')
                    image = cleaned.split('" ')[0] if '" ' in cleaned else cleaned.split()[0]
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "windows", username=user.username)
        else:
            for tmpl in cmd_templates:
                if "/" in tmpl:
                    image = tmpl.split()[0]
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "linux")
                if chosen_parent in ("bash", "sh", "zsh"):
                    image = f"/bin/{chosen_parent}"

        # Timing: parent is created before child
        spawn_delay = config.get("spawn_delay", [0.5, 3.0])
        delay_sec = rng.uniform(spawn_delay[0], spawn_delay[1])
        parent_time = time - timedelta(seconds=delay_sec * (depth + 1))

        # Create the parent process
        parent_pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=grandparent_pid,
            image=image,
            command_line=cmd_line,
            username=user.username,
            integrity_level="System" if user.username == "SYSTEM" else "Medium",
            logon_id=logon_id,
        )

        # Determine if this is a pre-existing process (no creation event)
        # Long-lived parents early in the scenario were "already running"
        lifetime = config.get("lifetime", "long")
        scenario_start = getattr(self, "_scenario_start_time", None)
        is_pre_existing = False
        if lifetime == "long" and scenario_start:
            elapsed = (time - scenario_start).total_seconds()
            if elapsed < 1800 and rng.random() < 0.7:  # First 30 min, 70% chance
                is_pre_existing = True
        # Parents created before the output window are always pre-existing
        # (their creation events would be suppressed by the warm-up filter anyway)
        if not is_pre_existing and scenario_start and parent_time < scenario_start:
            is_pre_existing = True

        if not is_pre_existing:
            # Emit a process creation event
            from evidenceforge.events.base import SecurityEvent
            from evidenceforge.events.contexts import AuthContext, ProcessContext

            event = SecurityEvent(
                timestamp=parent_time,
                event_type="process_create",
                src_host=self._build_host_context(system),
                auth=AuthContext(
                    username=user.username,
                    user_sid=self._get_sid(user.username),
                    logon_id=logon_id,
                ),
                process=ProcessContext(
                    pid=parent_pid,
                    parent_pid=grandparent_pid,
                    image=image,
                    command_line=cmd_line,
                    username=user.username,
                    integrity_level="Medium",
                    logon_id=logon_id,
                    parent_image=self._lookup_process_name(
                        system.hostname, grandparent_pid, _get_os_category(system.os)
                    ),
                    parent_command_line=self._lookup_parent_command_line(
                        system.hostname, grandparent_pid
                    ),
                    token_elevation="%%1938",
                    mandatory_label="S-1-16-8192",
                ),
            )
            self.dispatcher.dispatch(event)

        # Record in user process history
        self._record_user_process(system, user, parent_pid, image)
        return parent_pid

    def _record_user_process(self, system: System, user: User, pid: int, process_name: str) -> None:
        """Record a user process in history for future parent selection."""
        key = (system.hostname, user.username)
        self._user_process_history.setdefault(key, []).append((pid, process_name))
        # Keep only last 10 processes per user/system
        if len(self._user_process_history[key]) > 10:
            self._user_process_history[key] = self._user_process_history[key][-10:]

    def _os_for_ip(self, ip: str) -> str:
        """Look up OS category for an IP address. Defaults to 'windows'."""
        if hasattr(self, "_ip_to_system") and ip in self._ip_to_system:
            return _get_os_category(self._ip_to_system[ip].os)
        return "windows"

    def _get_sid(self, username: str) -> str:
        """Look up Windows SID for a username.

        For unknown principals (stale accounts, attacker-created accounts),
        generates a deterministic synthetic SID using the domain prefix from
        the existing registry and a stable RID derived from the username.

        Args:
            username: Username to look up

        Returns:
            SID string — from registry, well-known, or deterministic synthetic
        """
        if username in self.sid_registry:
            return self.sid_registry[username]
        if username in self._WELL_KNOWN_SIDS:
            return self._WELL_KNOWN_SIDS[username]
        # Generate deterministic synthetic SID for unknown principals.
        # Allocate from max existing RID + offset (not hardcoded 7000 range)
        # to avoid unrealistic gaps in the RID sequence.
        if not hasattr(self, "_domain_sid_prefix"):
            self._domain_sid_prefix: str | None = None
            self._max_rid: int = 1100
            for sid in self.sid_registry.values():
                if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                    self._domain_sid_prefix = "-".join(sid.split("-")[:7])
                    try:
                        rid_val = int(sid.rsplit("-", 1)[1])
                        if rid_val > self._max_rid:
                            self._max_rid = rid_val
                    except ValueError:
                        pass
        if self._domain_sid_prefix:
            from evidenceforge.utils.rng import _stable_seed

            rid = self._max_rid + 1 + (_stable_seed(f"unknown_sid_{username}") % 50)
            self._max_rid = max(self._max_rid, rid)
            synthetic = f"{self._domain_sid_prefix}-{rid}"
            self.sid_registry[username] = synthetic  # Cache for consistency
            return synthetic
        return "S-1-0-0"

    # Phase 5.2: EDR object type diversity data pools
    # EDR file/registry/DLL pools moved to edr_pools.yaml (data-driven config).
    # Access via: from evidenceforge.generation.activity.edr_pools import get_file_paths, etc.

    # _emit_ecar_file_event and _emit_ecar_registry_event removed in Phase 8.2
    # FILE/REGISTRY events now dispatched via SecurityEvent canonical model

    # _emit_ecar_flow_event removed in Phase 8.1 — eCAR FLOW now dispatched
    # via SecurityEvent "connection" type through the canonical event model

    # _emit_ecar_module_event removed in Phase 8.2
    # MODULE events now dispatched via SecurityEvent canonical model
