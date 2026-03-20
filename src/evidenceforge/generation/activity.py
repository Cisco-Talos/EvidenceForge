"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import ipaddress
import logging
import random
import uuid
from datetime import datetime, timedelta
from threading import local, get_ident, Lock
from typing import Optional

from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import User, System

logger = logging.getLogger(__name__)


# Thread-local storage for RNG (Phase 2.1)
_thread_local = local()


def _get_rng() -> random.Random:
    """Get thread-local Random instance with deterministic seed.

    This provides thread-safe random number generation without GIL contention.
    Each thread gets its own RNG instance with a deterministic seed based on
    the thread ID, preserving reproducibility.

    Returns:
        Thread-local Random instance
    """
    if not hasattr(_thread_local, 'rng'):
        thread_id = get_ident()
        # Deterministic seed: combine thread ID with global seed
        # TODO: Make global seed configurable via config
        seed = hash((thread_id, 42))  # 42 = global seed
        _thread_local.rng = random.Random(seed)
    return _thread_local.rng


def _get_os_category(os_string: str) -> str:
    """Detect OS category from OS string.

    Phase 2.10: OS-aware activity generation helper.

    Args:
        os_string: OS name/version (e.g., "Windows 10", "Linux Ubuntu 20.04")

    Returns:
        OS category: "windows", "linux", or "unknown"
    """
    os_lower = os_string.lower()
    if 'windows' in os_lower:
        return 'windows'
    elif 'linux' in os_lower or 'ubuntu' in os_lower or 'centos' in os_lower or 'debian' in os_lower or 'rhel' in os_lower:
        return 'linux'
    else:
        return 'unknown'


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC 1918 private address (for Zeek local_orig/local_resp)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# Fixed baseline activity patterns (no LLM expansion)
# Format: (activity_type, probability)
# Phase 5.6: Widened probability gaps for user diversity scoring
BASELINE_PATTERNS = {
    'developer': [
        ('logon', 0.7),
        ('process_code', 0.75),       # Dominant: code editors
        ('connection_git', 0.5),      # Heavy git usage
        ('process_build', 0.45),      # Frequent builds
        ('process_user_apps', 0.15),  # Minimal app usage
    ],
    'executive': [
        ('logon', 0.9),
        ('connection_web', 0.8),      # Dominant: browsing
        ('connection_email', 0.75),   # Heavy email
        ('process_user_apps', 0.7),   # Heavy Office/apps
    ],
    'analyst': [
        ('logon', 0.85),
        ('process_query', 0.7),       # Dominant: database queries
        ('connection_db', 0.6),       # Heavy DB connections
        ('process_user_apps', 0.45),  # Moderate apps (Excel, etc.)
    ],
    'sysadmin': [
        ('logon', 0.9),
        ('process_system', 0.65),     # Dominant: system tools
        ('process_code', 0.35),
        ('process_query', 0.3),
        ('connection_web', 0.2),
        ('process_user_apps', 0.1),   # Minimal app usage
    ],
    'default': [
        ('logon', 0.75),
        ('connection_web', 0.5),
        ('process_user_apps', 0.35),
    ],
}

# Process names and command lines for baseline activities (Windows)
PROCESS_TEMPLATES = {
    'process_code': [
        ('C:\\Program Files\\Microsoft VS Code\\Code.exe', 'Code.exe --no-sandbox'),
        ('C:\\Program Files (x86)\\Notepad++\\notepad++.exe', 'notepad++ document.txt'),
        ('C:\\Program Files\\JetBrains\\IntelliJ IDEA\\bin\\idea64.exe', 'idea64.exe'),
        ('C:\\Program Files\\Sublime Text\\sublime_text.exe', 'sublime_text.exe project.py'),
    ],
    'process_build': [
        ('C:\\Windows\\System32\\msbuild.exe', 'msbuild.exe solution.sln /t:Build'),
        ('C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c npm run build'),
        ('C:\\Program Files\\dotnet\\dotnet.exe', 'dotnet.exe build -c Release'),
        ('C:\\Program Files\\nodejs\\node.exe', 'node.exe scripts/build.js'),
    ],
    'process_query': [
        ('C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe', 'sqlcmd.exe -S localhost -Q "SELECT * FROM users"'),
        ('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -Command "Get-EventLog -LogName Security -Newest 100"'),
    ],
    'process_user_apps': [
        ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe --type=renderer --enable-features=NetworkService'),
        ('C:\\Program Files\\Mozilla Firefox\\firefox.exe', 'firefox.exe -contentproc -childID 3'),
        ('C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'OUTLOOK.EXE'),
        ('C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'WINWORD.EXE /n'),
        ('C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', 'EXCEL.EXE'),
        ('C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'msedge.exe --type=renderer'),
        ('C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', 'Teams.exe --type=utility'),
        ('C:\\Users\\{username}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe', 'OneDrive.exe /background'),
        ('C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe', 'Acrobat.exe'),
        ('C:\\Program Files\\7-Zip\\7zFM.exe', '7zFM.exe'),
    ],
    'process_system': [
        ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k netsvcs -p -s Schedule'),
        ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog'),
        ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k DcomLaunch -p'),
        ('C:\\Windows\\explorer.exe', 'C:\\Windows\\explorer.exe'),
        ('C:\\Windows\\System32\\RuntimeBroker.exe', 'C:\\Windows\\System32\\RuntimeBroker.exe -Embedding'),
        ('C:\\Windows\\System32\\SearchIndexer.exe', 'C:\\Windows\\System32\\SearchIndexer.exe /Embedding'),
        ('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe'),
        ('C:\\Windows\\System32\\conhost.exe', 'conhost.exe 0x4'),
        ('C:\\Windows\\System32\\dllhost.exe', 'dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}'),
        ('C:\\Windows\\System32\\sihost.exe', 'sihost.exe'),
    ],
}

# Process names and command lines for baseline activities (Linux) - Phase 2.10
PROCESS_TEMPLATES_LINUX = {
    'process_code': [
        ('/usr/bin/vim', 'vim /home/user/script.py'),
        ('/usr/bin/nano', 'nano /etc/config.conf'),
        ('/usr/bin/code', 'code --no-sandbox /home/user/project'),
        ('/usr/bin/emacs', 'emacs -nw /home/user/main.go'),
    ],
    'process_build': [
        ('/usr/bin/make', 'make -j4'),
        ('/usr/bin/gcc', 'gcc -o output source.c'),
        ('/usr/bin/npm', 'npm run build'),
        ('/usr/bin/cargo', 'cargo build --release'),
        ('/usr/bin/python3', 'python3 setup.py install'),
    ],
    'process_query': [
        ('/usr/bin/mysql', 'mysql -u root -p database'),
        ('/usr/bin/psql', 'psql -U postgres -d mydb'),
        ('/usr/bin/redis-cli', 'redis-cli GET session:abc123'),
    ],
    'process_user_apps': [
        ('/usr/bin/firefox', 'firefox --new-tab'),
        ('/usr/bin/thunderbird', 'thunderbird'),
        ('/usr/bin/git', 'git pull origin main'),
        ('/usr/bin/docker', 'docker ps'),
        ('/usr/bin/python3', 'python3 -m pytest tests/'),
        ('/usr/bin/ssh', 'ssh user@remote-host'),
        ('/usr/bin/curl', 'curl -s https://api.example.com/status'),
        ('/usr/bin/kubectl', 'kubectl get pods -n production'),
    ],
    'process_system': [
        ('/usr/lib/systemd/systemd', 'systemd --user'),
        ('/usr/sbin/cron', '/usr/sbin/cron -f'),
        ('/usr/sbin/sshd', '/usr/sbin/sshd -D'),
        ('/usr/sbin/rsyslogd', '/usr/sbin/rsyslogd -n'),
        ('/usr/sbin/NetworkManager', '/usr/sbin/NetworkManager --no-daemon'),
        ('/usr/bin/dbus-daemon', 'dbus-daemon --system --address=systemd:'),
        ('/usr/sbin/atd', '/usr/sbin/atd -f'),
    ],
}

# Per-persona process type weights (Phase 5.1)
# Maps persona name to relative probability of each process template category
PERSONA_PROCESS_WEIGHTS = {
    'developer': {'process_code': 0.5, 'process_build': 0.3, 'process_user_apps': 0.15, 'process_system': 0.05},
    'executive': {'process_code': 0.05, 'process_build': 0.0, 'process_user_apps': 0.8, 'process_system': 0.15},
    'analyst': {'process_code': 0.1, 'process_build': 0.05, 'process_query': 0.5, 'process_user_apps': 0.3, 'process_system': 0.05},
    'sysadmin': {'process_code': 0.2, 'process_build': 0.1, 'process_query': 0.2, 'process_user_apps': 0.1, 'process_system': 0.4},
    'default': {'process_code': 0.15, 'process_build': 0.05, 'process_user_apps': 0.6, 'process_system': 0.2},
}

# Per-persona app subsets for process_user_apps (Phase 5.6: user diversity)
# Each persona favors a different mix of applications from PROCESS_TEMPLATES['process_user_apps']
# Index references into PROCESS_TEMPLATES['process_user_apps']:
#   0=Chrome, 1=Firefox, 2=Outlook, 3=Word, 4=Excel, 5=Edge, 6=Teams, 7=OneDrive, 8=Acrobat, 9=7-Zip
PERSONA_APP_INDICES = {
    'developer': [0, 6, 7, 9],          # Chrome, Teams, OneDrive, 7-Zip
    'executive': [2, 3, 5, 6, 8],       # Outlook, Word, Edge, Teams, Acrobat
    'analyst': [0, 4, 2, 6, 8],         # Chrome, Excel, Outlook, Teams, Acrobat
    'sysadmin': [1, 5, 6, 9],           # Firefox, Edge, Teams, 7-Zip
    'default': [0, 2, 6, 7],            # Chrome, Outlook, Teams, OneDrive
}

# Per-persona app subsets for Linux process_user_apps
# Index references into PROCESS_TEMPLATES_LINUX['process_user_apps']:
#   0=firefox, 1=thunderbird, 2=git, 3=docker, 4=pytest, 5=ssh, 6=curl, 7=kubectl
PERSONA_APP_INDICES_LINUX = {
    'developer': [0, 2, 3, 4, 6],       # firefox, git, docker, pytest, curl
    'executive': [0, 1],                 # firefox, thunderbird
    'analyst': [0, 5, 6],               # firefox, ssh, curl
    'sysadmin': [2, 3, 5, 6, 7],        # git, docker, ssh, curl, kubectl
    'default': [0, 2, 5, 6],            # firefox, git, ssh, curl
}

# Zeek TCP connection state distribution with matching history strings
# Format: (conn_state, weight, history_string)
# Phase 6.3: Expanded from 7 to 20+ patterns for realism
TCP_CONN_STATE_DISTRIBUTION = [
    # Normal completions (SF) — various data exchange patterns
    ('SF', 54, 'ShADadfF'),      # Standard: SYN→SYN-ACK→data→FIN
    ('SF', 10, 'ShADaDadfF'),    # Multiple data exchanges before FIN
    ('SF', 5, 'ShADadTtFf'),     # Normal with retransmissions (T=orig retx, t=resp retx)
    ('SF', 4, 'ShADadfFa'),      # FIN-ACK with trailing ACK
    ('SF', 3, 'ShADaDaDadfF'),   # Bulk transfer (many data rounds)
    ('SF', 2, 'ShADadFf'),       # Originator FIN first (client closes)
    ('SF', 2, 'ShADadfF'),       # Responder FIN first (server closes)
    ('SF', 1, 'ShADadTFf'),      # Retransmit then FIN
    # Connection attempts (S0)
    ('S0', 3, 'S'),              # Single SYN, no reply
    ('S0', 2, 'S'),              # SYN retransmit (Zeek deduplicates to single 'S')
    # Partial handshakes (S1)
    ('S1', 2, 'ShR'),            # SYN-ACK seen, RST
    ('S1', 1, 'Sh'),             # SYN-ACK seen, no further data
    # Rejected connections (REJ)
    ('REJ', 2, 'Sr'),            # RST from responder immediately
    ('REJ', 1, 'Srr'),           # Multiple RSTs from responder
    # Reset by originator (RSTO)
    ('RSTO', 2, 'ShADaR'),       # Data exchange then originator RST
    ('RSTO', 1, 'ShADadTR'),     # Data + retransmit then RST
    ('RSTO', 1, 'ShAR'),         # Quick RST after handshake
    # Reset by responder (RSTR)
    ('RSTR', 1, 'ShADadR'),      # Data exchange then responder RST
    ('RSTR', 1, 'ShAdR'),        # Partial data then responder RST
    # Midstream (OTH)
    ('OTH', 1, 'Cc'),            # Midstream traffic (no SYN/SYN-ACK seen)
    ('OTH', 1, 'DdA'),           # Midstream data
]

# Zeek UDP connection state distribution
# UDP has no TCP handshake — only D/d datagram flags
UDP_CONN_STATE_DISTRIBUTION = [
    ('SF', 65, 'Dd'),            # Normal bidirectional exchange (query + response)
    ('SF', 8, 'DdDd'),           # Multi-packet exchange
    ('SF', 4, 'DdDdDd'),         # Extended multi-packet exchange
    ('SF', 3, 'DdA'),            # Additional acknowledgment packet
    ('S0', 10, 'D'),             # Originator only, no response (timeout)
    ('S0', 3, 'DD'),             # Retransmitted datagram, no response
    ('OTH', 4, 'Dd'),            # Midstream UDP exchange
    ('OTH', 3, 'DdDdA'),         # Midstream multi-packet with ACK
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

# Reverse DNS mapping: IP → hostname (for DNS query generation)
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

# SRV query → port mapping
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


def _generate_internal_hostname(rng, ip: str) -> str:
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
    return f"{prefix}-{suffix}.corp.local"


def _generate_random_hostname(rng, ip: str) -> str:
    """Generate a plausible hostname for a random CDN/cloud IP.

    Uses realistic hostname formats that match actual CDN/cloud naming conventions.
    """
    # Generate realistic CloudFront distribution IDs (alphanumeric hashes)
    cf_chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    cf_id = ''.join(rng.choices(cf_chars, k=13))

    # Realistic EC2 reverse DNS format: ec2-{octets}.{region}.compute.amazonaws.com
    octets = ip.split('.')
    regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']

    # Realistic googleusercontent rDNS: 4 hyphenated octets
    gc_octets = f"{rng.randint(1,255)}-{rng.randint(1,255)}-{rng.randint(1,255)}-{rng.randint(1,255)}"

    templates = [
        f"d{cf_id}.cloudfront.net",
        f"e{rng.randint(10000, 99999)}.dscb.akamaiedge.net",
        f"ec2-{'-'.join(octets)}.{rng.choice(regions)}.compute.amazonaws.com",
        f"{rng.choice(regions)}-elb-{rng.randint(1,50)}.{rng.choice(regions)}.elb.amazonaws.com",
        f"{gc_octets}.bc.googleusercontent.com",
        f"a{rng.randint(100, 999)}.dscg.akamaiedge.net",
    ]
    return rng.choice(templates)


def _is_invalid_network_connection(src_ip: str, dst_ip: str) -> tuple[bool, str]:
    """Validate that a network connection would be observable by network sensors.

    Network-based data sources like Zeek can only observe traffic that actually
    traverses the network. This function checks for connections that would never
    be visible to network sensors.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address

    Returns:
        Tuple of (is_invalid, reason). If is_invalid=True, connection should not be generated.
    """
    # Check if source and destination are the same
    if src_ip == dst_ip:
        return True, f"Source and destination are identical ({src_ip})"

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
        sid_registry: Optional[dict[str, str]] = None,
        dispatcher: Optional[EventDispatcher] = None,
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
            network_visibility: Optional NetworkVisibilityEngine for sensor-based filtering
            sid_registry: Optional dict mapping usernames to Windows SIDs
            dispatcher: Optional EventDispatcher for canonical event model (Phase 7)
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

        # Process tree tracking: recent user processes per (hostname, username)
        # Used by _select_parent_pid() for realistic parent-child relationships
        self._user_process_history: dict[tuple[str, str], list[tuple[int, str]]] = {}

        # Network visibility stored on dispatcher; keep local ref for fast-path check
        self._network_visibility = network_visibility

    def _build_host_context(self, system: System) -> HostContext:
        """Build a HostContext from a System model object.

        Precomputes FQDN and NetBIOS domain so render methods don't have to.
        """
        ad_domain = getattr(self, '_ad_domain', '')
        hostname = system.hostname
        return HostContext(
            hostname=hostname,
            ip=system.ip,
            os=system.os,
            os_category=_get_os_category(system.os),
            system_type=system.type,
            domain=ad_domain,
            fqdn=f"{hostname}.{ad_domain}" if ad_domain else hostname,
            netbios_domain=ad_domain.split('.')[0].upper() if ad_domain else 'CORP',
        )

    def _build_dc_host_context(self, dc_hostname: str) -> HostContext:
        """Build a HostContext for a domain controller from raw hostname string.

        DC methods receive raw strings (not System objects). Constructs a
        HostContext suitable for Windows event rendering (Computer field).
        """
        ad_domain = getattr(self, '_ad_domain', 'corp.local')
        return HostContext(
            hostname=dc_hostname,
            ip='',
            os='Windows Server 2019',
            os_category='windows',
            system_type='domain_controller',
            domain=ad_domain,
            fqdn=f"{dc_hostname}.{ad_domain}" if ad_domain else dc_hostname,
            netbios_domain=ad_domain.split('.')[0].upper() if ad_domain else 'CORP',
        )

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: Optional[str] = None
    ) -> str:
        """Generate logon event across all applicable log formats.

        Creates session in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4624 + optional 4672, syslog auth, eCAR).

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

        # Phase 1: Allocate IDs from StateManager
        logon_id = self.state_manager.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=logon_type,
            source_ip=source_ip
        )

        # Select auth package (semantic data, not format-specific)
        auth_pkg = self._select_auth_package(logon_type)

        # Phase 2: Build SecurityEvent with all contexts
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                logon_type=logon_type,
                auth_package=auth_pkg.get('AuthenticationPackageName', 'Negotiate'),
                source_ip=source_ip,
                elevated=_get_rng().random() < 0.15,
                logon_process=auth_pkg.get('LogonProcessName', ''),
                lm_package=auth_pkg.get('LmPackageName', '-'),
                logon_guid=auth_pkg.get('LogonGuid', '{00000000-0000-0000-0000-000000000000}'),
                subject_sid=self._get_sid('SYSTEM'),
                subject_username='SYSTEM',
                subject_domain='NT AUTHORITY',
                subject_logon_id='0x3e7',
                reporting_pid=self._get_system_pid(system.hostname, "lsass", 0x2e0),
            ),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        logger.debug(f"Generated logon: {user.username} on {system.hostname} (LogonID: {logon_id})")
        return logon_id

    def generate_failed_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: Optional[str] = None,
    ) -> None:
        """Generate a failed logon event.

        Does NOT create a session in StateManager. Builds a SecurityEvent with
        result="failure" and dispatches to matching emitters (Windows 4625,
        syslog "Failed password", eCAR LOGIN with failure_reason).

        Args:
            user: User attempting to log on
            system: Target system
            time: Attempt timestamp
            logon_type: Logon type attempted
            source_ip: Source IP (defaults to system IP for interactive)
        """
        if source_ip is None:
            source_ip = system.ip if logon_type != 3 else "127.0.0.1"

        # Determine failure substatus with correct SID handling
        rng = _get_rng()
        substatus_roll = rng.random()
        if substatus_roll < 0.60:
            substatus = '0xc000006a'  # Wrong password
            user_sid = self._get_sid(user.username)
            failure_reason = '%%2313'
        elif substatus_roll < 0.85:
            substatus = '0xc0000064'  # User not found: NULL SID
            user_sid = 'S-1-0-0'
            failure_reason = '%%2313'
        elif substatus_roll < 0.95:
            substatus = '0xc0000234'  # Account locked out
            user_sid = self._get_sid(user.username)
            failure_reason = '%%2304'
        else:
            substatus = '0xc0000072'  # Account disabled
            user_sid = self._get_sid(user.username)
            failure_reason = '%%2307'

        event = SecurityEvent(
            timestamp=time,
            event_type="failed_logon",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=user_sid,
                logon_type=logon_type,
                auth_package='Negotiate',
                result='failure',
                failure_reason=failure_reason,
                failure_status='0xc000006d',
                failure_substatus=substatus,
                source_ip=source_ip,
                subject_sid=self._get_sid('SYSTEM'),
                subject_username='SYSTEM',
                subject_domain='NT AUTHORITY',
                subject_logon_id='0x3e7',
            ),
        )

        self.dispatcher.dispatch(event)

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
        # Build SecurityEvent (StateManager.apply() handles end_session)
        event = SecurityEvent(
            timestamp=time,
            event_type="logoff",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                logon_type=logon_type,
            ),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        logger.debug(f"Generated logoff: {user.username} on {system.hostname} (LogonID: {logon_id})")

    def generate_process(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int = 4
    ) -> int:
        """Generate process creation event across all applicable log formats.

        Creates process in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4688, eCAR PROCESS/CREATE). Also emits
        probabilistic eCAR file/module/registry events.

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

        # Phase 1: Allocate IDs from StateManager
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=user.username,
            integrity_level='Medium'
        )

        # Phase 2: Build SecurityEvent
        event = SecurityEvent(
            timestamp=time,
            event_type="process_create",
            host=self._build_host_context(system),
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
                integrity_level='Medium',
                logon_id=logon_id,
                parent_image=self._lookup_process_name(system.hostname, parent_pid),
                token_elevation='%%1938',
                mandatory_label='S-1-16-8192',
            ),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        # Phase 5.2: Probabilistic eCAR object diversity (via dispatch_raw)
        rng = _get_rng()
        os_category = _get_os_category(system.os)
        if 'ecar' in self.dispatcher.emitters:
            if rng.random() < 0.40:
                action = rng.choice(['CREATE', 'MODIFY', 'MODIFY', 'DELETE'])
                self._emit_ecar_file_event(system, time, pid, action, user.username)
            if os_category == 'windows' and rng.random() < 0.30:
                self._emit_ecar_module_event(system, time, pid, user.username)
            if os_category == 'windows' and 'system32' in process_name.lower() and rng.random() < 0.20:
                self._emit_ecar_registry_event(system, time, pid, user.username)

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

        event = SecurityEvent(
            timestamp=time,
            event_type="process_terminate",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=process_name,
                command_line='',
                username=user.username,
                logon_id=logon_id,
            ),
        )

        self.dispatcher.dispatch(event)

        logger.debug(f"Generated process termination: {process_name} (PID: {pid}) on {system.hostname}")

    def generate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        dst_port: int = 443,
        proto: str = 'tcp',
        service: Optional[str] = None,
        duration: Optional[float] = None,
        orig_bytes: Optional[int] = None,
        resp_bytes: Optional[int] = None,
        src_port: Optional[int] = None,
    ) -> str:
        """Generate network connection across all applicable log formats.

        Opens connection in StateManager, builds a SecurityEvent with
        NetworkContext, and dispatches to matching emitters (Zeek conn,
        Snort, eCAR FLOW). Dispatcher handles network visibility filtering.

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

        Returns:
            Zeek UID (18-character string)
        """
        from evidenceforge.events.contexts import NetworkContext

        # Validate connection would be observable by network sensors
        is_invalid, reason = _is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            logger.warning(
                f"Skipping invalid network connection: {src_ip} -> {dst_ip}. "
                f"Reason: {reason}. Network sensors would not observe this traffic."
            )
            return ""

        # Phase 2.5: Check network topology visibility
        visibility = self._network_visibility or (self.dispatcher.visibility_engine if self.dispatcher else None)
        if visibility and not visibility.is_connection_visible(src_ip, dst_ip):
            logger.debug(
                f"Skipping connection {src_ip} -> {dst_ip}: "
                f"not observable by any configured sensor"
            )
            return ""

        if src_port is None:
            src_port = _get_rng().randint(49152, 65535)

        # Phase 1: Allocate IDs from StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port, protocol=proto
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        if orig_bytes is not None and resp_bytes is not None:
            self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Protocol-aware connection state selection
        rng = _get_rng()

        if proto == 'icmp':
            conn_state = 'OTH'
            history = '-'
            src_port = 8   # Echo request type
            dst_port = 0   # Echo reply type
        elif proto == 'udp':
            entry = rng.choices(_UDP_CONN_ENTRIES, weights=_UDP_CONN_WEIGHTS, k=1)[0]
            conn_state, _, history = entry
            if conn_state == 'S0':
                duration = None
                resp_bytes = 0
        else:
            if duration is not None:
                entry = rng.choices(_TCP_CONN_ENTRIES, weights=_TCP_CONN_WEIGHTS, k=1)[0]
                conn_state, _, history = entry
            else:
                conn_state = 'S0'
                history = 'S'
            if conn_state in ('S0', 'REJ'):
                duration = None
                resp_bytes = 0
                if conn_state == 'REJ':
                    orig_bytes = orig_bytes if orig_bytes else 0
            elif conn_state in ('RSTO', 'RSTR'):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))

        # Calculate packet counts — enforce consistency with history
        if proto == 'udp' and history:
            orig_pkts = history.count('D')
            resp_pkts = history.count('d')
            if orig_pkts > 0 and orig_bytes:
                orig_bytes = max(orig_bytes, orig_pkts * 28)
            if resp_pkts > 0 and resp_bytes:
                resp_bytes = max(resp_bytes, resp_pkts * 28)
            elif resp_pkts == 0:
                resp_bytes = 0
        elif proto == 'tcp' and history and history != '-':
            hist_orig = sum(1 for c in history if c.isupper())
            hist_resp = sum(1 for c in history if c.islower())
            byte_orig = max(1, (orig_bytes // 1460) + 1) if orig_bytes else 1
            byte_resp = max(1, (resp_bytes // 1460) + 1) if resp_bytes else 0
            orig_pkts = max(hist_orig, byte_orig)
            resp_pkts = max(hist_resp, byte_resp) if resp_bytes else hist_resp
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0

        overhead = 28 if proto == 'udp' else _get_rng().randint(52, 72)
        orig_ip_bytes = (orig_bytes + orig_pkts * overhead) if orig_bytes and orig_pkts else None
        resp_ip_bytes = (resp_bytes + resp_pkts * overhead) if resp_bytes and resp_pkts else None

        ip_proto = 6 if proto == 'tcp' else 17 if proto == 'udp' else 1

        # Port-based service correction (Zeek detects service from payload, not scenario labels)
        _PORT_SERVICE = {80: 'http', 443: 'https', 22: 'ssh', 53: 'dns', 25: 'smtp', 587: 'smtp', 88: 'kerberos', 389: 'ldap', 445: 'smb'}
        if service and dst_port in _PORT_SERVICE and service != _PORT_SERVICE[dst_port]:
            service = _PORT_SERVICE[dst_port]

        # Phase 2: Build SecurityEvent with NetworkContext
        event = SecurityEvent(
            timestamp=time,
            event_type="connection",
            network=NetworkContext(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol=proto, service=service or '',
                zeek_uid=uid, conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes, resp_bytes=resp_bytes,
                orig_pkts=orig_pkts, resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes, resp_ip_bytes=resp_ip_bytes,
                conn_state=conn_state, history=history,
                local_orig=_is_private_ip(src_ip),
                local_resp=_is_private_ip(dst_ip),
                ip_proto=ip_proto,
            ),
        )

        # Phase 3: Dispatch to matching emitters (visibility handled by dispatcher)
        self.dispatcher.dispatch(event)
        logger.debug(f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})")

        # eCAR FLOW still via helper (not format-filtered by visibility)
        self._emit_ecar_flow_event(src_ip, dst_ip, dst_port, time, src_ip, src_port=src_port, protocol=proto)

        return uid

    def generate_bash_command(
        self,
        user: User,
        system: System,
        time: datetime,
        activity_type: str = 'default'
    ) -> None:
        """Generate bash command history entry via dispatch.

        Builds a SecurityEvent with ShellContext and dispatches.
        BashHistoryEmitter.can_handle() filters for Linux-only.

        Args:
            user: User executing command
            system: Linux system
            time: Command execution time
            activity_type: Type of activity (process_code, process_build, etc.)
        """
        from evidenceforge.events.contexts import ShellContext

        # Select command based on activity type
        commands = {
            'process_code': ['vim script.py', 'nano config.conf', 'code .'],
            'process_build': ['make', 'gcc -o output source.c', 'npm run build'],
            'connection_web': ['curl https://example.com', 'wget https://github.com/repo/file.tar.gz'],
            'default': ['ls -la', 'ps aux', 'top', 'df -h']
        }

        command_list = commands.get(activity_type, commands['default'])
        command = _get_rng().choice(command_list)

        event = SecurityEvent(
            timestamp=time,
            event_type="bash_command",
            host=self._build_host_context(system),
            auth=AuthContext(username=user.username),
            shell=ShellContext(command=command),
        )

        self.dispatcher.dispatch(event)
        logger.debug(f"Generated bash command: {command} by {user.username} on {system.hostname}")

    def generate_system_process(
        self,
        system: System,
        time: datetime,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        username: str = "SYSTEM",
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
            integrity_level='System',
        )

        # Determine system-level SID and logon ID
        sid = self.sid_registry.get(username, 'S-1-5-18') if self.sid_registry else 'S-1-5-18'
        system_logon_ids = {'SYSTEM': '0x3e7', 'LOCAL SERVICE': '0x3e5', 'NETWORK SERVICE': '0x3e4'}
        logon_id = system_logon_ids.get(username, '0x3e7')

        event = SecurityEvent(
            timestamp=time,
            event_type="system_process_create",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=username,
                user_sid=sid,
                logon_id=logon_id,
                subject_sid=sid,
                subject_username=username,
                subject_domain='NT AUTHORITY',
                subject_logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=username,
                integrity_level='System',
                logon_id=logon_id,
                parent_image=r'C:\Windows\System32\services.exe',
                token_elevation='%%1936',
                mandatory_label='S-1-16-16384',
            ),
        )

        self.dispatcher.dispatch(event)

        return pid

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
    ) -> None:
        """Emit a DNS lookup preceding a TCP connection.

        Generates both a Zeek conn.log UDP/53 record and a Zeek dns.log record
        with consistent fields. The dns.log answers field contains the dst_ip
        that the subsequent TCP connection will use.

        Args:
            src_ip: IP of the system making the query
            dst_ip: IP that will be resolved (the "answer")
            time: Timestamp of the DNS query (should precede TCP connection)
        """
        rng = _get_rng()

        # Look up hostname for this IP, or generate one
        hostname = REVERSE_DNS.get(dst_ip)
        if not hostname:
            if _is_private_ip(dst_ip):
                hostname = _generate_internal_hostname(rng, dst_ip)
            else:
                hostname = _generate_random_hostname(rng, dst_ip)

        # DNS caching: skip re-emission if this (src, hostname) was queried recently.
        # Real clients cache DNS responses (TTL typically 60-3600s), so not every
        # connection is preceded by a DNS query.
        if not hasattr(self, '_dns_cache'):
            self._dns_cache: dict[tuple[str, str], float] = {}
        cache_key = (src_ip, hostname)
        ts_epoch = time.timestamp()
        last_query = self._dns_cache.get(cache_key, 0)
        cache_ttl = rng.choice([60, 120, 300, 600])  # Varied TTLs
        if ts_epoch - last_query < cache_ttl:
            return  # Cache hit — skip DNS emission
        self._dns_cache[cache_key] = ts_epoch

        # Determine DNS server IP from network visibility or use default
        dns_ips = getattr(self, '_dns_server_ips', ['10.0.0.1'])
        dns_server_ip = _get_rng().choice(dns_ips)

        src_port = rng.randint(49152, 65535)

        # Emit Zeek conn.log UDP/53 record — UID is generated in StateManager
        # and shared with dns.log for cross-log correlation.
        # Pass src_port so conn.log and dns.log share the same 5-tuple.
        dns_time = time - timedelta(milliseconds=rng.randint(10, 50))
        dns_uid = self.generate_connection(
            src_ip=src_ip,
            dst_ip=dns_server_ip,
            time=dns_time,
            dst_port=53,
            proto='udp',
            service='dns',
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(40, 100),
            resp_bytes=rng.randint(80, 400),
            src_port=src_port,
        )

        # Emit Zeek dns.log record
        if 'zeek_dns' in self.dispatcher.emitters:
            # Phase 6.3: 0.2% chance of SERVFAIL (transient failures)
            if rng.random() < 0.002:
                self.dispatcher.dispatch_raw(RawLogEntry(
                    timestamp=dns_time, target_emitter='zeek_dns',
                    data={'ts': dns_time, 'uid': dns_uid,
                          'id.orig_h': src_ip, 'id.orig_p': src_port,
                          'id.resp_h': dns_server_ip, 'id.resp_p': 53,
                          'proto': 'udp', 'trans_id': rng.randint(1, 65535),
                          'query': hostname, 'qclass': 1, 'qclass_name': 'C_INTERNET',
                          'qtype': 1, 'qtype_name': 'A',
                          'rcode': 2, 'rcode_name': 'SERVFAIL',
                          'AA': False, 'TC': False, 'RD': True, 'RA': True,
                          'answers': '-', 'TTLs': '-', 'rejected': False},
                ))
                return

            # Determine query type, query string, and answer
            qtype_roll = rng.random()
            is_internal = hostname.endswith('.corp.local') or hostname.endswith('.local')

            if qtype_roll < 0.65:
                # A record: hostname → IPv4
                qtype, qtype_name = 1, 'A'
                query = hostname
                # Multi-answer: CDNs/clouds return multiple A records (40% chance)
                if not is_internal and rng.random() < 0.40:
                    # Find sibling IPs from the SAME PROVIDER (not cross-provider)
                    sibling_ips = []
                    for provider_ips in _PROVIDER_IP_GROUPS:
                        if dst_ip in provider_ips:
                            sibling_ips = [ip for ip in provider_ips if ip != dst_ip]
                            break
                    if sibling_ips:
                        extra = rng.sample(sibling_ips, min(rng.randint(1, 2), len(sibling_ips)))
                        answers = ', '.join([dst_ip] + extra)
                    else:
                        answers = dst_ip
                else:
                    answers = dst_ip
            elif qtype_roll < 0.85:
                # AAAA record: hostname → IPv6
                qtype, qtype_name = 28, 'AAAA'
                query = hostname
                answers = _IPV6_MAP.get(dst_ip, _ipv4_to_fake_ipv6(dst_ip))
            elif qtype_roll < 0.93:
                # PTR record: reversed IP → hostname
                qtype, qtype_name = 12, 'PTR'
                octets = dst_ip.split('.')
                query = '.'.join(reversed(octets)) + '.in-addr.arpa'
                answers = hostname
            elif qtype_roll < 0.98:
                # SRV record: AD service discovery
                qtype, qtype_name = 33, 'SRV'
                domain = 'corp.local'
                query = rng.choice(_AD_SRV_QUERIES).format(domain=domain)
                dc_ips = getattr(self, '_dns_server_ips', ['10.0.0.1'])
                dc_ip = _get_rng().choice(dc_ips)
                dc_hostname = REVERSE_DNS.get(dc_ip, f'dc-01.{domain}')
                # Determine port from service prefix
                svc_prefix = query.split('.')[0]  # e.g., '_ldap'
                port = _SRV_PORT_MAP.get(svc_prefix, 389)
                answers = f'0 100 {port} {dc_hostname}'
                is_internal = True
            else:
                # MX record: domain → mail server
                qtype, qtype_name = 15, 'MX'
                parts = hostname.split('.', 1)
                query = parts[1] if len(parts) > 1 else hostname
                answers = f'10 mail.{query}'

            # Phase 6.0: varied TTLs (not just round numbers)
            ttl = rng.choice([30, 60, 120, 247, 300, 598, 1800, 3600, 7200, 86400])

            # Match TTLs count to answers count for multi-answer responses
            num_answers = answers.count(', ') + 1 if isinstance(answers, str) and ', ' in answers else 1
            ttls_str = ', '.join([str(ttl)] * num_answers)

            # This lookup precedes an actual connection, so always NOERROR
            self.dispatcher.dispatch_raw(RawLogEntry(
                timestamp=dns_time, target_emitter='zeek_dns',
                data={'ts': dns_time, 'uid': dns_uid,
                      'id.orig_h': src_ip, 'id.orig_p': src_port,
                      'id.resp_h': dns_server_ip, 'id.resp_p': 53,
                      'proto': 'udp', 'trans_id': rng.randint(1, 65535),
                      'query': query, 'qclass': 1, 'qclass_name': 'C_INTERNET',
                      'qtype': qtype, 'qtype_name': qtype_name,
                      'rcode': 0, 'rcode_name': 'NOERROR',
                      'AA': is_internal, 'TC': False, 'RD': True, 'RA': True,
                      'answers': answers, 'TTLs': ttls_str, 'rejected': False},
            ))

            # Phase 6.0: ~20% chance of emitting an additional NXDOMAIN query
            # (suffix search failure, WPAD probe, etc.) alongside the real lookup
            if rng.random() < 0.20:
                nxdomain_queries = [
                    f'{hostname}.corp.local',  # Suffix search failure
                    'wpad.corp.local', 'wpad.local', 'wpad',
                    'isatap.corp.local', 'isatap',
                    '_ldap._tcp.Default-First-Site-Name._sites.corp.local',
                    'oldserver.corp.local', 'printer01.corp.local',
                ]
                nx_query = rng.choice(nxdomain_queries)
                nx_time = dns_time - timedelta(milliseconds=rng.randint(1, 10))
                nx_src_port = rng.randint(49152, 65535)
                # Emit conn.log first to get the shared UID
                nx_uid = self.generate_connection(
                    src_ip=src_ip, dst_ip=dns_server_ip, time=nx_time,
                    dst_port=53, proto='udp', service='dns',
                    duration=rng.uniform(0.001, 0.01),
                    orig_bytes=rng.randint(40, 80), resp_bytes=rng.randint(80, 200),
                    src_port=nx_src_port,
                )
                self.dispatcher.dispatch_raw(RawLogEntry(
                    timestamp=nx_time, target_emitter='zeek_dns',
                    data={'ts': nx_time, 'uid': nx_uid,
                          'id.orig_h': src_ip, 'id.orig_p': nx_src_port,
                          'id.resp_h': dns_server_ip, 'id.resp_p': 53,
                          'proto': 'udp', 'trans_id': rng.randint(1, 65535),
                          'query': nx_query, 'qclass': 1, 'qclass_name': 'C_INTERNET',
                          'qtype': 1, 'qtype_name': 'A',
                          'rcode': 3, 'rcode_name': 'NXDOMAIN',
                          'AA': True, 'TC': False, 'RD': True, 'RA': True,
                          'answers': '-', 'TTLs': '-', 'rejected': False},
                ))

    def get_baseline_pattern(
        self,
        persona_name: Optional[str],
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
        return BASELINE_PATTERNS['default']

    def _build_pattern_from_intensity(
        self, intensity: dict[str, int]
    ) -> list[tuple[str, float]]:
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

        # Normalize intensities to probabilities (cap at 0.95)
        max_val = max(intensity.values())
        for activity, value in intensity.items():
            if activity == "logon":
                continue  # Already added
            prob = min(0.95, value / max_val * 0.8 + 0.1)
            pattern.append((activity, prob))

        return pattern

    def execute_baseline_activity(
        self,
        user: User,
        system: System,
        time: datetime,
        activity_type: str
    ) -> None:
        """Execute a specific baseline activity type.

        Args:
            user: User performing the activity
            system: System where activity occurs
            time: Activity timestamp
            activity_type: Type of activity to execute
        """
        # Logon activity (10% chance of failure — bad password)
        if activity_type == 'logon':
            if _get_rng().random() < 0.10:
                self.generate_failed_logon(user, system, time)
                return

            # Phase 6.2: Realistic logon type distribution by system type
            # Type 3 (network) should dominate in AD; Type 5 only for service accounts
            rng = _get_rng()
            sys_type = (system.type or 'workstation').lower()
            is_service_account = (
                user.username.endswith('$') or
                user.username.lower().startswith('svc')
            )

            if sys_type in ('server', 'domain_controller'):
                # Servers/DCs: Type 3 (network) dominates
                logon_type = rng.choices(
                    [3, 5, 10, 4, 2, 8, 9],
                    weights=[70, 15, 8, 4, 1, 1, 1], k=1)[0]
            elif is_service_account:
                # Service accounts on workstations: network + service logons
                logon_type = rng.choices(
                    [3, 5, 10],
                    weights=[70, 25, 5], k=1)[0]
            else:
                # Regular users on workstations: Type 3 dominant, no Type 5
                logon_type = rng.choices(
                    [3, 2, 7, 11, 10],
                    weights=[55, 20, 10, 10, 5], k=1)[0]

            # Type 3 (network) logons are standalone events, not interactive sessions
            if logon_type in (3, 4, 5, 8, 9):
                # Pick a source IP from another system for network logons
                source_ip = None
                if logon_type == 3 and hasattr(self, '_all_system_ips'):
                    other_ips = [ip for ip in self._all_system_ips if ip != system.ip]
                    if other_ips:
                        source_ip = rng.choice(other_ips)
                self.generate_logon(user, system, time, logon_type=logon_type,
                                    source_ip=source_ip if source_ip else system.ip)
                # Don't create a session — these are background auth events
                return

            # Interactive logon types (2, 7, 10, 11) — create sessions
            source_ip = '127.0.0.1' if logon_type == 7 else None
            self.generate_logon(user, system, time, logon_type=logon_type,
                                source_ip=source_ip)

        # Process activities
        elif activity_type in PROCESS_TEMPLATES:
            # Get or create session for this user
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if not sessions:
                # No active session - create one first
                logon_id = self.generate_logon(user, system, time)
            else:
                logon_id = sessions[0].logon_id  # Use first active session

            # Phase 2.10: OS-aware process template selection
            os_category = _get_os_category(system.os)
            if os_category == 'windows' and activity_type in PROCESS_TEMPLATES:
                # Phase 5.6: Per-persona app pool for user diversity
                pool = PROCESS_TEMPLATES[activity_type]
                if activity_type == 'process_user_apps':
                    persona_key = (user.persona or 'default').lower()
                    indices = PERSONA_APP_INDICES.get(persona_key, PERSONA_APP_INDICES['default'])
                    pool = [pool[i] for i in indices if i < len(pool)]
                process_name, command_line = _get_rng().choice(pool)
                # Phase 5.1: Substitute username placeholder in paths
                process_name = process_name.replace('{username}', user.username)
                command_line = command_line.replace('{username}', user.username)
                parent_pid = self._select_parent_pid(system, user, process_name)
                pid = self.generate_process(user, system, time, logon_id, process_name, command_line, parent_pid=parent_pid)
                self._record_user_process(system, user, pid, process_name)

            elif os_category == 'linux' and activity_type in PROCESS_TEMPLATES_LINUX:
                # Phase 5.6: Per-persona app pool for Linux user diversity
                pool = PROCESS_TEMPLATES_LINUX[activity_type]
                if activity_type == 'process_user_apps':
                    persona_key = (user.persona or 'default').lower()
                    indices = PERSONA_APP_INDICES_LINUX.get(persona_key, PERSONA_APP_INDICES_LINUX['default'])
                    pool = [pool[i] for i in indices if i < len(pool)]
                process_name, command_line = _get_rng().choice(pool)
                parent_pid = self._select_parent_pid(system, user, process_name)
                pid = self.generate_process(user, system, time, logon_id, process_name, command_line, parent_pid=parent_pid)
                self._record_user_process(system, user, pid, process_name)

                # Also generate bash history for Linux
                self.generate_bash_command(user, system, time, activity_type)

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            rng = _get_rng()

            # Phase 5.3: 30% chance of random CDN/cloud IP for destination diversity
            if activity_type in ('connection_web', 'connection_saas') and rng.random() < 0.30:
                dst_ip = _generate_random_external_ip(rng)
            else:
                available_destinations = [
                    ip for ip in EXTERNAL_IPS[activity_type]
                    if ip != system.ip
                ]
                if not available_destinations:
                    logger.debug(
                        f"Skipping {activity_type} for {system.hostname}: "
                        f"no valid destination IPs (all match source {system.ip})"
                    )
                    return
                dst_ip = rng.choice(available_destinations)

            # Set service and port based on activity type
            if activity_type in ('connection_web', 'connection_saas'):
                service = rng.choice(['http', 'https'])
                dst_port = 443 if service == 'https' else 80
            elif activity_type == 'connection_email':
                service = 'smtp'
                # Route through internal Exchange if detected (P1-15)
                exchange_ip = getattr(self, '_exchange_ip', None)
                if exchange_ip:
                    dst_ip = exchange_ip
                    dst_port = 25  # Internal SMTP relay uses port 25
                else:
                    dst_port = 587
            elif activity_type == 'connection_git':
                service = 'https'
                dst_port = 443
            elif activity_type == 'connection_db':
                db_servers = getattr(self, '_db_servers', [])
                if db_servers:
                    db = _get_rng().choice(db_servers)
                    dst_ip = db['ip']
                    service = db['service']
                    dst_port = db['port']
                else:
                    # No DB servers detected from scenario; skip DB connection
                    return
            else:
                service = None
                dst_port = 443

            # Phase 5.3: Emit DNS lookup before TCP connection
            self._emit_dns_lookup(system.ip, dst_ip, time)

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
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes
            )

    def generate_machine_account_logon(
        self,
        hostname: str,
        machine_username: str,
        dc_hostname: str,
        source_ip: str,
        dc_ip: str,
        time: datetime,
        domain: str = '',
    ) -> None:
        """Generate machine account logon event (4624 type 3) on the DC.

        Machine accounts (COMPUTERNAME$) authenticate to DCs constantly for
        GPO updates, Kerberos renewal, LDAP queries, etc. The event is logged
        on the DC, not on the source machine.
        """
        domain = domain or getattr(self, '_netbios_domain', 'CORP')
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="machine_logon",
            host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=f'0x{rng.randint(0x10000, 0xFFFFF):x}',
                logon_type=3,
                auth_package='Kerberos',
                source_ip=source_ip,
                logon_process='Kerberos',
                lm_package='-',
                logon_guid='{00000000-0000-0000-0000-000000000000}',
                subject_sid=self._get_sid('SYSTEM'),
                subject_username='SYSTEM',
                subject_domain='NT AUTHORITY',
                subject_logon_id='0x3e7',
            ),
        )
        self.dispatcher.dispatch(event)

        # Also generate the Kerberos network connection to DC
        self.generate_connection(
            src_ip=source_ip, dst_ip=dc_ip, time=time,
            dst_port=88, proto='tcp', service='kerberos',
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
        domain: str = '',
    ) -> None:
        """Generate Kerberos TGT request event (4768) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        domain = domain or getattr(self, '_netbios_domain', 'CORP')
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt",
            host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name='krbtgt',
                service_sid=self._get_sid('krbtgt'),
                ticket_options='0x40810010',
                encryption_type='0x12',
                pre_auth_type=15,
                source_ip=f'::ffff:{source_ip}',
                source_port=rng.randint(49152, 65535),
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
        domain: str = '',
    ) -> None:
        """Generate Kerberos service ticket request event (4769) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        domain = domain or getattr(self, '_netbios_domain', 'CORP')
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_service",
            host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=f'{username}@{domain}',
                target_domain=domain,
                service_name=service_name,
                service_sid=self._get_sid(f"{service_name.split('/')[1]}$" if '/' in service_name else service_name),
                ticket_options='0x40810000',
                encryption_type='0x12',
                source_ip=f'::ffff:{source_ip}',
                source_port=rng.randint(49152, 65535),
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
            host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=username,
                source_ip=workstation,  # SourceWorkstation stored in source_ip
            ),
        )

        self.dispatcher.dispatch(event)

    def _get_next_event_record_id(self, hostname: str = '') -> int:
        """Get next EventRecordID for a specific computer (thread-safe).

        Real Windows event logs have per-computer sequential IDs. Each host
        starts at a random offset (1000-50000) to simulate uptime history.

        Args:
            hostname: Computer hostname for per-machine counter
        """
        with self._counter_lock:
            if hostname not in self._event_record_counters:
                rng = random.Random(hash(f"erid_{hostname}"))
                self._event_record_counters[hostname] = rng.randint(1000, 50000)
            self._event_record_counters[hostname] += 1
            return self._event_record_counters[hostname]

    # Well-known Windows SIDs (always available regardless of registry)
    _WELL_KNOWN_SIDS = {
        'SYSTEM': 'S-1-5-18',
        'LOCAL SERVICE': 'S-1-5-19',
        'NETWORK SERVICE': 'S-1-5-20',
    }

    def _select_auth_package(self, logon_type: int) -> dict[str, str]:
        """Select auth package, LogonProcessName, and LogonGuid based on logon type.

        In real AD: Kerberos dominates for network logons, NTLM as fallback,
        Negotiate for interactive logons.
        """
        rng = _get_rng()
        if logon_type == 2:
            # Interactive: Negotiate (local login)
            return {
                'LogonProcessName': 'User32',
                'AuthenticationPackageName': 'Negotiate',
                'LmPackageName': '-',
                'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
            }
        elif logon_type in (3, 4, 5, 8, 9):
            # Network/batch/service: Kerberos dominates in AD
            roll = rng.random()
            if roll < 0.70:
                return {
                    'LogonProcessName': 'Kerberos',
                    'AuthenticationPackageName': 'Kerberos',
                    'LmPackageName': '-',
                    'LogonGuid': f'{{{uuid.uuid4()}}}',
                }
            elif roll < 0.90:
                return {
                    'LogonProcessName': 'NtLmSsp',
                    'AuthenticationPackageName': 'NTLM',
                    'LmPackageName': 'NTLM V2',
                    'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
                }
            else:
                return {
                    'LogonProcessName': 'NtLmSsp',
                    'AuthenticationPackageName': 'Negotiate',
                    'LmPackageName': '-',
                    'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
                }
        elif logon_type == 10:
            # RDP: NtLmSsp/CredSSP
            return {
                'LogonProcessName': 'NtLmSsp',
                'AuthenticationPackageName': rng.choice(['CredSSP', 'Negotiate']),
                'LmPackageName': '-',
                'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
            }
        else:
            # Type 7 (unlock), 11 (cached), etc.: Negotiate
            return {
                'LogonProcessName': 'Negotiate',
                'AuthenticationPackageName': 'Negotiate',
                'LmPackageName': '-',
                'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
            }

    def _get_system_pid(self, hostname: str, role: str, fallback: int) -> int:
        """Get a seeded system process PID by role name."""
        pids = getattr(self, '_system_pids', {}).get(hostname, {})
        return pids.get(role, fallback)

    def _lookup_process_name(self, hostname: str, pid: int) -> str:
        """Look up the image path of a running process by PID.

        Falls back to explorer.exe for user processes if PID not tracked.
        """
        key = (hostname, pid)
        proc = self.state_manager.state.running_processes.get(key)
        if proc:
            return proc.image
        return r'C:\Windows\explorer.exe'

    # Process names that can spawn child processes
    _WINDOWS_SHELLS = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'WindowsTerminal.exe'}
    _WINDOWS_SPAWNERS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'WindowsTerminal.exe',
        'outlook.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    }
    _LINUX_SHELLS = {'/bin/bash', '/bin/zsh', '/bin/sh', '/usr/bin/bash', '/usr/bin/zsh'}

    def _is_pid_alive(self, system: System, pid: int) -> bool:
        """Check if a PID is still running in state manager."""
        return self.state_manager.get_process(system.hostname, pid) is not None

    def _select_parent_pid(self, system: System, user: User, process_name: str) -> int:
        """Select a realistic parent PID based on process type and history.

        Builds process trees with depth by tracking recent user processes.
        Windows user processes typically spawn from explorer.exe or shells.
        Linux user processes typically spawn from login shells.

        Only returns PIDs that are still alive in the state manager.
        """
        rng = _get_rng()
        sys_pids = getattr(self, '_system_pids', {}).get(system.hostname, {})
        os_cat = _get_os_category(system.os)
        key = (system.hostname, user.username)
        history = self._user_process_history.get(key, [])
        # Filter history to only include still-running processes
        alive_history = [(pid, name) for pid, name in history
                         if self._is_pid_alive(system, pid)]

        if os_cat == 'windows':
            exe_name = process_name.rsplit('\\', 1)[-1].lower() if '\\' in process_name else process_name.lower()

            # Shells and terminals spawn from explorer.exe
            if exe_name in self._WINDOWS_SHELLS:
                return sys_pids.get('explorer', 4)

            # Check for a running shell in history that could be parent
            shells = [(pid, name) for pid, name in alive_history
                      if name.rsplit('\\', 1)[-1].lower() in self._WINDOWS_SHELLS]
            if shells and rng.random() < 0.6:
                return shells[-1][0]

            # Check for a browser/app that could spawn this process
            spawners = [(pid, name) for pid, name in alive_history
                        if name.rsplit('\\', 1)[-1].lower() in self._WINDOWS_SPAWNERS]
            if spawners and rng.random() < 0.3:
                return spawners[-1][0]

            # Default: explorer.exe
            return sys_pids.get('explorer', 4)
        else:
            # Linux: most user commands spawn from a shell
            shells = [(pid, name) for pid, name in alive_history
                      if name in self._LINUX_SHELLS]
            if shells:
                return shells[-1][0]
            return sys_pids.get('bash', sys_pids.get('sshd', 1))

    def _record_user_process(self, system: System, user: User, pid: int, process_name: str) -> None:
        """Record a user process in history for future parent selection."""
        key = (system.hostname, user.username)
        self._user_process_history.setdefault(key, []).append((pid, process_name))
        # Keep only last 10 processes per user/system
        if len(self._user_process_history[key]) > 10:
            self._user_process_history[key] = self._user_process_history[key][-10:]

    def _get_sid(self, username: str) -> str:
        """Look up Windows SID for a username.

        Args:
            username: Username to look up

        Returns:
            SID string, or a fallback SID if username not in registry
        """
        if username in self.sid_registry:
            return self.sid_registry[username]
        if username in self._WELL_KNOWN_SIDS:
            return self._WELL_KNOWN_SIDS[username]
        return 'S-1-5-21-0-0-0-0'

    # Phase 5.2: eCAR object type diversity data pools
    _ECAR_FILE_PATHS_WIN = [
        'C:\\Users\\{user}\\Documents\\report.docx',
        'C:\\Users\\{user}\\Documents\\spreadsheet.xlsx',
        'C:\\Users\\{user}\\Documents\\presentation.pptx',
        'C:\\Users\\{user}\\Downloads\\file.pdf',
        'C:\\Users\\{user}\\AppData\\Local\\Temp\\tmp{rand}.tmp',
        'C:\\Users\\{user}\\Desktop\\notes.txt',
        'C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\Report.wer',
    ]
    _ECAR_FILE_PATHS_LINUX = [
        '/home/{user}/documents/report.odt',
        '/home/{user}/downloads/file.pdf',
        '/tmp/tmp{rand}',
        '/home/{user}/.cache/mozilla/firefox/cache2/entries/{rand}',
        '/var/log/syslog',
    ]
    _ECAR_REGISTRY_KEYS = [
        ('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', 'a'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'SecurityHealth'),
        ('HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General', 'ShownFirstRunOptin'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Shell'),
        ('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyEnable'),
    ]
    _ECAR_DLL_POOL = [
        'C:\\Windows\\System32\\ntdll.dll',
        'C:\\Windows\\System32\\kernel32.dll',
        'C:\\Windows\\System32\\user32.dll',
        'C:\\Windows\\System32\\advapi32.dll',
        'C:\\Windows\\System32\\msvcrt.dll',
        'C:\\Windows\\System32\\rpcrt4.dll',
        'C:\\Windows\\System32\\ole32.dll',
        'C:\\Windows\\System32\\combase.dll',
        'C:\\Windows\\System32\\sechost.dll',
        'C:\\Windows\\System32\\gdi32.dll',
    ]

    def _emit_ecar_file_event(
        self, system: System, time: datetime, pid: int,
        action: str, username: str,
    ) -> None:
        """Emit eCAR FILE event via dispatch_raw (CREATE, MODIFY, or DELETE)."""
        if 'ecar' not in self.dispatcher.emitters:
            return
        rng = _get_rng()
        os_cat = _get_os_category(system.os)
        pool = self._ECAR_FILE_PATHS_WIN if os_cat == 'windows' else self._ECAR_FILE_PATHS_LINUX
        path = rng.choice(pool).replace('{user}', username).replace('{rand}', f'{rng.randint(10000, 99999)}')
        self.dispatcher.dispatch_raw(RawLogEntry(
            timestamp=time, target_emitter='ecar',
            data={'timestamp': time, 'hostname': system.hostname, 'object': 'FILE',
                  'action': action, 'pid': pid, 'principal': username, 'file_path': path},
        ))

    def _emit_ecar_registry_event(
        self, system: System, time: datetime, pid: int, username: str,
    ) -> None:
        """Emit eCAR REGISTRY/MODIFY event via dispatch_raw (Windows only)."""
        if 'ecar' not in self.dispatcher.emitters:
            return
        key, value = _get_rng().choice(self._ECAR_REGISTRY_KEYS)
        self.dispatcher.dispatch_raw(RawLogEntry(
            timestamp=time, target_emitter='ecar',
            data={'timestamp': time, 'hostname': system.hostname, 'object': 'REGISTRY',
                  'action': 'MODIFY', 'pid': pid, 'principal': username,
                  'registry_key': key, 'registry_value': value},
        ))

    def _emit_ecar_flow_event(
        self, src_ip: str, dst_ip: str, dst_port: int,
        time: datetime, hostname: str, pid: int = -1,
        src_port: int = 0, protocol: str = 'tcp',
    ) -> None:
        """Emit eCAR FLOW/CONNECT event via dispatch_raw."""
        if 'ecar' not in self.dispatcher.emitters:
            return
        if src_port == 0:
            src_port = _get_rng().randint(49152, 65535)
        if protocol not in ('udp', 'icmp') and dst_port in (53, 123):
            protocol = 'udp'
        self.dispatcher.dispatch_raw(RawLogEntry(
            timestamp=time, target_emitter='ecar',
            data={'timestamp': time, 'hostname': hostname, 'object': 'FLOW',
                  'action': 'CONNECT', 'pid': pid, 'src_ip': src_ip,
                  'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port,
                  'protocol': protocol},
        ))

    def _emit_ecar_module_event(
        self, system: System, time: datetime, pid: int, username: str,
    ) -> None:
        """Emit eCAR MODULE/LOAD event via dispatch_raw (DLL load, Windows only)."""
        if 'ecar' not in self.dispatcher.emitters:
            return
        dll_path = _get_rng().choice(self._ECAR_DLL_POOL)
        self.dispatcher.dispatch_raw(RawLogEntry(
            timestamp=time, target_emitter='ecar',
            data={'timestamp': time, 'hostname': system.hostname, 'object': 'MODULE',
                  'action': 'LOAD', 'pid': pid, 'principal': username, 'file_path': dll_path},
        ))
