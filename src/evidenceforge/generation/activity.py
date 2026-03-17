"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import logging
import random
from datetime import datetime, timedelta
from threading import local, get_ident, Lock
from typing import Optional

from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import User, System
from evidenceforge.utils.ids import generate_zeek_uid

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


# Fixed baseline activity patterns for Phase 1 (no LLM expansion)
# Format: (activity_type, probability)
BASELINE_PATTERNS = {
    'developer': [
        ('logon', 0.8),              # 80% chance of logon
        ('process_code', 0.6),       # 60% chance of code editor
        ('connection_git', 0.4),     # 40% chance of git operation
        ('process_build', 0.3),      # 30% chance of build
        ('process_user_apps', 0.25), # 25% chance of user app activity
    ],
    'executive': [
        ('logon', 0.9),
        ('connection_web', 0.7),
        ('connection_email', 0.6),
        ('process_user_apps', 0.5),  # 50% chance of Office/browser activity
    ],
    'analyst': [
        ('logon', 0.85),
        ('process_query', 0.5),
        ('connection_db', 0.4),
        ('process_user_apps', 0.3),
    ],
    'sysadmin': [
        ('logon', 0.9),
        ('process_code', 0.3),
        ('process_query', 0.3),
        ('connection_web', 0.3),
        ('process_system', 0.4),
        ('process_user_apps', 0.2),
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

# Zeek connection state distribution with matching history strings (Phase 5.1)
# Format: (conn_state, weight, history_string)
CONN_STATE_DISTRIBUTION = [
    ('SF', 85, 'ShADadfF'),      # Normal completion (SYN, SYN-ACK, data, FIN)
    ('S0', 5, 'S'),              # Connection attempt, no reply
    ('S1', 3, 'ShR'),            # SYN-ACK seen, no final ACK from originator
    ('REJ', 2, 'Sr'),            # Connection rejected (RST from responder)
    ('RSTO', 3, 'ShADaR'),       # Connection reset by originator after data
    ('RSTR', 1, 'ShADadR'),      # Connection reset by responder after data
    ('OTH', 1, 'Cc'),            # Midstream traffic (no SYN/SYN-ACK seen)
]

# Pre-extract for random.choices
_CONN_STATES = [s[0] for s in CONN_STATE_DISTRIBUTION]
_CONN_WEIGHTS = [s[1] for s in CONN_STATE_DISTRIBUTION]
_CONN_HISTORY = {s[0]: s[2] for s in CONN_STATE_DISTRIBUTION}

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

# Reverse DNS mapping: IP → hostname (for DNS query generation)
REVERSE_DNS: dict[str, str] = {
    # Google
    '172.217.14.206': 'www.google.com', '142.250.80.46': 'accounts.google.com',
    '142.250.185.206': 'drive.google.com', '142.250.191.46': 'calendar.google.com',
    # Cloudflare
    '104.16.132.229': 'www.cloudflare.com', '104.18.32.7': 'dash.cloudflare.com',
    '104.18.25.35': 'api.cloudflare.com', '104.21.67.152': 'blog.example.com',
    # Fastly
    '151.101.1.140': 'www.reddit.com', '151.101.65.140': 'i.redd.it',
    '151.101.129.140': 'old.reddit.com', '151.101.193.140': 'v.redd.it',
    # Akamai
    '23.45.67.89': 'cdn.example.com', '23.72.134.56': 'static.akamai.net',
    '23.196.25.38': 'download.windowsupdate.com', '23.205.100.42': 'media.akamai.net',
    # AWS
    '52.84.123.45': 'd1234.cloudfront.net', '54.230.67.89': 'd5678.cloudfront.net',
    '54.230.129.180': 'cdn.jsdelivr.net', '13.35.42.100': 'api.example.com',
    # Microsoft
    '13.107.42.14': 'www.office.com', '13.107.213.70': 'outlook.office365.com',
    '204.79.197.200': 'www.bing.com', '13.107.246.40': 'teams.microsoft.com',
    # Other
    '93.184.216.34': 'www.example.com', '31.13.65.36': 'www.facebook.com',
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


def _generate_random_external_ip(rng) -> str:
    """Generate a random plausible external IP from common cloud/CDN ranges."""
    prefix = rng.choice(_CDN_RANGES)
    return f"{prefix[0]}.{prefix[1]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _generate_random_hostname(rng, ip: str) -> str:
    """Generate a plausible hostname for a random CDN/cloud IP."""
    templates = [
        f"cdn-{rng.randint(1000, 9999)}.cloudfront.net",
        f"edge-{rng.randint(100, 999)}.akamai.net",
        f"server-{rng.randint(10, 99)}-{rng.randint(100, 999)}.compute.amazonaws.com",
        f"lb-{rng.randint(1, 50)}.{rng.choice(['us-east-1', 'eu-west-1', 'ap-south-1'])}.elb.amazonaws.com",
        f"{rng.randint(1, 255)}-{rng.randint(1, 255)}-{rng.randint(1, 255)}.bc.googleusercontent.com",
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
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
            network_visibility: Optional NetworkVisibilityEngine for sensor-based filtering
            sid_registry: Optional dict mapping usernames to Windows SIDs
        """
        self.state_manager = state_manager
        self.emitters = emitters
        self.event_record_counter = event_record_counter
        self._counter_lock = Lock()  # Thread-safe counter for EventRecordID
        self.sid_registry = sid_registry or {}

        # Network visibility (Phase 2.5): default to all-visible if not provided
        if network_visibility is None:
            from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
            network_visibility = NetworkVisibilityEngine(None, [])
        self.network_visibility = network_visibility

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: Optional[str] = None
    ) -> str:
        """Generate logon event and emit Windows 4624.

        Creates session in StateManager and emits Windows Event 4624 (successful logon).

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

        # Create session in StateManager
        logon_id = self.state_manager.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=logon_type,
            source_ip=source_ip
        )

        # Phase 2.10: OS-aware multi-format emission
        os_category = _get_os_category(system.os)

        # Emit to native OS log format
        if os_category == 'windows':
            # Emit Windows Event 4624 (An account was successfully logged on)
            event_data = {
                'EventID': 4624,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,  # Information
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,    # System process
                'ExecutionThreadID': _get_rng().randint(100, 500),
                # Logon variant fields
                'SubjectUserSid': self._get_sid('SYSTEM'),  # lsass reports logon events
                'TargetUserSid': self._get_sid(user.username),
                'TargetUserName': user.username,
                'TargetDomainName': 'CORP',  # Phase 1: Fixed domain
                'TargetLogonId': logon_id,
                'LogonType': logon_type,
                'WorkstationName': system.hostname,
                'IpAddress': source_ip,
                'IpPort': _get_rng().randint(49152, 65535) if logon_type == 3 else None,
                'LogonProcessName': 'User32' if logon_type == 2 else 'NtLmSsp',
                'AuthenticationPackageName': 'Negotiate',
            }
            self.emitters['windows_event_security'].emit_event(event_data)

        elif os_category == 'linux':
            # Emit syslog authentication message
            if 'syslog' in self.emitters:
                event_data = {
                    'timestamp': time,
                    'hostname': system.hostname,
                    'facility': 10,  # authpriv
                    'severity': 6,   # info
                    'app_name': 'sshd' if logon_type == 3 else 'login',
                    'pid': _get_rng().randint(1000, 9999),
                    'message': f'Accepted password for {user.username} from {source_ip} port {_get_rng().randint(49152, 65535)}'
                }
                self.emitters['syslog'].emit_event(event_data)

        # Emit eCAR if available (optional EDR/XDR layer)
        self._emit_ecar_logon(user, system, time, logon_id, logon_type, source_ip)

        # Phase 5.2: Emit 4672 (special privileges) for ~15% of logons (admin accounts)
        if os_category == 'windows' and _get_rng().random() < 0.15:
            priv_event = {
                'EventID': 4672,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 500),
                'SubjectUserSid': self._get_sid(user.username),
                'SubjectUserName': user.username,
                'SubjectDomainName': 'CORP',
                'SubjectLogonId': logon_id,
                'PrivilegeList': 'SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege',
            }
            self.emitters['windows_event_security'].emit_event(priv_event)

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
        """Generate a failed logon event (bad password).

        Does NOT create a session in StateManager. Emits:
        - Windows: Event 4625 (failed logon)
        - Linux: syslog "Failed password"
        - eCAR: USER_SESSION/LOGIN with failure_reason (if available)

        Args:
            user: User attempting to log on
            system: Target system
            time: Attempt timestamp
            logon_type: Logon type attempted
            source_ip: Source IP (defaults to system IP for interactive)
        """
        if source_ip is None:
            source_ip = system.ip if logon_type != 3 else "127.0.0.1"

        os_category = _get_os_category(system.os)

        if os_category == 'windows':
            event_data = {
                'EventID': 4625,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 500),
                'SubjectUserSid': self._get_sid('SYSTEM'),
                'TargetUserSid': self._get_sid(user.username),
                'TargetUserName': user.username,
                'TargetDomainName': 'CORP',
                'Status': '0xc000006d',
                'FailureReason': '%%2313',  # Unknown user name or bad password
                'SubStatus': '0xc0000064',  # User name does not exist / bad password
                'LogonType': logon_type,
                'IpAddress': source_ip,
                'IpPort': _get_rng().randint(49152, 65535) if logon_type == 3 else 0,
            }
            self.emitters['windows_event_security'].emit_event(event_data)

        elif os_category == 'linux':
            if 'syslog' in self.emitters:
                event_data = {
                    'timestamp': time,
                    'hostname': system.hostname,
                    'facility': 10,  # authpriv
                    'severity': 4,   # warning
                    'app_name': 'sshd' if logon_type == 3 else 'login',
                    'pid': _get_rng().randint(1000, 9999),
                    'message': f'Failed password for {user.username} from {source_ip} port {_get_rng().randint(49152, 65535)} ssh2',
                }
                self.emitters['syslog'].emit_event(event_data)

        # Emit eCAR failed login if available
        if 'ecar' in self.emitters:
            event_data = {
                'timestamp': time,
                'hostname': system.hostname,
                'object': 'USER_SESSION',
                'action': 'LOGIN',
                'principal': user.username,
                'src_ip': source_ip,
                'failure_reason': 'bad_password',
            }
            self.emitters['ecar'].emit_event(event_data)

        logger.debug(f"Generated failed logon: {user.username} on {system.hostname}")

    def generate_logoff(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        logon_type: int = 2,
    ) -> None:
        """Generate logoff event across OS-appropriate formats.

        Ends session in StateManager and emits:
        - Windows: Event 4634 (logoff)
        - Linux: syslog "session closed"
        - eCAR: USER_SESSION/LOGOUT (if available)

        Args:
            user: User logging off
            system: System being logged off from
            time: Logoff timestamp
            logon_id: LogonID from the logon event
            logon_type: Logon type for the session being ended
        """
        # End session in StateManager
        self.state_manager.end_session(logon_id)

        # Phase 5.1: OS-aware multi-format emission
        os_category = _get_os_category(system.os)

        if os_category == 'windows':
            # Emit Windows Event 4634 (An account was logged off)
            event_data = {
                'EventID': 4634,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 500),
                # Logoff variant fields
                'TargetUserSid': self._get_sid(user.username),
                'TargetUserName': user.username,
                'TargetDomainName': 'CORP',
                'TargetLogonId': logon_id,
                'LogonType': logon_type,
            }
            self.emitters['windows_event_security'].emit_event(event_data)

        elif os_category == 'linux':
            # Emit syslog session closed message
            if 'syslog' in self.emitters:
                event_data = {
                    'timestamp': time,
                    'hostname': system.hostname,
                    'facility': 10,  # authpriv
                    'severity': 6,   # info
                    'app_name': 'sshd' if logon_type == 3 else 'login',
                    'pid': _get_rng().randint(1000, 9999),
                    'message': f'session closed for user {user.username}',
                }
                self.emitters['syslog'].emit_event(event_data)

        # Emit eCAR USER_SESSION/LOGOUT if available
        if 'ecar' in self.emitters:
            event_data = {
                'timestamp': time,
                'hostname': system.hostname,
                'object': 'USER_SESSION',
                'action': 'LOGOUT',
                'principal': user.username,
            }
            self.emitters['ecar'].emit_event(event_data)

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
        """Generate process creation event and emit Windows 4688.

        Creates process in StateManager and emits Windows Event 4688.

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
        # Create process in StateManager
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=user.username,
            integrity_level='Medium'  # Phase 1: Fixed integrity level
        )

        # Phase 2.10: OS-aware multi-format emission
        os_category = _get_os_category(system.os)

        # Emit to native OS log format
        if os_category == 'windows':
            # Emit Windows Event 4688 (A new process has been created)
            event_data = {
                'EventID': 4688,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 500),
                # Process variant fields
                'SubjectUserSid': self._get_sid(user.username),
                'SubjectUserName': user.username,
                'SubjectDomainName': 'CORP',
                'SubjectLogonId': logon_id,
                'NewProcessId': f'0x{pid:x}',  # Hex format
                'NewProcessName': process_name,
                'TokenElevationType': '%%1936',  # Limited token
                'ProcessId': f'0x{parent_pid:x}',  # Parent PID in hex
                'CommandLine': command_line,
                'TargetUserName': user.username,
                'TargetDomainName': 'CORP',
                'TargetLogonId': logon_id,
            }
            self.emitters['windows_event_security'].emit_event(event_data)

        elif os_category == 'linux':
            # Linux process creation may not generate syslog (depends on auditd config)
            # For now, skip native log (eCAR would provide visibility if enabled)
            pass

        # Emit eCAR if available (optional EDR/XDR layer)
        self._emit_ecar_process(user, system, time, pid, parent_pid, process_name, command_line, logon_id)

        # Phase 5.2: Probabilistic eCAR object diversity
        rng = _get_rng()
        os_category = _get_os_category(system.os)
        if 'ecar' in self.emitters:
            # 40% chance: file event after process creation
            if rng.random() < 0.40:
                action = rng.choice(['CREATE', 'MODIFY', 'MODIFY', 'DELETE'])
                self._emit_ecar_file_event(system, time, pid, action, user.username)
            # 30% chance: module load (Windows only)
            if os_category == 'windows' and rng.random() < 0.30:
                self._emit_ecar_module_event(system, time, pid, user.username)
            # 20% chance: registry event (Windows system processes only)
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
        """Generate process termination event and emit Windows 4689.

        Ends process in StateManager and emits:
        - Windows: Event 4689 (process exited)
        - eCAR: PROCESS/TERMINATE (if available)

        Args:
            user: User who owned the process
            system: System where process ran
            time: Termination timestamp
            pid: PID of the terminated process
            process_name: Full path of the terminated process
            logon_id: LogonID of the owning session
        """
        # End process in StateManager
        self.state_manager.end_process(system.hostname, pid)

        os_category = _get_os_category(system.os)

        if os_category == 'windows':
            event_data = {
                'EventID': 4689,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 500),
                'SubjectUserSid': self._get_sid(user.username),
                'SubjectUserName': user.username,
                'SubjectDomainName': 'CORP',
                'SubjectLogonId': logon_id,
                'Status': '0x0',
                'ProcessId': f'0x{pid:x}',
                'ProcessName': process_name,
            }
            self.emitters['windows_event_security'].emit_event(event_data)

        # Emit eCAR PROCESS/TERMINATE if available
        if 'ecar' in self.emitters:
            event_data = {
                'timestamp': time,
                'hostname': system.hostname,
                'object': 'PROCESS',
                'action': 'TERMINATE',
                'pid': pid,
                'principal': user.username,
                'image_path': process_name,
            }
            self.emitters['ecar'].emit_event(event_data)

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
        resp_bytes: Optional[int] = None
    ) -> str:
        """Generate network connection and emit Zeek conn.log event.

        Opens connection in StateManager and emits Zeek connection record.

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

        Returns:
            Zeek UID (18-character string)
        """
        # Validate connection would be observable by network sensors
        is_invalid, reason = _is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            logger.warning(
                f"Skipping invalid network connection: {src_ip} -> {dst_ip}. "
                f"Reason: {reason}. Network sensors would not observe this traffic."
            )
            return ""  # Return empty UID to indicate skipped connection

        # Phase 2.5: Check network topology visibility
        if not self.network_visibility.is_connection_visible(src_ip, dst_ip):
            logger.debug(
                f"Skipping connection {src_ip} -> {dst_ip}: "
                f"not observable by any configured sensor"
            )
            return ""

        src_port = _get_rng().randint(49152, 65535)  # Ephemeral port

        # Create connection in StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto
        )

        # Generate Zeek UID
        uid = generate_zeek_uid('C')  # 'C' prefix for conn.log

        # Update connection bytes if provided
        if orig_bytes is not None and resp_bytes is not None:
            self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Phase 5.1: Probabilistic connection state selection
        rng = _get_rng()
        if duration is not None:
            # Caller specified duration → use weighted distribution (mostly SF)
            conn_state = rng.choices(_CONN_STATES, weights=_CONN_WEIGHTS, k=1)[0]
        else:
            # No duration → connection attempt with no completion
            conn_state = 'S0'

        history = _CONN_HISTORY[conn_state]

        # Adjust bytes/duration for consistency with connection state
        if conn_state in ('S0', 'REJ'):
            # Failed connections: no response data, no duration
            duration = None
            resp_bytes = 0
            if conn_state == 'REJ':
                orig_bytes = orig_bytes if orig_bytes else 0
        elif conn_state in ('RSTO', 'RSTR'):
            # Reset connections: may have partial data, shorter duration
            if duration is not None:
                duration = duration * rng.uniform(0.1, 0.5)
            if resp_bytes:
                resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))

        # Calculate packet counts (rough estimate: 1 packet per 1500 bytes)
        orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else None
        resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else None
        orig_ip_bytes = (orig_bytes + orig_pkts * 40) if orig_bytes and orig_pkts else None
        resp_ip_bytes = (resp_bytes + resp_pkts * 40) if resp_bytes and resp_pkts else None

        # Emit Zeek conn.log event
        event_data = {
            'ts': time,
            'uid': uid,
            'id.orig_h': src_ip,
            'id.orig_p': src_port,
            'id.resp_h': dst_ip,
            'id.resp_p': dst_port,
            'proto': proto,
            'service': service,
            'duration': duration,
            'orig_bytes': orig_bytes,
            'resp_bytes': resp_bytes,
            'conn_state': conn_state,
            'local_orig': True,  # Phase 1: Assume local originator
            'local_resp': False,  # Phase 1: Assume remote responder
            'missed_bytes': 0,
            'history': history,
            'orig_pkts': orig_pkts,
            'orig_ip_bytes': orig_ip_bytes,
            'resp_pkts': resp_pkts,
            'resp_ip_bytes': resp_ip_bytes,
            'ip_proto': 6 if proto == 'tcp' else 17 if proto == 'udp' else 1,  # TCP=6, UDP=17, ICMP=1
        }

        # Phase 2.5: Emit to sensor-appropriate formats
        visible_formats = self.network_visibility.get_log_formats_for_connection(src_ip, dst_ip)
        for format_name in visible_formats:
            if format_name in self.emitters:
                self.emitters[format_name].emit_event(event_data)
        logger.debug(f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid}, formats: {visible_formats})")

        # Phase 5.2: Emit eCAR FLOW/CONNECT for eCAR-equipped hosts
        # Use src_ip to find the hostname for this connection
        self._emit_ecar_flow_event(src_ip, dst_ip, dst_port, time, src_ip)

        return uid

    def generate_bash_command(
        self,
        user: User,
        system: System,
        time: datetime,
        activity_type: str = 'default'
    ) -> None:
        """Generate bash command history entry (Linux only).

        Phase 2.10: Linux command-line visibility.

        Args:
            user: User executing command
            system: Linux system
            time: Command execution time
            activity_type: Type of activity (process_code, process_build, etc.)
        """
        os_category = _get_os_category(system.os)
        if os_category != 'linux':
            return  # Bash history only for Linux

        if 'bash_history' not in self.emitters:
            return  # bash_history not enabled

        # Select command based on activity type
        commands = {
            'process_code': ['vim script.py', 'nano config.conf', 'code .'],
            'process_build': ['make', 'gcc -o output source.c', 'npm run build'],
            'connection_web': ['curl https://example.com', 'wget https://github.com/repo/file.tar.gz'],
            'default': ['ls -la', 'ps aux', 'top', 'df -h']
        }

        command_list = commands.get(activity_type, commands['default'])
        command = _get_rng().choice(command_list)

        event_data = {
            'timestamp': time,
            'username': user.username,
            'hostname': system.hostname,
            'command': command,
            'exit_code': 0  # Success
        }

        self.emitters['bash_history'].emit_event(event_data)
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
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=username,
            integrity_level='System',
        )

        os_category = _get_os_category(system.os)

        if os_category == 'windows':
            sid = self.sid_registry.get(username, 'S-1-5-18') if self.sid_registry else 'S-1-5-18'
            event_data = {
                'EventID': 4688,
                'TimeCreated': time,
                'Computer': system.hostname,
                'Channel': 'Security',
                'Level': 0,
                'EventRecordID': self._get_next_event_record_id(),
                'ExecutionProcessID': 4,
                'ExecutionThreadID': _get_rng().randint(100, 999),
                'SubjectUserSid': sid,
                'SubjectUserName': username,
                'SubjectDomainName': 'NT AUTHORITY',
                'SubjectLogonId': '0x3e7',
                'NewProcessId': hex(pid),
                'NewProcessName': process_name,
                'TokenElevationType': '%%1936',
                'ProcessId': hex(parent_pid),
                'CommandLine': command_line,
                'ParentProcessName': '',
                'MandatoryLabel': 'S-1-16-16384',
            }
            if 'windows_event_security' in self.emitters:
                self.emitters['windows_event_security'].emit_event(event_data)

        elif os_category == 'linux':
            if 'syslog' in self.emitters:
                self.emitters['syslog'].emit_event({
                    'timestamp': time,
                    'hostname': system.hostname,
                    'app_name': process_name.split('/')[-1],
                    'facility': 1,
                    'severity': 6,
                    'message': f'{process_name.split("/")[-1]}[{pid}]: started: {command_line}',
                })

        # eCAR emission (direct, since _emit_ecar_process expects a User object)
        if 'ecar' in self.emitters:
            self.emitters['ecar'].emit_event({
                'timestamp': time,
                'hostname': system.hostname,
                'object': 'PROCESS',
                'action': 'CREATE',
                'pid': pid,
                'ppid': parent_pid,
                'principal': username,
                'image_path': process_name,
                'command_line': command_line,
            })

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
        from evidenceforge.utils.ids import generate_zeek_uid

        rng = _get_rng()

        # Look up hostname for this IP, or generate one
        hostname = REVERSE_DNS.get(dst_ip)
        if not hostname:
            hostname = _generate_random_hostname(rng, dst_ip)

        # Determine DNS server IP from network visibility or use default
        dns_server_ip = getattr(self, '_dns_server_ip', '10.0.0.1')

        # Shared UID for the DNS conn.log and dns.log records
        dns_uid = generate_zeek_uid()
        src_port = rng.randint(49152, 65535)

        # Emit Zeek conn.log UDP/53 record
        dns_time = time - timedelta(milliseconds=rng.randint(10, 50))
        self.generate_connection(
            src_ip=src_ip,
            dst_ip=dns_server_ip,
            time=dns_time,
            dst_port=53,
            proto='udp',
            service='dns',
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(40, 100),
            resp_bytes=rng.randint(80, 400),
        )

        # Emit Zeek dns.log record
        if 'zeek_dns' in self.emitters:
            qtype_roll = rng.random()
            if qtype_roll < 0.60:
                qtype, qtype_name = 1, 'A'
            elif qtype_roll < 0.85:
                qtype, qtype_name = 28, 'AAAA'
            elif qtype_roll < 0.95:
                qtype, qtype_name = 5, 'CNAME'
            else:
                qtype, qtype_name = 12, 'PTR'

            self.emitters['zeek_dns'].emit_event({
                'ts': dns_time,
                'uid': dns_uid,
                'id.orig_h': src_ip,
                'id.orig_p': src_port,
                'id.resp_h': dns_server_ip,
                'id.resp_p': 53,
                'proto': 'udp',
                'trans_id': rng.randint(1, 65535),
                'query': hostname,
                'qclass': 1,
                'qclass_name': 'C_INTERNET',
                'qtype': qtype,
                'qtype_name': qtype_name,
                'rcode': 0,
                'rcode_name': 'NOERROR',
                'AA': False,
                'TC': False,
                'RD': True,
                'RA': True,
                'answers': dst_ip,
                'TTLs': str(rng.choice([60, 300, 3600, 86400])),
                'rejected': False,
            })

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
            self.generate_logon(user, system, time)

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
                # Use Windows process templates
                process_name, command_line = _get_rng().choice(PROCESS_TEMPLATES[activity_type])
                # Phase 5.1: Substitute username placeholder in paths
                process_name = process_name.replace('{username}', user.username)
                command_line = command_line.replace('{username}', user.username)
                self.generate_process(user, system, time, logon_id, process_name, command_line)

            elif os_category == 'linux' and activity_type in PROCESS_TEMPLATES_LINUX:
                # Use Linux process templates
                process_name, command_line = _get_rng().choice(PROCESS_TEMPLATES_LINUX[activity_type])
                self.generate_process(user, system, time, logon_id, process_name, command_line)

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
                dst_port = 587
            elif activity_type == 'connection_git':
                service = 'https'
                dst_port = 443
            elif activity_type == 'connection_db':
                service = 'mysql'
                dst_port = 3306
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

    def _get_next_event_record_id(self) -> int:
        """Get next EventRecordID for Windows events (thread-safe).

        Returns:
            Next sequential EventRecordID
        """
        with self._counter_lock:
            self.event_record_counter += 1
            return self.event_record_counter

    # Well-known Windows SIDs (always available regardless of registry)
    _WELL_KNOWN_SIDS = {
        'SYSTEM': 'S-1-5-18',
        'LOCAL SERVICE': 'S-1-5-19',
        'NETWORK SERVICE': 'S-1-5-20',
    }

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

    def _emit_ecar_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        logon_type: int,
        source_ip: str
    ) -> None:
        """Emit eCAR USER_SESSION/LOGIN event.

        Phase 2.10: eCAR provides unified EDR/XDR visibility across all OSes.

        Args:
            user: User logging on
            system: Target system
            time: Login timestamp
            logon_id: Session logon ID
            logon_type: Logon type (2=interactive, 3=network)
            source_ip: Source IP address
        """
        if 'ecar' not in self.emitters:
            return  # eCAR not enabled

        event_data = {
            'timestamp': time,
            'hostname': system.hostname,
            'object': 'USER_SESSION',
            'action': 'LOGIN',
            'principal': user.username,
            'src_ip': source_ip,
        }

        self.emitters['ecar'].emit_event(event_data)
        logger.debug(f"Generated eCAR logon: {user.username} on {system.hostname}")

    def _emit_ecar_process(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        parent_pid: int,
        process_name: str,
        command_line: str,
        logon_id: str
    ) -> None:
        """Emit eCAR PROCESS/CREATE event.

        Phase 2.10: eCAR provides unified EDR/XDR visibility across all OSes.

        Args:
            user: User creating the process
            system: System where process created
            time: Process creation timestamp
            pid: Process ID
            parent_pid: Parent process ID
            process_name: Executable path
            command_line: Command line
            logon_id: Session logon ID
        """
        if 'ecar' not in self.emitters:
            return  # eCAR not enabled

        event_data = {
            'timestamp': time,
            'hostname': system.hostname,
            'object': 'PROCESS',
            'action': 'CREATE',
            'pid': pid,
            'ppid': parent_pid,
            'principal': user.username,
            'image_path': process_name,
            'command_line': command_line,
        }

        self.emitters['ecar'].emit_event(event_data)
        logger.debug(f"Generated eCAR process: {process_name} (PID: {pid}) on {system.hostname}")

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
        """Emit eCAR FILE event (CREATE, MODIFY, or DELETE)."""
        if 'ecar' not in self.emitters:
            return
        rng = _get_rng()
        os_cat = _get_os_category(system.os)
        pool = self._ECAR_FILE_PATHS_WIN if os_cat == 'windows' else self._ECAR_FILE_PATHS_LINUX
        path = rng.choice(pool).replace('{user}', username).replace('{rand}', f'{rng.randint(10000, 99999)}')
        self.emitters['ecar'].emit_event({
            'timestamp': time,
            'hostname': system.hostname,
            'object': 'FILE',
            'action': action,
            'pid': pid,
            'principal': username,
            'file_path': path,
        })

    def _emit_ecar_registry_event(
        self, system: System, time: datetime, pid: int, username: str,
    ) -> None:
        """Emit eCAR REGISTRY/MODIFY event (Windows only)."""
        if 'ecar' not in self.emitters:
            return
        key, value = _get_rng().choice(self._ECAR_REGISTRY_KEYS)
        self.emitters['ecar'].emit_event({
            'timestamp': time,
            'hostname': system.hostname,
            'object': 'REGISTRY',
            'action': 'MODIFY',
            'pid': pid,
            'principal': username,
            'registry_key': key,
            'registry_value': value,
        })

    def _emit_ecar_flow_event(
        self, src_ip: str, dst_ip: str, dst_port: int,
        time: datetime, hostname: str, pid: int = -1,
    ) -> None:
        """Emit eCAR FLOW/CONNECT event."""
        if 'ecar' not in self.emitters:
            return
        self.emitters['ecar'].emit_event({
            'timestamp': time,
            'hostname': hostname,
            'object': 'FLOW',
            'action': 'CONNECT',
            'pid': pid,
            'src_ip': src_ip,
            'src_port': _get_rng().randint(49152, 65535),
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': 'tcp',
        })

    def _emit_ecar_module_event(
        self, system: System, time: datetime, pid: int, username: str,
    ) -> None:
        """Emit eCAR MODULE/LOAD event (DLL load, Windows only)."""
        if 'ecar' not in self.emitters:
            return
        dll_path = _get_rng().choice(self._ECAR_DLL_POOL)
        self.emitters['ecar'].emit_event({
            'timestamp': time,
            'hostname': system.hostname,
            'object': 'MODULE',
            'action': 'LOAD',
            'pid': pid,
            'principal': username,
            'file_path': dll_path,
        })
