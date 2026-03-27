"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import logging
import random
import uuid
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Optional

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    EdrContext,
    FileContext,
    HostContext,
    HttpContext,
    IdsContext,
    KerberosContext,
    RegistryContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed

from .helpers import _get_os_category, _get_rng, _parameterize_command
from .network import (
    _AD_SRV_QUERIES,
    _IPV6_MAP,
    _PROVIDER_IP_GROUPS,
    _SRV_PORT_MAP,
    EXTERNAL_IPS,
    REVERSE_DNS,
    _generate_internal_hostname,
    _generate_random_external_ip,
    _generate_random_hostname,
    _generate_rdns_name,
    _get_http_status,
    _ipv4_to_fake_ipv6,
    _is_invalid_network_connection,
    _is_private_ip,
)

logger = logging.getLogger(__name__)


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

# Process names and command lines for baseline activities (Windows)
PROCESS_TEMPLATES = {
    "process_code": [
        ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe --no-sandbox"),
        ("C:\\Program Files (x86)\\Notepad++\\notepad++.exe", "notepad++ document.txt"),
        ("C:\\Program Files\\JetBrains\\IntelliJ IDEA\\bin\\idea64.exe", "idea64.exe"),
        ("C:\\Program Files\\Sublime Text\\sublime_text.exe", "sublime_text.exe project.py"),
    ],
    "process_build": [
        ("C:\\Windows\\System32\\msbuild.exe", "msbuild.exe solution.sln /t:Build"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c npm run build"),
        ("C:\\Program Files\\dotnet\\dotnet.exe", "dotnet.exe build -c Release"),
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
        (
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe --type=renderer --enable-features=NetworkService",
        ),
        ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe -contentproc -childID 3"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE /n"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE"),
        (
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "msedge.exe --type=renderer",
        ),
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "Teams.exe --type=utility",
        ),
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "OneDrive.exe /background",
        ),
        ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Acrobat.exe"),
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
        ("/usr/bin/vim", "vim /home/user/script.py"),
        ("/usr/bin/nano", "nano /etc/config.conf"),
        ("/usr/bin/code", "code --no-sandbox /home/user/project"),
        ("/usr/bin/emacs", "emacs -nw /home/user/main.go"),
    ],
    "process_build": [
        ("/usr/bin/make", "make -j4"),
        ("/usr/bin/gcc", "gcc -o output source.c"),
        ("/usr/bin/npm", "npm run build"),
        ("/usr/bin/cargo", "cargo build --release"),
        ("/usr/bin/python3", "python3 setup.py install"),
    ],
    "process_query": [
        ("/usr/bin/mysql", "mysql -u root -p database"),
        ("/usr/bin/psql", "psql -U postgres -d mydb"),
        ("/usr/bin/redis-cli", "redis-cli GET session:abc123"),
    ],
    "process_user_apps": [
        ("/usr/bin/firefox", "firefox --new-tab"),
        ("/usr/bin/thunderbird", "thunderbird"),
        ("/usr/bin/git", "git pull origin main"),
        ("/usr/bin/docker", "docker ps"),
        ("/usr/bin/python3", "python3 -m pytest tests/"),
        ("/usr/bin/ssh", "ssh user@remote-host"),
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
# Phase 6.3: Expanded from 7 to 20+ patterns for realism
TCP_CONN_STATE_DISTRIBUTION = [
    # Normal completions (SF) — various data exchange patterns
    ("SF", 28, "ShADadfF"),  # Standard: SYN→SYN-ACK→data→FIN
    ("SF", 14, "ShADaDadfF"),  # Multiple data exchanges before FIN
    ("SF", 8, "ShADadTtFf"),  # Normal with retransmissions (T=orig retx, t=resp retx)
    ("SF", 7, "ShADadfFa"),  # FIN-ACK with trailing ACK
    ("SF", 6, "ShADaDaDadfF"),  # Bulk transfer (many data rounds)
    ("SF", 5, "ShADadFf"),  # Originator FIN first (client closes)
    ("SF", 5, "ShADaDadfFa"),  # Multi-exchange with trailing ACK
    ("SF", 4, "ShADadTFf"),  # Retransmit then FIN
    ("SF", 3, "ShADaDadFf"),  # Multi data then client closes
    ("SF", 2, "ShADaDaTtdfF"),  # Multi data with retransmissions
    # Connection attempts (S0)
    ("S0", 3, "S"),  # Single SYN, no reply
    ("S0", 2, "S"),  # SYN retransmit (Zeek deduplicates to single 'S')
    # Partial handshakes (S1)
    ("S1", 2, "ShR"),  # SYN-ACK seen, RST
    ("S1", 1, "Sh"),  # SYN-ACK seen, no further data
    # Rejected connections (REJ)
    ("REJ", 2, "Sr"),  # RST from responder immediately
    ("REJ", 1, "Srr"),  # Multiple RSTs from responder
    # Reset by originator (RSTO)
    ("RSTO", 2, "ShADaR"),  # Data exchange then originator RST
    ("RSTO", 1, "ShADadTR"),  # Data + retransmit then RST
    ("RSTO", 1, "ShAR"),  # Quick RST after handshake
    # Reset by responder (RSTR)
    ("RSTR", 1, "ShADadR"),  # Data exchange then responder RST
    ("RSTR", 1, "ShAdR"),  # Partial data then responder RST
    # Midstream (OTH) — rare in enterprise (<0.3%), only from partial captures
    ("OTH", 1, "Cc"),  # Midstream traffic (no SYN/SYN-ACK seen)
]

# Zeek UDP connection state distribution
# UDP has no TCP handshake — only D/d datagram flags
UDP_CONN_STATE_DISTRIBUTION = [
    ("SF", 65, "Dd"),  # Normal bidirectional exchange (query + response)
    ("SF", 8, "DdDd"),  # Multi-packet exchange
    ("SF", 4, "DdDdDd"),  # Extended multi-packet exchange
    ("SF", 3, "DdA"),  # Additional acknowledgment packet
    ("S0", 10, "D"),  # Originator only, no response (timeout)
    ("S0", 3, "DD"),  # Retransmitted datagram, no response
    ("OTH", 4, "Dd"),  # Midstream UDP exchange
    ("OTH", 3, "DdDdA"),  # Midstream multi-packet with ACK
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

        # IP→System lookup for HostContext resolution on connection events
        self._ip_to_system: dict[str, Any] = {}

        # Process tree tracking: recent user processes per (hostname, username)
        # Used by _select_parent_pid() for realistic parent-child relationships
        self._user_process_history: dict[tuple[str, str], list[tuple[int, str]]] = {}

        # Network visibility stored on dispatcher; keep local ref for fast-path check
        self._network_visibility = network_visibility

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
        )

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

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: str | None = None,
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
            source_ip=source_ip,
        )

        # Select auth package (semantic data, not format-specific)
        auth_pkg = self._select_auth_package(logon_type)

        # Phase 2: Build SecurityEvent with all contexts
        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            host=self._build_host_context(system),
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

        # Attach SyslogContext for Linux hosts (sshd logon message)
        if event.host and event.host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            sshd_pid = 1000 + (hash(logon_id) % 59000)
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=(
                    f"Accepted password for {user.username} from {source_ip} "
                    f"port {_get_rng().randint(49152, 65535)} ssh2"
                ),
            )

        # Phase 2.5: Emit DC-side Kerberos events for domain logons
        # When a user authenticates via Kerberos to a Windows domain system,
        # the DC sees a TGT request (4768) then a service ticket request (4769)
        # before the target system logs the 4624.
        self._emit_dc_kerberos_for_logon(
            user=user,
            system=system,
            time=time,
            auth_package=auth_pkg.get("AuthenticationPackageName", "Negotiate"),
            source_ip=source_ip,
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
                    # Find a valid parent: userinit, winlogon, or any seeded system PID
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
        service_name = f"host/{system.hostname}"
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
                host=self._build_dc_host_context(dc_hostname),
                auth=AuthContext(
                    username=user.username,
                    user_sid=self._get_sid(user.username),
                    logon_id="0x0",  # DC Kerberos auth doesn't have a target logon ID
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
            host=self._build_host_context(system),
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
        if event.host and event.host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            event.syslog = SyslogContext(
                app_name="sshd",
                pid=_get_rng().randint(5000, 60000),
                facility=10,
                severity=4,
                message=(
                    f"Failed password for {effective_username} from {source_ip} "
                    f"port {_get_rng().randint(49152, 65535)} ssh2"
                ),
            )

        self.dispatcher.dispatch(event)

        # Domain controller side: 4625 + 4776 for domain account authentication
        if dc_system and dc_system.hostname != system.hostname:
            dc_event = SecurityEvent(
                timestamp=time,
                event_type="failed_logon",
                host=self._build_dc_host_context(dc_system.hostname),
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
        # Terminate session-specific explorer.exe before ending session
        session = self.state_manager.get_session(logon_id)
        if session and session.explorer_pid is not None:
            self.state_manager.end_process(session.system, session.explorer_pid)

        # Build SecurityEvent (StateManager.apply() handles end_session)
        session_obj_id = self.state_manager.get_session_object_id(logon_id)
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
            edr=EdrContext(object_id=session_obj_id),
        )

        # Attach SyslogContext for Linux hosts (sshd session closed)
        if event.host and event.host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            sshd_pid = 1000 + (hash(logon_id) % 59000)
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=f"pam_unix(sshd:session): session closed for user {user.username}",
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

        # Phase 1: Allocate IDs from StateManager
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=user.username,
            integrity_level="Medium",
        )

        # Phase 2: Build SecurityEvent
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        parent_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
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
                integrity_level="Medium",
                logon_id=logon_id,
                parent_image=self._lookup_process_name(system.hostname, parent_pid),
                token_elevation="%%1938",
                mandatory_label="S-1-16-8192",
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
        )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        # Guaranteed FILE/CREATE for the process image when requested (storyline processes)
        if ensure_file_event:
            self.dispatcher.dispatch(
                SecurityEvent(
                    timestamp=time,
                    event_type="file_create",
                    host=self._build_host_context(system),
                    auth=AuthContext(username=user.username),
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
            pool = (
                self._EDR_FILE_PATHS_WIN if os_category == "windows" else self._EDR_FILE_PATHS_LINUX
            )
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
                    host=host_ctx,
                    auth=auth_ctx,
                    file=FileContext(path=path, action=action.lower(), pid=pid),
                    edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                )
            )
        if os_category == "windows" and rng.random() < 0.30:
            dll_path = rng.choice(self._EDR_DLL_POOL)
            self.dispatcher.dispatch(
                SecurityEvent(
                    timestamp=time,
                    event_type="module_load",
                    host=host_ctx,
                    auth=auth_ctx,
                    file=FileContext(path=dll_path, action="load", pid=pid),
                    edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                )
            )
        if os_category == "windows" and "system32" in process_name.lower() and rng.random() < 0.20:
            key, value = rng.choice(self._EDR_REGISTRY_KEYS)
            self.dispatcher.dispatch(
                SecurityEvent(
                    timestamp=time,
                    event_type="registry_modify",
                    host=host_ctx,
                    auth=auth_ctx,
                    registry=RegistryContext(key=key, value=value, action="modify", pid=pid),
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

        # Emit DNS lookup before connection if requested (ensures DNS evidence exists)
        if emit_dns and proto == "tcp" and dst_port not in (53,):
            self._emit_dns_lookup(src_ip, dst_ip, time)

        # Same-host connections are valid for host-based logs (eCAR FLOW)
        # but invisible to network sensors (Zeek/Snort)
        local_only = src_ip == dst_ip

        # Validate connection is not fundamentally invalid (localhost, link-local, multicast)
        is_invalid, reason = _is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            logger.warning(
                f"Skipping invalid network connection: {src_ip} -> {dst_ip}. Reason: {reason}."
            )
            return ""

        # Phase 2.5: Check network topology visibility (skip for local-only)
        if not local_only:
            visibility = self._network_visibility or (
                self.dispatcher.visibility_engine if self.dispatcher else None
            )
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
            src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, protocol=proto
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        if orig_bytes is not None and resp_bytes is not None:
            self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Protocol-aware connection state selection
        rng = _get_rng()

        # If caller provides explicit conn_state (e.g., UFW BLOCK → REJ), skip probabilistic selection
        if conn_state is not None:
            history = {"REJ": "Sr", "S0": "S", "SF": "ShADadfF", "OTH": "Cc"}.get(
                conn_state, "ShADadfF"
            )
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                orig_bytes = rng.choice([0, 40, 44, 48])
        elif proto == "icmp":
            conn_state = "OTH"
            history = "-"
            src_port = 0  # ICMP has no ports; Zeek emits 0
            dst_port = 0
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
                # S0 = SYN only, no handshake completed — orig_bytes is just the SYN packet
                if conn_state == "S0":
                    orig_bytes = rng.choice([0, 40, 44, 48, 60])
                elif conn_state == "REJ":
                    # REJ = SYN then RST; orig_bytes is just the SYN packet(s)
                    orig_bytes = rng.choice([0, 40, 44, 48])
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
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0

        overhead = 28 if proto == "udp" else _get_rng().randint(52, 72)
        orig_ip_bytes = (orig_bytes + orig_pkts * overhead) if orig_bytes and orig_pkts else None
        resp_ip_bytes = (resp_bytes + resp_pkts * overhead) if resp_bytes and resp_pkts else None

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
        # Resolve source system for HostContext (needed by eCAR emitter for hostname/routing)
        host_ctx = None
        if source_system:
            host_ctx = self._build_host_context(source_system)
        elif hasattr(self, "_ip_to_system") and src_ip in self._ip_to_system:
            host_ctx = self._build_host_context(self._ip_to_system[src_ip])

        # Resolve eCAR actor_id from initiating process (if pid is known)
        conn_actor_id = ""
        if pid > 0 and source_system:
            conn_actor_id = self.state_manager.get_process_object_id(source_system.hostname, pid)

        event = SecurityEvent(
            timestamp=time,
            event_type="connection",
            host=host_ctx,
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

        # DNS context for Zeek dns.log fan-out
        if dns is not None:
            event.dns = dns

        # Proxy context: attach if source system routes through a proxy for HTTP/HTTPS
        if not local_only and service in ("ssl", "http") and dst_port in (80, 443):
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
                hostname = REVERSE_DNS.get(dst_ip)
                if not hostname:
                    hostname = _generate_random_hostname(_get_rng(), dst_ip)
                schema = "https" if dst_port == 443 else "http"
                url = f"{schema}://{hostname}/"
                # Pick a random user from the scenario (if available)
                user_agent = _get_rng().choice(
                    [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                    ]
                )
                cache_roll = _get_rng().random()
                if cache_roll < 0.30:
                    cache_result = "HIT"
                elif cache_roll < 0.95:
                    cache_result = "MISS"
                else:
                    cache_result = "DENIED"
                event.proxy = ProxyContext(
                    client_ip=src_ip,
                    method="GET",
                    url=url,
                    host=hostname,
                    status_code=200 if cache_result != "DENIED" else 403,
                    sc_bytes=resp_bytes or 0,
                    cs_bytes=orig_bytes or 0,
                    time_taken=int((duration or 0) * 1000),
                    user_agent=user_agent,
                    content_type="text/html",
                    cache_result=cache_result,
                    proxy_fqdn=proxy_fqdn,
                )

        # Zeek protocol-layer contexts: populate SSL/HTTP/files for fan-out
        # Skip for local-only events (no network sensor will see them)
        rng = _get_rng()
        if not local_only and service == "ssl" and proto == "tcp" and conn_state == "SF":
            from evidenceforge.events.contexts import SslContext

            server_name = REVERSE_DNS.get(dst_ip)
            if not server_name:
                # Generate a plausible hostname for IPs not in REVERSE_DNS
                server_name = _generate_random_hostname(rng, dst_ip)
            _TLS12_CIPHERS = [
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]
            _TLS13_CIPHERS = [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ]
            tls_version = rng.choice(["TLSv12", "TLSv12", "TLSv12", "TLSv13"])
            event.ssl = SslContext(
                version=tls_version,
                cipher=rng.choice(_TLS13_CIPHERS if tls_version == "TLSv13" else _TLS12_CIPHERS),
                server_name=server_name,
                resumed=rng.random() < 0.6,
                established=True,
                ssl_history="CsiI" if rng.random() < 0.7 else "CsijI",
            )

            # X.509 certificate for SSL connections (fan-out to x509.log)
            import hashlib

            from evidenceforge.events.contexts import X509Context

            cert_hash = hashlib.sha256(f"cert_{server_name}".encode()).hexdigest()
            is_ecdsa = rng.random() < 0.4
            _ISSUERS = [
                "CN=R3, O=Let's Encrypt, C=US",
                "CN=GTS CA 1C3, O=Google Trust Services LLC, C=US",
                "CN=Amazon RSA 2048 M01, O=Amazon, C=US",
                "CN=E1, O=Let's Encrypt, C=US",
                "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
            ]
            now_epoch = event.timestamp.timestamp()
            event.x509 = X509Context(
                fingerprint=cert_hash,
                certificate_version=3,
                certificate_serial=f"{rng.randint(0x1000000000, 0xFFFFFFFFFF):X}",
                certificate_subject=f"CN={server_name}",
                certificate_issuer=rng.choice(_ISSUERS),
                certificate_not_valid_before=now_epoch - rng.randint(86400, 86400 * 365),
                certificate_not_valid_after=now_epoch + rng.randint(86400 * 30, 86400 * 365),
                certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
                certificate_sig_alg="ecdsa-with-SHA256" if is_ecdsa else "sha256WithRSAEncryption",
                certificate_key_type="ecdsa" if is_ecdsa else "rsa",
                certificate_key_length=256 if is_ecdsa else rng.choice([2048, 4096]),
                certificate_exponent="65537" if not is_ecdsa else "",
                san_dns=[server_name, f"*.{'.'.join(server_name.split('.')[1:])}"]
                if "." in server_name
                else [server_name],
                basic_constraints_ca=False,
                host_cert=True,
                client_cert=False,
            )

            # OCSP response (~30% of SSL connections)
            if rng.random() < 0.30:
                from evidenceforge.events.contexts import OcspContext
                from evidenceforge.utils.ids import generate_zeek_uid as _gen_uid

                event.ocsp = OcspContext(
                    id=_gen_uid("F"),
                    hash_algorithm="sha256",
                    issuer_name_hash=hashlib.sha256(
                        event.x509.certificate_issuer.encode()
                    ).hexdigest()[:40],
                    issuer_key_hash=hashlib.sha256(
                        f"key_{event.x509.certificate_issuer}".encode()
                    ).hexdigest()[:40],
                    serial_number=event.x509.certificate_serial,
                    cert_status="good",
                    this_update=now_epoch - rng.randint(0, 86400),
                    next_update=now_epoch + rng.randint(86400, 86400 * 7),
                )

        elif (
            not local_only
            and service == "http"
            and proto == "tcp"
            and conn_state == "SF"
            and event.http is None  # Skip auto-generation if caller provided HttpContext
        ):
            from evidenceforge.events.contexts import HttpContext

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
            host = REVERSE_DNS.get(dst_ip, dst_ip)
            if dst_port not in (80, 443):
                host = f"{host}:{dst_port}"
            _URI_MIME_MAP = {
                "/": "text/html",
                "/index.html": "text/html",
                "/api/v1/status": "application/json",
                "/favicon.ico": "image/x-icon",
                "/robots.txt": "text/plain",
                "/assets/main.css": "text/css",
                "/assets/app.js": "application/javascript",
                "/images/logo.png": "image/png",
            }
            uri = rng.choice(list(_URI_MIME_MAP.keys()))
            mime_type = _URI_MIME_MAP[uri]
            status_code, status_msg = _get_http_status(dst_ip, uri)
            resp_body_len = resp_bytes or rng.randint(200, 50000)
            if status_code in (301, 302):
                resp_body_len = rng.randint(100, 300)
            elif status_code == 304:
                resp_body_len = 0
            event.http = HttpContext(
                method="GET",
                host=host,
                uri=uri,
                version="1.1",
                user_agent=ua,
                request_body_len=0,
                response_body_len=resp_body_len,
                status_code=status_code,
                status_msg=status_msg,
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

        # NTP context for Zeek ntp.log fan-out
        if not local_only and service == "ntp" and proto == "udp":
            from evidenceforge.events.contexts import NtpContext

            ntp_rng = _get_rng()
            event.ntp = NtpContext(
                version=ntp_rng.choice([3, 4]),
                mode=3,  # client
                stratum=ntp_rng.randint(1, 4),
                poll=float(ntp_rng.choice([64, 128, 256, 512, 1024])),
                precision=ntp_rng.uniform(-25.0, -18.0),
                root_delay=ntp_rng.uniform(0.0, 0.1),
                root_disp=ntp_rng.uniform(0.0, 0.05),
                ref_id=ntp_rng.choice(["GPS", "PPS", "GOES", ".GPS.", ".PPS."]),
            )

        # Zeek weird.log: probabilistic network anomalies (~3% of connections)
        if not local_only and rng.random() < 0.03:
            from evidenceforge.events.contexts import WeirdContext

            _WEIRD_NAMES = [
                "window_recision",
                "possible_split_routing",
                "above_hole_data_without_any_acks",
                "data_before_established",
                "connection_originator_SYN_ack",
                "truncated_header",
                "inappropriate_FIN",
                "bad_TCP_checksum",
            ]
            event.weird = WeirdContext(
                name=rng.choice(_WEIRD_NAMES),
                source="TCP" if proto == "tcp" else "UDP",
            )

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
        src_port = rng.randint(49152, 65535)
        duration = rng.uniform(30.0, 3600.0)
        orig_bytes = rng.randint(2000, 50000)
        resp_bytes = rng.randint(5000, 200000)

        # Allocate connection in StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=source_ip,
            src_port=src_port,
            dst_ip=target_system.ip,
            dst_port=22,
            protocol="tcp",
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Emit DNS for SSH target
        self._emit_dns_lookup(source_ip, target_system.ip, time)

        # Build compound SSH session event
        event = SecurityEvent(
            timestamp=time,
            event_type="ssh_session",
            host=self._build_host_context(target_system),
            auth=AuthContext(
                username=user.username,
                source_ip=source_ip,
                source_port=src_port,
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
        )

        # Attach SyslogContext for Linux hosts: 3 syslog entries for SSH session
        if event.host and event.host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            sshd_pid = 1000 + (hash(f"{user.username}{time}") % 59000)
            session_id = rng.randint(100, 99999)

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
        if event.host and event.host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            # pam_unix session opened (syslog-only, no eCAR/Zeek correlation)
            pam_event = SecurityEvent(
                timestamp=time + timedelta(microseconds=rng.randint(1000, 50000)),
                event_type="syslog",
                host=event.host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"pam_unix(sshd:session): session opened for user "
                        f"{user.username} by (uid=0)"
                    ),
                ),
            )
            self.dispatcher.dispatch(pam_event)

            # systemd-logind new session (syslog-only)
            logind_event = SecurityEvent(
                timestamp=time + timedelta(microseconds=rng.randint(50000, 80000)),
                event_type="syslog",
                host=event.host,
                syslog=SyslogContext(
                    app_name="systemd-logind",
                    pid=1000 + (hash("logind") % 59000),
                    facility=10,
                    severity=6,
                    message=f"New session {session_id} of user {user.username}.",
                ),
            )
            self.dispatcher.dispatch(logind_event)

        logger.debug(
            f"Generated SSH session: {user.username} → {target_system.hostname} (UID: {uid})"
        )
        return uid

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

        # If the argument looks like a direct command (contains / or spaces), use it directly
        if "/" in activity_type_or_command or " " in activity_type_or_command:
            command = activity_type_or_command
        else:
            # Select command based on activity type
            commands = {
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

            command_list = commands.get(activity_type_or_command, commands["default"])
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
            host=self._build_host_context(system),
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
                token_elevation="%%1936",
                mandatory_label="S-1-16-16384",
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
        )

        # Attach SyslogContext for Linux hosts
        if event.host and event.host.os_category == "linux":
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
            host=self._build_host_context(system),
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

        if syslog_message and event.host and event.host.os_category == "linux":
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
        cache_key = (src_ip, hostname)
        ts_epoch = time.timestamp()
        last_query = self._dns_cache.get(cache_key, 0)
        cache_ttl = rng.choice([60, 120, 300, 600])  # Varied TTLs
        if ts_epoch - last_query < cache_ttl:
            return  # Cache hit — skip DNS emission
        self._dns_cache[cache_key] = ts_epoch

        # Determine DNS server IP from network visibility or use default
        dns_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
        dns_server_ip = _get_rng().choice(dns_ips)

        src_port = rng.randint(49152, 65535)

        from evidenceforge.events.contexts import DnsContext

        dns_time = time - timedelta(milliseconds=rng.randint(10, 50))
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        is_internal = hostname.endswith(f".{ad_domain}") or hostname.endswith(".local")

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
                sibling_ips = []
                for provider_ips in _PROVIDER_IP_GROUPS:
                    if dst_ip in provider_ips:
                        sibling_ips = [ip for ip in provider_ips if ip != dst_ip]
                        break
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
            answers = [_IPV6_MAP.get(dst_ip, _ipv4_to_fake_ipv6(dst_ip))]
        elif qtype_roll < 0.93:
            # PTR record: reversed IP → rDNS name
            qtype, qtype_name = 12, "PTR"
            octets = dst_ip.split(".")
            query = ".".join(reversed(octets)) + ".in-addr.arpa"
            if _is_private_ip(dst_ip):
                answers = [hostname]
            else:
                answers = [_generate_rdns_name(rng, dst_ip)]
        elif qtype_roll < 0.98:
            # SRV record: AD service discovery
            qtype, qtype_name = 33, "SRV"
            domain = ad_domain
            query = rng.choice(_AD_SRV_QUERIES).format(domain=domain)
            dc_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
            dc_ip = _get_rng().choice(dc_ips)
            dc_hostname = REVERSE_DNS.get(dc_ip, f"dc-01.{domain}")
            svc_prefix = query.split(".")[0]
            port = _SRV_PORT_MAP.get(svc_prefix, 389)
            answers = [f"0 100 {port} {dc_hostname}"]
            is_internal = True
        else:
            # MX record: domain → mail server
            qtype, qtype_name = 15, "MX"
            parts = hostname.split(".", 1)
            query = parts[1] if len(parts) > 1 else hostname
            answers = [f"10 mail.{query}"]

        # Phase 6.0: varied TTLs with cache-aging jitter
        if is_internal:
            base_ttl = rng.choice([300, 600, 1800, 3600, 7200, 86400])
        else:
            base_ttl = rng.choice([30, 60, 120, 300, 600, 1800, 3600])

        ttls = []
        for _ in range(len(answers)):
            jittered = max(1, base_ttl - rng.randint(0, base_ttl // 2))
            ttls.append(float(jittered))

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
            rtt=rng.uniform(0.0005, 0.1),
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

        # Phase 6.0: ~20% chance of NXDOMAIN companion query
        if rng.random() < 0.20:
            nxdomain_queries = [
                f"{hostname}.{ad_domain}",
                f"wpad.{ad_domain}",
                "wpad.local",
                "wpad",
                f"isatap.{ad_domain}",
                "isatap",
                f"_ldap._tcp.Default-First-Site-Name._sites.{ad_domain}",
                f"oldserver.{ad_domain}",
                f"printer01.{ad_domain}",
            ]
            nx_query = rng.choice(nxdomain_queries)
            nx_time = dns_time - timedelta(milliseconds=rng.randint(1, 10))
            nx_src_port = rng.randint(49152, 65535)
            nx_ctx = DnsContext(
                query=nx_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NXDOMAIN",
                rcode_num=3,
                AA=True,
                RD=True,
                RA=True,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=dns_server_ip,
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

        # Normalize intensities to probabilities (cap at 0.95)
        max_val = max(intensity.values())
        for activity, value in intensity.items():
            if activity == "logon":
                continue  # Already added
            prob = min(0.95, value / max_val * 0.8 + 0.1)
            pattern.append((activity, prob))

        return pattern

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
            source_ip = "127.0.0.1" if logon_type == 7 else None
            self.generate_logon(user, system, time, logon_type=logon_type, source_ip=source_ip)

        # Process activities
        elif activity_type in PROCESS_TEMPLATES:
            # Get or create session for this user (with login cooldown)
            sessions = self.state_manager.get_sessions_for_user(user.username)
            active_session = (
                next((s for s in sessions if s.system == system.hostname), None)
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
            if os_category == "windows" and activity_type in PROCESS_TEMPLATES:
                # Phase 5.6: Per-persona app pool for user diversity
                pool = PROCESS_TEMPLATES[activity_type]
                if activity_type == "process_user_apps":
                    persona_key = (user.persona or "default").lower()
                    indices = PERSONA_APP_INDICES.get(persona_key, PERSONA_APP_INDICES["default"])
                    pool = [pool[i] for i in indices if i < len(pool)]
                rng = _get_rng()
                process_name, command_line = rng.choice(pool)
                # Phase 5.1: Substitute username placeholder in paths
                process_name = process_name.replace("{username}", user.username)
                command_line = command_line.replace("{username}", user.username)
                # Parameterize command templates (process_query variety)
                command_line = _parameterize_command(rng, command_line)
                parent_pid = self._select_parent_pid(system, user, process_name)
                pid = self.generate_process(
                    user, system, time, logon_id, process_name, command_line, parent_pid=parent_pid
                )
                self._record_user_process(system, user, pid, process_name)

                # Generate network connections for processes that connect to remote services
                exe_lower = process_name.rsplit("\\", 1)[-1].lower()
                if exe_lower == "sqlcmd.exe" and activity_type == "process_query":
                    # Extract server from command line (-S flag)
                    db_port = 1433
                    db_ip = "127.0.0.1"  # Default localhost
                    if "-S " in command_line:
                        server = command_line.split("-S ")[1].split()[0]
                        # Resolve server name to IP if possible
                        db_ip = REVERSE_DNS.get(server) or next(
                            (
                                ip
                                for name, ip in REVERSE_DNS.items()
                                if server.lower() in name.lower()
                            ),
                            "10.0.2.50",  # Default DB server IP
                        )
                    conn_time = time + timedelta(milliseconds=rng.randint(50, 200))
                    self.generate_connection(
                        src_ip=system.ip,
                        dst_ip=db_ip,
                        time=conn_time,
                        dst_port=db_port,
                        proto="tcp",
                        service="mssql",
                        duration=rng.uniform(0.5, 5.0),
                        orig_bytes=rng.randint(200, 2000),
                        resp_bytes=rng.randint(500, 50000),
                    )

            elif os_category == "linux" and activity_type in PROCESS_TEMPLATES_LINUX:
                # Phase 5.6: Per-persona app pool for Linux user diversity
                pool = PROCESS_TEMPLATES_LINUX[activity_type]
                if activity_type == "process_user_apps":
                    persona_key = (user.persona or "default").lower()
                    indices = PERSONA_APP_INDICES_LINUX.get(
                        persona_key, PERSONA_APP_INDICES_LINUX["default"]
                    )
                    pool = [pool[i] for i in indices if i < len(pool)]
                process_name, command_line = _get_rng().choice(pool)
                parent_pid = self._select_parent_pid(system, user, process_name)
                pid = self.generate_process(
                    user, system, time, logon_id, process_name, command_line, parent_pid=parent_pid
                )
                self._record_user_process(system, user, pid, process_name)

                # Also generate bash history for Linux
                self.generate_bash_command(user, system, time, activity_type)

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            rng = _get_rng()

            # Phase 5.3: 30% chance of random CDN/cloud IP for destination diversity
            if activity_type in ("connection_web", "connection_saas") and rng.random() < 0.30:
                dst_ip = _generate_random_external_ip(rng)
            else:
                available_destinations = [
                    ip for ip in EXTERNAL_IPS[activity_type] if ip != system.ip
                ]
                if not available_destinations:
                    logger.debug(
                        f"Skipping {activity_type} for {system.hostname}: "
                        f"no valid destination IPs (all match source {system.ip})"
                    )
                    return
                dst_ip = rng.choice(available_destinations)

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

        event = SecurityEvent(
            timestamp=time,
            event_type="machine_logon",
            host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=f"0x{rng.randint(0x10000, 0xFFFFF):x}",
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

        domain = domain or getattr(self, "_netbios_domain", "CORP")
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt",
            host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options="0x40810010",
                encryption_type="0x12",
                pre_auth_type=15,
                source_ip=f"::ffff:{source_ip}",
                source_port=rng.randint(49152, 65535),
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

        domain = domain or getattr(self, "_netbios_domain", "CORP")
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt_renewal",
            host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options="0x2",
                encryption_type="0x12",
                source_ip=f"::ffff:{source_ip}",
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
        domain: str = "",
    ) -> None:
        """Generate Kerberos service ticket request event (4769) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        domain = domain or getattr(self, "_netbios_domain", "CORP")
        rng = _get_rng()

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_service",
            host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=f"{username}@{domain}",
                target_domain=domain,
                service_name=service_name,
                service_sid=self._get_sid(
                    f"{service_name.split('/')[1]}$" if "/" in service_name else service_name
                ),
                ticket_options="0x40810000",
                encryption_type="0x12",
                source_ip=f"::ffff:{source_ip}",
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
        sessions = self.state_manager.get_sessions_for_user(user.username)
        subject_logon_id = sessions[0].logon_id if sessions else "0x3e7"
        event = SecurityEvent(
            timestamp=time,
            event_type="explicit_credentials",
            host=self._build_host_context(system),
            auth=AuthContext(
                username=target_username,
                user_sid=self._get_sid(target_username),
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=self._build_host_context(system).netbios_domain,
                subject_logon_id=subject_logon_id,
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                reporting_pid=reporting_pid,
                target_server=target_server,
                process_name=process_name,
                source_ip=source_ip or "-",
                source_port=source_port,
            ),
        )
        self.dispatcher.dispatch(event)

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
            host=self._build_host_context(system),
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
    ) -> str:
        """Generate RDP session: Zeek conn + 4624 type 10 + eCAR on target.

        Compound event ensuring network and host evidence are always paired.
        Returns Zeek UID.
        """
        rng = _get_rng()

        # 1. Network connection (Zeek conn.log port 3389)
        uid = self.generate_connection(
            src_ip=source_ip,
            dst_ip=target_system.ip,
            time=time,
            dst_port=3389,
            service="rdp",
            duration=rng.uniform(60.0, 3600.0),
            orig_bytes=rng.randint(50000, 500000),
            resp_bytes=rng.randint(100000, 2000000),
            emit_dns=False,
            source_system=source_system,
        )

        # 2. Host logon on target (4624 type 10 + 4672 if elevated)
        logon_time = time + timedelta(milliseconds=rng.randint(50, 200))
        self.generate_logon(
            user=user,
            system=target_system,
            time=logon_time,
            logon_type=10,
            source_ip=source_ip,
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
            host=host,
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
            host=dc_host,
            kerberos=KerberosContext(
                target_username=username,
                target_domain=dc_host.netbios_domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                ticket_options="0x40810010",
                ticket_status=status,
                pre_auth_type=0,
                source_ip=f"::ffff:{source_ip}" if ":" not in source_ip else source_ip,
                source_port=rng.randint(49152, 65535),
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
            host=self._build_host_context(system),
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
            host=self._build_host_context(system),
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
            host=self._build_host_context(system),
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
            host=host,
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
            host=host,
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
            host=host,
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
            host=host,
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
            host=host,
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
        from evidenceforge.events.contexts import ProcessContext

        event = SecurityEvent(
            timestamp=time,
            event_type="create_remote_thread",
            host=self._build_host_context(system),
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
        from evidenceforge.events.contexts import ProcessContext

        event = SecurityEvent(
            timestamp=time,
            event_type="process_access",
            host=self._build_host_context(system),
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
            host=host,
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
    ) -> None:
        """Generate a DHCP lease event via canonical SecurityEvent dispatch."""
        from evidenceforge.events.contexts import DhcpContext

        event = SecurityEvent(
            timestamp=time,
            event_type="dhcp_lease",
            host=self._build_host_context(system),
            dhcp=DhcpContext(
                client_addr=system.ip,
                server_addr=server_addr,
                mac=mac,
                host_name=system.hostname,
                assigned_addr=system.ip,
                lease_time=lease_time,
                uids=[uid] if uid else [],
                msg_types=["DISCOVER", "OFFER", "REQUEST", "ACK"],
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
            host=self._build_host_context(system),
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
            host=self._build_host_context(system),
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
        event = SecurityEvent(
            timestamp=time,
            event_type="raw",
            host=host_ctx,
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
            host=HostContext(
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
                    host=HostContext(
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

    def _lookup_process_name(self, hostname: str, pid: int) -> str:
        """Look up the image path of a running process by PID.

        Falls back to explorer.exe for user processes if PID not tracked.
        """
        key = (hostname, pid)
        proc = self.state_manager.state.running_processes.get(key)
        if proc:
            return proc.image
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
                return sys_pids.get("services", sys_pids.get("svchost_dcom", 4))

            # Prefer session-specific explorer PID over system-wide default
            session_explorer = self._get_session_explorer_pid(system, user)
            explorer_pid = session_explorer or sys_pids.get("explorer", 4)

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
            return sys_pids.get("bash", sys_pids.get("sshd", 1))

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
        return "S-1-5-21-0-0-0-0"

    # Phase 5.2: EDR object type diversity data pools
    _EDR_FILE_PATHS_WIN = [
        # User documents
        "C:\\Users\\{user}\\Documents\\report.docx",
        "C:\\Users\\{user}\\Documents\\spreadsheet.xlsx",
        "C:\\Users\\{user}\\Documents\\presentation.pptx",
        "C:\\Users\\{user}\\Documents\\Q4-review.pdf",
        "C:\\Users\\{user}\\Documents\\meeting-notes.txt",
        # Downloads and desktop
        "C:\\Users\\{user}\\Downloads\\file.pdf",
        "C:\\Users\\{user}\\Downloads\\installer-{rand}.exe",
        "C:\\Users\\{user}\\Desktop\\notes.txt",
        "C:\\Users\\{user}\\Desktop\\shortcut.lnk",
        # Temp files
        "C:\\Users\\{user}\\AppData\\Local\\Temp\\tmp{rand}.tmp",
        "C:\\Users\\{user}\\AppData\\Local\\Temp\\~DF{rand}.tmp",
        # Application data
        "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Office\\16.0\\OfficeFileCache\\{rand}.dat",
        "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\data_{rand}",
        "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\{rand}",
        "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\report.docx.lnk",
        # System paths
        "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\Report.wer",
        "C:\\Windows\\Prefetch\\CMD.EXE-{rand}.pf",
        "C:\\Windows\\Temp\\{rand}.tmp",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\{rand}",
        "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    ]
    _EDR_FILE_PATHS_LINUX = [
        # User files
        "/home/{user}/documents/report.odt",
        "/home/{user}/documents/notes.md",
        "/home/{user}/downloads/file.pdf",
        "/home/{user}/downloads/archive-{rand}.tar.gz",
        "/home/{user}/.bashrc",
        "/home/{user}/.ssh/known_hosts",
        # Temp files
        "/tmp/tmp{rand}",
        "/tmp/systemd-private-{rand}-apache2.service",
        "/var/tmp/{rand}.lock",
        # Application caches
        "/home/{user}/.cache/mozilla/firefox/cache2/entries/{rand}",
        "/home/{user}/.cache/pip/http/{rand}",
        "/home/{user}/.local/share/recently-used.xbel",
        # Logs and system
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/apache2/access.log",
        "/proc/{rand}/status",
        "/etc/passwd",
        # Package manager
        "/var/lib/dpkg/status",
        "/var/cache/apt/archives/lock",
        "/var/lib/apt/lists/lock",
    ]
    _EDR_REGISTRY_KEYS = [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "a"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth"),
        ("HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General", "ShownFirstRunOptin"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell"),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable"),
    ]
    _EDR_DLL_POOL = [
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\user32.dll",
        "C:\\Windows\\System32\\advapi32.dll",
        "C:\\Windows\\System32\\msvcrt.dll",
        "C:\\Windows\\System32\\rpcrt4.dll",
        "C:\\Windows\\System32\\ole32.dll",
        "C:\\Windows\\System32\\combase.dll",
        "C:\\Windows\\System32\\sechost.dll",
        "C:\\Windows\\System32\\gdi32.dll",
    ]

    # _emit_ecar_file_event and _emit_ecar_registry_event removed in Phase 8.2
    # FILE/REGISTRY events now dispatched via SecurityEvent canonical model

    # _emit_ecar_flow_event removed in Phase 8.1 — eCAR FLOW now dispatched
    # via SecurityEvent "connection" type through the canonical event model

    # _emit_ecar_module_event removed in Phase 8.2
    # MODULE events now dispatched via SecurityEvent canonical model
