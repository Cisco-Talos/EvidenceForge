"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import logging
import random
from datetime import datetime
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
        ('logon', 0.8),          # 80% chance of logon
        ('process_code', 0.6),   # 60% chance of code editor
        ('connection_git', 0.4), # 40% chance of git operation
        ('process_build', 0.3),  # 30% chance of build
    ],
    'executive': [
        ('logon', 0.9),
        ('connection_web', 0.7),
        ('connection_email', 0.6),
    ],
    'analyst': [
        ('logon', 0.85),
        ('process_query', 0.5),
        ('connection_db', 0.4),
    ],
    'default': [
        ('logon', 0.75),
        ('connection_web', 0.5),
    ],
}

# Process names and command lines for baseline activities (Windows)
PROCESS_TEMPLATES = {
    'process_code': [
        ('C:\\Program Files\\Microsoft VS Code\\Code.exe', 'Code.exe --no-sandbox'),
        ('C:\\Program Files (x86)\\Notepad++\\notepad++.exe', 'notepad++ document.txt'),
    ],
    'process_build': [
        ('C:\\Windows\\System32\\msbuild.exe', 'msbuild.exe solution.sln /t:Build'),
        ('C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c npm run build'),
    ],
    'process_query': [
        ('C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe', 'sqlcmd.exe -S localhost -Q "SELECT * FROM users"'),
        ('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -Command "Get-EventLog -LogName Security -Newest 100"'),
    ],
}

# Process names and command lines for baseline activities (Linux) - Phase 2.10
PROCESS_TEMPLATES_LINUX = {
    'process_code': [
        ('/usr/bin/vim', 'vim /home/user/script.py'),
        ('/usr/bin/nano', 'nano /etc/config.conf'),
        ('/usr/bin/code', 'code --no-sandbox /home/user/project'),
    ],
    'process_build': [
        ('/usr/bin/make', 'make -j4'),
        ('/usr/bin/gcc', 'gcc -o output source.c'),
        ('/usr/bin/npm', 'npm run build'),
    ],
    'process_query': [
        ('/usr/bin/mysql', 'mysql -u root -p database'),
        ('/usr/bin/psql', 'psql -U postgres -d mydb'),
    ],
}

# External IPs for network connections (non-RFC1918)
EXTERNAL_IPS = {
    'connection_web': [
        '93.184.216.34',   # example.com
        '172.217.14.206',  # google.com
        '151.101.1.140',   # reddit.com
    ],
    'connection_email': [
        '52.97.145.162',   # Office 365
        '209.85.233.27',   # Gmail
    ],
    'connection_git': [
        '140.82.121.3',    # github.com
        '104.26.7.33',     # gitlab.com
    ],
    'connection_db': [
        # For internal DB connections, use dedicated DB server IPs in separate subnet
        # This prevents matching workstation IPs (10.0.10.x) which would create
        # same source/destination connections that network sensors can't observe
        '10.0.100.10',     # Internal DB server (separate subnet)
        '10.0.100.11',     # Internal DB replica
    ],
}


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
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
            network_visibility: Optional NetworkVisibilityEngine for sensor-based filtering
        """
        self.state_manager = state_manager
        self.emitters = emitters
        self.event_record_counter = event_record_counter
        self._counter_lock = Lock()  # Thread-safe counter for EventRecordID

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

        logger.debug(f"Generated logon: {user.username} on {system.hostname} (LogonID: {logon_id})")
        return logon_id

    def generate_logoff(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str
    ) -> None:
        """Generate logoff event and emit Windows 4634.

        Ends session in StateManager and emits Windows Event 4634 (logoff).

        Args:
            user: User logging off
            system: System being logged off from
            time: Logoff timestamp
            logon_id: LogonID from the logon event
        """
        # End session in StateManager
        self.state_manager.end_session(logon_id)

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
            'TargetUserName': user.username,
            'TargetDomainName': 'CORP',
            'TargetLogonId': logon_id,
            'LogonType': 2,  # Phase 1: Assume interactive
        }

        self.emitters['windows_event_security'].emit_event(event_data)
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

        logger.debug(f"Generated process: {process_name} (PID: {pid}) on {system.hostname}")
        return pid

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

        # Determine connection state and other Zeek-specific fields
        conn_state = 'SF' if duration else 'S0'  # SF = normal termination, S0 = connection attempt seen, no reply

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
            'history': 'ShADadfF' if conn_state == 'SF' else '^',  # Simplified history
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
        # Logon activity
        if activity_type == 'logon':
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
                self.generate_process(user, system, time, logon_id, process_name, command_line)

            elif os_category == 'linux' and activity_type in PROCESS_TEMPLATES_LINUX:
                # Use Linux process templates
                process_name, command_line = _get_rng().choice(PROCESS_TEMPLATES_LINUX[activity_type])
                self.generate_process(user, system, time, logon_id, process_name, command_line)

                # Also generate bash history for Linux
                self.generate_bash_command(user, system, time, activity_type)

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            # Choose random destination IP (exclude source system's IP)
            available_destinations = [
                ip for ip in EXTERNAL_IPS[activity_type]
                if ip != system.ip
            ]

            if not available_destinations:
                # No valid destinations (all IPs match source)
                logger.debug(
                    f"Skipping {activity_type} for {system.hostname}: "
                    f"no valid destination IPs (all match source {system.ip})"
                )
                return

            dst_ip = _get_rng().choice(available_destinations)

            # Set service and port based on activity type
            if activity_type == 'connection_web':
                service = _get_rng().choice(['http', 'https'])
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

            # Generate realistic traffic sizes
            orig_bytes = _get_rng().randint(500, 5000)
            resp_bytes = _get_rng().randint(1000, 50000)
            duration = _get_rng().uniform(0.1, 5.0)

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
