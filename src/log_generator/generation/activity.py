"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import logging
import random
from datetime import datetime
from typing import Optional

from log_generator.generation.emitters import WindowsEventEmitter, ZeekEmitter
from log_generator.generation.state_manager import StateManager
from log_generator.models.scenario import User, System
from log_generator.utils.ids import generate_zeek_uid

logger = logging.getLogger(__name__)


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

# Process names and command lines for baseline activities
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
        '10.0.10.50',      # Internal DB server
        '192.168.100.25',  # Internal DB server
    ],
}


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
        event_record_counter: int = 10000
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
        """
        self.state_manager = state_manager
        self.emitters = emitters
        self.event_record_counter = event_record_counter

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

        # Emit Windows Event 4624 (An account was successfully logged on)
        event_data = {
            'EventID': 4624,
            'TimeCreated': time,
            'Computer': system.hostname,
            'Channel': 'Security',
            'Level': 0,  # Information
            'EventRecordID': self._get_next_event_record_id(),
            'ExecutionProcessID': 4,    # System process
            'ExecutionThreadID': random.randint(100, 500),
            # Logon variant fields
            'TargetUserName': user.username,
            'TargetDomainName': 'CORP',  # Phase 1: Fixed domain
            'TargetLogonId': logon_id,
            'LogonType': logon_type,
            'WorkstationName': system.hostname,
            'IpAddress': source_ip,
            'IpPort': random.randint(49152, 65535) if logon_type == 3 else None,
            'LogonProcessName': 'User32' if logon_type == 2 else 'NtLmSsp',
            'AuthenticationPackageName': 'Negotiate',
        }

        self.emitters['windows_event_security'].emit_event(event_data)
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
            'ExecutionThreadID': random.randint(100, 500),
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

        # Emit Windows Event 4688 (A new process has been created)
        event_data = {
            'EventID': 4688,
            'TimeCreated': time,
            'Computer': system.hostname,
            'Channel': 'Security',
            'Level': 0,
            'EventRecordID': self._get_next_event_record_id(),
            'ExecutionProcessID': 4,
            'ExecutionThreadID': random.randint(100, 500),
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
        src_port = random.randint(49152, 65535)  # Ephemeral port

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

        self.emitters['zeek_conn'].emit_event(event_data)
        logger.debug(f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})")

        return uid

    def get_baseline_pattern(self, persona_name: Optional[str]) -> list[tuple[str, float]]:
        """Get baseline activity pattern for persona.

        Args:
            persona_name: Persona name (or None for default)

        Returns:
            List of (activity_type, probability) tuples
        """
        if persona_name and persona_name.lower() in BASELINE_PATTERNS:
            return BASELINE_PATTERNS[persona_name.lower()]
        return BASELINE_PATTERNS['default']

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

            # Choose random process template
            process_name, command_line = random.choice(PROCESS_TEMPLATES[activity_type])
            self.generate_process(user, system, time, logon_id, process_name, command_line)

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            # Choose random destination IP
            dst_ip = random.choice(EXTERNAL_IPS[activity_type])

            # Set service and port based on activity type
            if activity_type == 'connection_web':
                service = random.choice(['http', 'https'])
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
            orig_bytes = random.randint(500, 5000)
            resp_bytes = random.randint(1000, 50000)
            duration = random.uniform(0.1, 5.0)

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
        """Get next EventRecordID for Windows events.

        Returns:
            Next sequential EventRecordID
        """
        self.event_record_counter += 1
        return self.event_record_counter
