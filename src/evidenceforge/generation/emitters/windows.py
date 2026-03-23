"""Windows Event Log emitter.

Buffers raw event dicts, sorts by timestamp on flush, assigns per-computer
EventRecordIDs in sorted order (ensuring monotonic IDs match chronological
order), then renders to XML and writes to per-host FQDN directories.
"""

import logging
import random
from datetime import datetime
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.generation.emitters.host_base import _SingleHostWriter

win_logger = logging.getLogger(__name__)


class WindowsEventEmitter(LogEmitter):
    """Emitter for Windows Event Log format (XML).

    Unlike other emitters that buffer rendered strings, this emitter buffers
    raw event dicts and defers rendering until flush time. This allows
    EventRecordIDs to be assigned after chronological sorting, ensuring
    higher RecordID always corresponds to same-or-later timestamp (matching
    real Windows Event Log behavior).

    _supported_types will be populated during Phase 7.2 migration.
    """

    _supported_types: set[str] = {
        "logon", "logoff", "failed_logon",
        "process_create", "process_terminate", "system_process_create",
        "machine_logon", "kerberos_tgt", "kerberos_tgt_renewal", "kerberos_service",
        "ntlm_validation", "explicit_credentials", "wfp_connection",
    }

    @staticmethod
    def _ipv6_mapped(ip: str | None) -> str:
        """Format IPv4 as ::ffff:-mapped for Windows event consistency."""
        if not ip:
            return '-'
        if ':' in ip:
            return ip  # Already IPv6
        return f'::ffff:{ip}'

    def can_handle(self, event: SecurityEvent) -> bool:
        """Windows emitter handles events on Windows hosts."""
        return (
            event.event_type in self._supported_types
            and event.host is not None
            and event.host.os_category == "windows"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        renderer = {
            "logon": self._render_logon,
            "logoff": self._render_logoff,
            "failed_logon": self._render_failed_logon,
            "process_create": self._render_process_create,
            "process_terminate": self._render_process_terminate,
            "system_process_create": self._render_system_process_create,
            "machine_logon": self._render_machine_logon,
            "kerberos_tgt": self._render_kerberos_tgt,
            "kerberos_tgt_renewal": self._render_kerberos_tgt_renewal,
            "kerberos_service": self._render_kerberos_service,
            "ntlm_validation": self._render_ntlm_validation,
            "explicit_credentials": self._render_explicit_credentials,
            "wfp_connection": self._render_wfp_connection,
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(
                f"WindowsEventEmitter: no render method for {event.event_type}"
            )
        renderer(event)

    def _render_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4624 (successful logon) + optional 4672 (special privileges)."""
        rng = random.Random()
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4624,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'SubjectUserSid': auth.subject_sid,
            'SubjectUserName': auth.subject_username,
            'SubjectDomainName': auth.subject_domain,
            'SubjectLogonId': auth.subject_logon_id,
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'TargetLogonId': auth.logon_id,
            'LogonType': auth.logon_type,
            'WorkstationName': host.hostname,
            'ProcessId': f'0x{auth.reporting_pid:x}' if auth.reporting_pid else '0x2e0',
            'ProcessName': r'C:\Windows\System32\lsass.exe',
            'IpAddress': self._ipv6_mapped(auth.source_ip),
            'IpPort': rng.randint(49152, 65535) if auth.logon_type == 3 else 0,
            'LogonProcessName': auth.logon_process,
            'AuthenticationPackageName': auth.auth_package,
            'LmPackageName': auth.lm_package,
            'LogonGuid': auth.logon_guid,
        }
        self.emit_event(event_data)

        # 4672 special privileges (when auth.elevated is True)
        if auth.elevated:
            # Admin/service/machine accounts get full privilege set
            is_admin = (auth.username.endswith('$')
                        or auth.username in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')
                        or auth.logon_type == 5)
            if is_admin:
                privs = (
                    'SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t'
                    'SeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\t'
                    'SeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\t'
                    'SeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\t'
                    'SeDelegateSessionUserImpersonatePrivilege'
                )
            else:
                # Regular user with occasional elevation (e.g., UAC prompt)
                privs = (
                    'SeChangeNotifyPrivilege\n\t\t\tSeIncreaseWorkingSetPrivilege\n\t\t\t'
                    'SeShutdownPrivilege\n\t\t\tSeUndockPrivilege\n\t\t\t'
                    'SeTimeZonePrivilege'
                )
            priv_data = {
                'EventID': 4672,
                'TimeCreated': event.timestamp,
                'Computer': host.fqdn,
                'Channel': 'Security',
                'Level': 0,
                'ExecutionProcessID': auth.reporting_pid or 600,
                'ExecutionThreadID': rng.randint(100, 500),
                'SubjectUserSid': auth.user_sid,
                'SubjectUserName': auth.username,
                'SubjectDomainName': host.netbios_domain,
                'SubjectLogonId': auth.logon_id,
                'PrivilegeList': privs,
            }
            self.emit_event(priv_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render Windows 4634 (logoff)."""
        rng = random.Random()
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4634,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'TargetLogonId': auth.logon_id,
            'LogonType': auth.logon_type,
        }
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4625 (failed logon)."""
        rng = random.Random()
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4625,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'Keywords': '0x8010000000000000',  # Audit Failure
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 9999),
            'SubjectUserSid': auth.subject_sid,
            'SubjectUserName': auth.subject_username,
            'SubjectDomainName': auth.subject_domain,
            'SubjectLogonId': auth.subject_logon_id,
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'Status': auth.failure_status,
            'SubStatus': auth.failure_substatus,
            'FailureReason': auth.failure_reason,
            'LogonType': auth.logon_type,
            'IpAddress': self._ipv6_mapped(auth.source_ip),
            'IpPort': rng.randint(49152, 65535) if auth.logon_type == 3 else 0,
        }
        self.emit_event(event_data)

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render Windows 4688 (new process created)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4688,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(100, 9999),
            'SubjectUserSid': auth.user_sid,
            'SubjectUserName': auth.username,
            'SubjectDomainName': host.netbios_domain,
            'SubjectLogonId': proc.logon_id,
            'NewProcessId': f'0x{proc.pid:x}',
            'NewProcessName': proc.image,
            'TokenElevationType': proc.token_elevation or '%%1938',
            'ProcessId': f'0x{proc.parent_pid:x}',
            'CommandLine': proc.command_line,
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'TargetLogonId': proc.logon_id,
            'ParentProcessName': proc.parent_image,
            'MandatoryLabel': proc.mandatory_label or 'S-1-16-8192',
        }
        self.emit_event(event_data)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render Windows 4689 (process exited)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4689,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(100, 500),
            'SubjectUserSid': auth.user_sid,
            'SubjectUserName': auth.username,
            'SubjectDomainName': host.netbios_domain,
            'SubjectLogonId': proc.logon_id,
            'Status': '0x0',
            'ProcessId': f'0x{proc.pid:x}',
            'ProcessName': proc.image,
        }
        self.emit_event(event_data)

    def _render_system_process_create(self, event: SecurityEvent) -> None:
        """Render Windows 4688 for system-account process (SYSTEM, LOCAL SERVICE, etc.)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4688,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(100, 9999),
            'SubjectUserSid': auth.subject_sid,
            'SubjectUserName': auth.subject_username,
            'SubjectDomainName': auth.subject_domain,
            'SubjectLogonId': auth.subject_logon_id,
            'NewProcessId': f'0x{proc.pid:x}',
            'NewProcessName': proc.image,
            'TokenElevationType': proc.token_elevation or '%%1936',
            'ProcessId': f'0x{proc.parent_pid:x}',
            'CommandLine': proc.command_line,
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': auth.subject_domain,
            'TargetLogonId': proc.logon_id,
            'ParentProcessName': proc.parent_image,
            'MandatoryLabel': proc.mandatory_label or 'S-1-16-16384',
        }
        self.emit_event(event_data)

    def _render_machine_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4624 for machine account logon (type 3 on DC)."""
        rng = random.Random()
        auth = event.auth
        host = event.host
        # Derive WorkstationName from machine account (WKS-01$ → WKS-01)
        workstation = auth.username.rstrip('$') if auth.username.endswith('$') else auth.username

        event_data = {
            'EventID': 4624,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'SubjectUserSid': auth.subject_sid,
            'SubjectUserName': auth.subject_username,
            'SubjectDomainName': auth.subject_domain,
            'SubjectLogonId': auth.subject_logon_id,
            'TargetUserSid': auth.user_sid,
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'TargetLogonId': auth.logon_id,
            'LogonType': 3,
            'LogonProcessName': auth.logon_process,
            'AuthenticationPackageName': auth.auth_package,
            'WorkstationName': workstation,
            'LogonGuid': auth.logon_guid,
            'TransmittedServices': '-',
            'LmPackageName': auth.lm_package,
            'KeyLength': 0,
            'ProcessId': '0x0',
            'ProcessName': '-',
            'IpAddress': self._ipv6_mapped(auth.source_ip),
            'IpPort': str(rng.randint(49152, 65535)),
            'ImpersonationLevel': '%%1833',
            'RestrictedAdminMode': '-',
            'TargetOutboundUserName': '-',
            'TargetOutboundDomainName': '-',
            'VirtualAccount': '%%1843',
            'TargetLinkedLogonId': '0x0',
            'ElevatedToken': '%%1842',
        }
        self.emit_event(event_data)

        # 4672 special privileges for machine accounts
        if auth.elevated:
            priv_data = {
                'EventID': 4672,
                'TimeCreated': event.timestamp,
                'Computer': host.fqdn,
                'Channel': 'Security',
                'Level': 0,
                'ExecutionProcessID': auth.reporting_pid or 600,
                'ExecutionThreadID': rng.randint(100, 500),
                'SubjectUserSid': auth.user_sid,
                'SubjectUserName': auth.username,
                'SubjectDomainName': host.netbios_domain,
                'SubjectLogonId': auth.logon_id,
                'PrivilegeList': (
                    'SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t'
                    'SeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\t'
                    'SeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\t'
                    'SeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\t'
                    'SeDelegateSessionUserImpersonatePrivilege'
                ),
            }
            self.emit_event(priv_data)

    def _render_kerberos_tgt(self, event: SecurityEvent) -> None:
        """Render Windows 4768 (Kerberos TGT request)."""
        rng = random.Random()
        krb = event.kerberos
        host = event.host
        is_failure = krb.ticket_status != '0x0'

        event_data = {
            'EventID': 4768,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'Keywords': '0x8010000000000000' if is_failure else '0x8020000000000000',
            'ExecutionProcessID': krb.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'TargetUserName': krb.target_username,
            'TargetDomainName': krb.target_domain,
            'TargetSid': krb.target_sid,
            'ServiceName': krb.service_name,
            'ServiceSid': krb.service_sid,
            'TicketOptions': krb.ticket_options,
            'Status': krb.ticket_status,
            'TicketEncryptionType': krb.encryption_type,
            'PreAuthType': krb.pre_auth_type,
            'IpAddress': krb.source_ip,
            'IpPort': krb.source_port,
        }
        self.emit_event(event_data)

    def _render_kerberos_service(self, event: SecurityEvent) -> None:
        """Render Windows 4769 (Kerberos service ticket request)."""
        rng = random.Random()
        krb = event.kerberos
        host = event.host
        is_failure = krb.ticket_status != '0x0'

        event_data = {
            'EventID': 4769,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'Keywords': '0x8010000000000000' if is_failure else '0x8020000000000000',
            'ExecutionProcessID': krb.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'TargetUserName': f"{krb.target_username}@{krb.target_domain.upper()}",
            'TargetDomainName': krb.target_domain,
            'ServiceName': krb.service_name,
            'ServiceSid': krb.service_sid,
            'TicketOptions': krb.ticket_options,
            'TicketEncryptionType': krb.encryption_type,
            'IpAddress': krb.source_ip,
            'IpPort': krb.source_port,
            'Status': krb.ticket_status,
        }
        self.emit_event(event_data)

    def _render_kerberos_tgt_renewal(self, event: SecurityEvent) -> None:
        """Render Windows 4770 (Kerberos TGT renewal)."""
        rng = random.Random()
        krb = event.kerberos
        host = event.host

        event_data = {
            'EventID': 4770,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': krb.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'TargetUserName': krb.target_username,
            'TargetDomainName': krb.target_domain,
            'ServiceName': krb.service_name,
            'ServiceSid': krb.service_sid,
            'TicketOptions': krb.ticket_options,
            'TicketEncryptionType': krb.encryption_type,
            'IpAddress': krb.source_ip,
            'IpPort': krb.source_port,
        }
        self.emit_event(event_data)

    def _render_ntlm_validation(self, event: SecurityEvent) -> None:
        """Render Windows 4776 (NTLM credential validation)."""
        rng = random.Random()
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4776,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 500),
            'PackageName': 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0',
            'TargetUserName': auth.username,
            'Workstation': auth.source_ip,  # workstation stored in source_ip
            'Status': '0x0',
        }
        self.emit_event(event_data)

    def _render_explicit_credentials(self, event: SecurityEvent) -> None:
        """Render Windows 4648 (explicit credentials logon)."""
        rng = random.Random()
        auth = event.auth
        host = event.host

        event_data = {
            'EventID': 4648,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': auth.reporting_pid or 600,
            'ExecutionThreadID': rng.randint(100, 9999),
            'SubjectUserSid': auth.subject_sid,
            'SubjectUserName': auth.subject_username,
            'SubjectDomainName': auth.subject_domain,
            'SubjectLogonId': auth.subject_logon_id,
            'LogonGuid': auth.logon_guid or '{00000000-0000-0000-0000-000000000000}',
            'TargetUserName': auth.username,
            'TargetDomainName': host.netbios_domain,
            'TargetLogonGuid': '{00000000-0000-0000-0000-000000000000}',
            'TargetServerName': auth.target_server or 'localhost',
            'TargetInfo': auth.target_server or 'localhost',
            'ProcessId': f'0x{auth.reporting_pid:x}' if auth.reporting_pid else '0x0',
            'ProcessName': auth.process_name or r'C:\Windows\System32\svchost.exe',
            'IpAddress': auth.source_ip or '-',
            'IpPort': auth.source_port or 0,
        }
        self.emit_event(event_data)

    def _render_wfp_connection(self, event: SecurityEvent) -> None:
        """Render Windows 5156 (WFP connection permitted)."""
        rng = random.Random()
        net = event.network
        host = event.host
        proc = event.process
        is_outbound = net.src_ip == host.ip

        event_data = {
            'EventID': 5156,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(50, 200),
            'ProcessID': net.initiating_pid if net.initiating_pid > 0 else 4,
            'Application': self._to_device_path(
                proc.image if proc else r'C:\Windows\System32\svchost.exe'
            ),
            'Direction': '%%14593' if is_outbound else '%%14592',
            'SourceAddress': net.src_ip,
            'SourcePort': net.src_port,
            'DestAddress': net.dst_ip,
            'DestPort': net.dst_port,
            'Protocol': net.ip_proto,
            'FilterRTID': rng.randint(0, 70000),
            'LayerName': '%%14611',
            'LayerRTID': 48,
            'RemoteUserID': 'S-1-0-0',
            'RemoteMachineID': 'S-1-0-0',
        }
        self.emit_event(event_data)

    @staticmethod
    def _to_device_path(path: str) -> str:
        """Convert C:\\path to \\device\\harddiskvolume1\\path (lowercase)."""
        if path and len(path) > 2 and path[1] == ':':
            return f'\\device\\harddiskvolume1\\{path[3:]}'.lower()
        return path.lower()

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        # Detect direct file mode (backward compat for tests)
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._host_writers: dict[str, _SingleHostWriter] = {}
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        # Buffer raw event dicts instead of rendered strings
        self._event_dicts: list[dict[str, Any]] = []
        # Per-computer RecordID counters persist across flushes
        self._record_id_counters: dict[str, int] = {}

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        writer = self._host_writers.get(host_fqdn)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(host_fqdn)
            if writer is not None:
                return writer
            if host_fqdn and not self._direct_file_mode:
                path = self._base_dir / host_fqdn / "windows_event_security.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_security.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
            # Write XML header immediately for new host files
            header = self.format_def.output.header_template
            if header:
                writer.write_header(header)
            self._host_writers[host_fqdn] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        """Override base class to route through default host writer (backward compat for tests)."""
        self._get_host_writer("").write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Buffer a Windows Event dict for deferred rendering."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            with self._file_lock:
                self._event_dicts.append(event_data)
                if len(self._event_dicts) >= self.buffer_size:
                    self._flush_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event dict to XML format."""
        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        return self._template.render(**event_data)

    def _run(self) -> None:
        """Thread run loop — buffers dicts from queue instead of rendering."""
        win_logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                with self._file_lock:
                    self._event_dicts.append(event_data)
                    if len(self._event_dicts) >= self.buffer_size:
                        self._flush_unlocked()
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    self.flush()
                    self._flush_barrier.clear()

        self.flush()
        win_logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _flush_unlocked(self) -> None:
        """Sort events, assign RecordIDs, render, and write to per-host files."""
        if not self._event_dicts:
            return

        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            return ts if isinstance(ts, datetime) else ts

        self._event_dicts.sort(key=_sort_key)

        # Assign per-computer EventRecordIDs in sorted order
        for event in self._event_dicts:
            computer = event.get("Computer", "")
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                rng = random.Random(f"erid_{counter_key}")
                key_lower = counter_key.lower()
                if 'dc' in key_lower:
                    self._record_id_counters[counter_key] = rng.randint(5_000_000, 15_000_000)
                elif any(x in key_lower for x in ('srv', 'server', 'web', 'file', 'db', 'mail', 'exch')):
                    self._record_id_counters[counter_key] = rng.randint(50_000, 550_000)
                else:
                    self._record_id_counters[counter_key] = rng.randint(5_000, 55_000)
            gap_rng = random.Random(f"erid_gap_{counter_key}_{self._record_id_counters[counter_key]}")
            if gap_rng.random() < 0.15:
                self._record_id_counters[counter_key] += gap_rng.randint(2, 8)
            elif gap_rng.random() < 0.03:
                self._record_id_counters[counter_key] += gap_rng.randint(20, 200)
            else:
                self._record_id_counters[counter_key] += 1
            event["EventRecordID"] = self._record_id_counters[counter_key]

        # Render and route to per-host writers
        for event in self._event_dicts:
            rendered = self._render_event(event)
            host_fqdn = event.get("Computer", "")
            self._get_host_writer(host_fqdn).write(rendered)

        self._event_dicts.clear()

    def flush(self) -> None:
        """Flush dict buffer then all host writers."""
        with self._file_lock:
            self._flush_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()

    def close(self) -> None:
        """Close emitter — flush and write XML footers for each host file."""
        if self.threaded:
            self.stop_thread()
        else:
            self.flush()
        # Write XML footer for each host file that has events
        footer = self.format_def.output.footer_template or ""
        for writer in self._host_writers.values():
            writer.flush()
            if footer and writer.event_count > 0:
                writer.write_footer(footer)

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._host_writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
