"""Windows Event Log emitter.

Buffers raw event dicts, sorts by timestamp on flush, assigns per-computer
EventRecordIDs in sorted order (ensuring monotonic IDs match chronological
order), then renders to XML and writes to disk.
"""

import random
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


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
        "machine_logon", "kerberos_tgt", "kerberos_service", "ntlm_validation",
    }

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
            "kerberos_service": self._render_kerberos_service,
            "ntlm_validation": self._render_ntlm_validation,
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
            'ExecutionProcessID': 4,
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
            'IpAddress': auth.source_ip,
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
                    'SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\t'
                    'SeLoadDriverPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t'
                    'SeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\t'
                    'SeSystemEnvironmentPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\t'
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
                'ExecutionProcessID': 4,
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
            'ExecutionProcessID': 4,
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
            'ExecutionProcessID': 4,
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
            'IpAddress': auth.source_ip,
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
            'ExecutionProcessID': 4,
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
            'IpAddress': auth.source_ip,
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

    def _render_kerberos_tgt(self, event: SecurityEvent) -> None:
        """Render Windows 4768 (Kerberos TGT request)."""
        rng = random.Random()
        krb = event.kerberos
        host = event.host

        event_data = {
            'EventID': 4768,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
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

        event_data = {
            'EventID': 4769,
            'TimeCreated': event.timestamp,
            'Computer': host.fqdn,
            'Channel': 'Security',
            'Level': 0,
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(100, 500),
            'TargetUserName': krb.target_username,
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
            'ExecutionProcessID': 4,
            'ExecutionThreadID': rng.randint(100, 500),
            'PackageName': 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0',
            'LogonAccount': auth.username,
            'SourceWorkstation': auth.source_ip,  # workstation stored in source_ip
            'Status': '0x0',
        }
        self.emit_event(event_data)

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded)
        # Buffer raw event dicts instead of rendered strings
        self._event_dicts: list[dict[str, Any]] = []
        # Per-computer RecordID counters persist across flushes
        self._record_id_counters: dict[str, int] = {}

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Buffer a Windows Event dict for deferred rendering.

        In threaded mode, posts dict to the queue. In non-threaded mode,
        adds to the local dict buffer directly.
        """
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
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return self._template.render(**event_data)

    def _run(self) -> None:
        """Thread run loop — buffers dicts from queue instead of rendering.

        Overrides base class to route events through the dict buffer
        for deferred rendering with correct RecordID assignment.
        """
        from queue import Empty
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"Emitter thread started for {self.format_def.name}")

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
                    logger.debug(f"Flushing {self.format_def.name} emitter at barrier")
                    self.flush()
                    self._flush_barrier.clear()

        # Final flush before thread exits
        logger.debug(f"Emitter thread stopping for {self.format_def.name}, final flush")
        self.flush()
        logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _flush_unlocked(self) -> None:
        """Sort events chronologically, assign RecordIDs, render, and write.

        1. Sort buffered dicts by TimeCreated
        2. Assign per-computer EventRecordIDs in sorted order
           (counters persist across flushes for continuity)
        3. Render each event to XML via Jinja2 template
        4. Write to disk via parent class machinery
        """
        if not self._event_dicts:
            return

        # Sort by timestamp (datetime objects sort naturally)
        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            if isinstance(ts, datetime):
                return ts
            return ts  # string timestamps sort lexicographically (ISO 8601)

        self._event_dicts.sort(key=_sort_key)

        # Assign per-computer EventRecordIDs in sorted order
        for event in self._event_dicts:
            computer = event.get("Computer", "")
            # Strip FQDN for counter key (bare hostname)
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                # System-role-aware offset: DCs have much higher event volumes
                # Use deterministic seed (not Python's randomized hash)
                rng = random.Random(f"erid_{counter_key}")
                key_lower = counter_key.lower()
                if 'dc' in key_lower:
                    self._record_id_counters[counter_key] = rng.randint(5_000_000, 15_000_000)
                elif any(x in key_lower for x in ('srv', 'server', 'web', 'file', 'db', 'mail', 'exch')):
                    self._record_id_counters[counter_key] = rng.randint(50_000, 550_000)
                else:
                    self._record_id_counters[counter_key] = rng.randint(5_000, 55_000)
            # Realistic gaps: other event channels and filtered events create
            # non-sequential record IDs in real Windows Security logs
            gap_rng = random.Random(f"erid_gap_{counter_key}_{self._record_id_counters[counter_key]}")
            if gap_rng.random() < 0.15:
                # 15% chance of small gap (1-8 missing events from other channels)
                self._record_id_counters[counter_key] += gap_rng.randint(2, 8)
            elif gap_rng.random() < 0.03:
                # 3% chance of larger gap (log rotation, batch system events)
                self._record_id_counters[counter_key] += gap_rng.randint(20, 200)
            else:
                self._record_id_counters[counter_key] += 1
            event["EventRecordID"] = self._record_id_counters[counter_key]

        # Render to XML strings and transfer to parent's string buffer
        for event in self._event_dicts:
            rendered = self._render_event(event)
            self.buffer.append(rendered)
            self.event_count += 1

        self._event_dicts.clear()

        # Delegate actual file writing to parent
        super()._flush_unlocked()
