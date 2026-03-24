"""Syslog emitter for Linux system logs."""

import random
from datetime import timedelta
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class SyslogEmitter(HostMultiplexEmitter):
    """Emitter for Linux syslog format.

    Per-host FQDN directory routing: each Linux host gets its own syslog.log.
    """

    _log_filename = "syslog.log"
    _flat_filename = "syslog.log"
    _sort_flat_file = True

    _supported_types: set[str] = {"logon", "logoff", "failed_logon", "system_process_create", "ssh_session"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Syslog emitter handles events on Linux hosts."""
        return (
            event.event_type in self._supported_types
            and event.host is not None
            and event.host.os_category == "linux"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        renderer = {
            "logon": self._render_logon,
            "logoff": self._render_logoff,
            "failed_logon": self._render_failed_logon,
            "system_process_create": self._render_system_process,
            "ssh_session": self._render_ssh_session,
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(
                f"SyslogEmitter: no render method for {event.event_type}"
            )
        renderer(event)

    def _get_host_fqdn(self, event: SecurityEvent) -> str:
        if event.host:
            return event.host.fqdn or event.host.hostname
        return ''

    def _session_pid(self, logon_id: str) -> int:
        """Derive a stable sshd PID from a session's logon ID."""
        return 1000 + (hash(logon_id) % 59000)

    def _render_logon(self, event: SecurityEvent) -> None:
        rng = random.Random()
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10, 'severity': 6,
            'app_name': 'sshd',
            'pid': self._session_pid(auth.logon_id),
            'message': (
                f'Accepted password for {auth.username} from {auth.source_ip} '
                f'port {rng.randint(49152, 65535)}'
            ),
            '_host_fqdn': self._get_host_fqdn(event),
        }
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10, 'severity': 6,
            'app_name': 'sshd',
            'pid': self._session_pid(auth.logon_id),
            'message': f'session closed for user {auth.username}',
            '_host_fqdn': self._get_host_fqdn(event),
        }
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        rng = random.Random()
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10, 'severity': 4,
            'app_name': 'sshd',
            'pid': self._session_pid(auth.logon_id) if auth.logon_id else rng.randint(5000, 60000),
            'message': (
                f'Failed password for {auth.username} from {auth.source_ip} '
                f'port {rng.randint(49152, 65535)} ssh2'
            ),
            '_host_fqdn': self._get_host_fqdn(event),
        }
        self.emit_event(event_data)

    def _render_system_process(self, event: SecurityEvent) -> None:
        proc = event.process
        # Detect CRON processes: parent is cron daemon or image is cron
        is_cron = (
            'cron' in (proc.parent_image or '').lower()
            or proc.image in ('/usr/sbin/cron', '/usr/sbin/crond')
        )
        if is_cron:
            # CRON format: CRON[pid]: (user) CMD (command)
            event_data = {
                'timestamp': event.timestamp,
                'hostname': event.host.hostname,
                'app_name': 'CRON',
                'pid': proc.pid,
                'facility': 9, 'severity': 6,
                'message': f'({proc.username}) CMD ({proc.command_line})',
                '_host_fqdn': self._get_host_fqdn(event),
            }
        else:
            app_name = proc.image.split('/')[-1]
            event_data = {
                'timestamp': event.timestamp,
                'hostname': event.host.hostname,
                'app_name': app_name,
                'pid': proc.pid,
                'facility': 3, 'severity': 6,
                'message': f'started: {proc.command_line}',
                '_host_fqdn': self._get_host_fqdn(event),
            }
        self.emit_event(event_data)

    def _render_ssh_session(self, event: SecurityEvent) -> None:
        rng = random.Random()
        auth = event.auth
        net = event.network
        sshd_pid = self._session_pid(auth.logon_id or str(hash(f"{auth.username}{event.timestamp}")))
        host_fqdn = self._get_host_fqdn(event)
        hostname = event.host.hostname
        session_id = rng.randint(100, 99999)

        # 1. sshd: Accepted password
        self.emit_event({
            'timestamp': event.timestamp,
            'hostname': hostname,
            'facility': 10, 'severity': 6,
            'app_name': 'sshd',
            'pid': sshd_pid,
            'message': (
                f'Accepted password for {auth.username} from {net.src_ip} '
                f'port {net.src_port} ssh2'
            ),
            '_host_fqdn': host_fqdn,
        })

        # 2. sshd: pam_unix session opened
        ts_pam = event.timestamp + timedelta(microseconds=rng.randint(1000, 50000))
        self.emit_event({
            'timestamp': ts_pam,
            'hostname': hostname,
            'facility': 10, 'severity': 6,
            'app_name': 'sshd',
            'pid': sshd_pid,
            'message': (
                f'pam_unix(sshd:session): session opened for user {auth.username}'
                f' by (uid=0)'
            ),
            '_host_fqdn': host_fqdn,
        })

        # 3. systemd-logind: New session
        ts_logind = ts_pam + timedelta(microseconds=rng.randint(1000, 30000))
        self.emit_event({
            'timestamp': ts_logind,
            'hostname': hostname,
            'facility': 10, 'severity': 6,
            'app_name': 'systemd-logind',
            'pid': self._session_pid('logind'),
            'message': f'New session {session_id} of user {auth.username}.',
            '_host_fqdn': host_fqdn,
        })

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route syslog event to both centralized and per-host files."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop('_host_fqdn', '')
        # Always write to centralized syslog.log
        self.emit_to_host(rendered, '')
        # Also write to per-host file if host FQDN is set
        if host_fqdn:
            self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        context = {
            'timestamp': event_data.get('timestamp'),
            'hostname': event_data.get('hostname'),
            'facility': event_data.get('facility'),
            'severity': event_data.get('severity'),
            'app_name': event_data.get('app_name'),
            'pid': event_data.get('pid'),
            'message': event_data.get('message')
        }
        rendered = self._template.render(**context)
        return rendered.strip()
