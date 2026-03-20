"""Syslog emitter for Linux system logs."""

import random
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter


class SyslogEmitter(LogEmitter):
    """Emitter for Linux syslog format."""

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

    def _render_logon(self, event: SecurityEvent) -> None:
        """Render syslog authentication message for successful logon."""
        rng = random.Random()
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10,  # authpriv
            'severity': 6,   # info
            'app_name': 'sshd' if auth.logon_type == 3 else 'login',
            'pid': rng.randint(1000, 9999),
            'message': (
                f'Accepted password for {auth.username} from {auth.source_ip} '
                f'port {rng.randint(49152, 65535)}'
            ),
        }
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render syslog session closed message."""
        rng = random.Random()
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10,  # authpriv
            'severity': 6,   # info
            'app_name': 'sshd' if auth.logon_type == 3 else 'login',
            'pid': rng.randint(1000, 9999),
            'message': f'session closed for user {auth.username}',
        }
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render syslog 'Failed password' message."""
        rng = random.Random()
        auth = event.auth
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10,  # authpriv
            'severity': 4,   # warning
            'app_name': 'sshd' if auth.logon_type == 3 else 'login',
            'pid': rng.randint(1000, 9999),
            'message': (
                f'Failed password for {auth.username} from {auth.source_ip} '
                f'port {rng.randint(49152, 65535)} ssh2'
            ),
        }
        self.emit_event(event_data)

    def _render_system_process(self, event: SecurityEvent) -> None:
        """Render syslog message for system/daemon process start."""
        proc = event.process
        app_name = proc.image.split('/')[-1]
        facility = 9 if 'cron' in proc.command_line.lower() else 3  # cron or daemon
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'app_name': app_name,
            'pid': proc.pid,
            'facility': facility,
            'severity': 6,
            'message': f'{app_name}[{proc.pid}]: started: {proc.command_line}',
        }
        self.emit_event(event_data)

    def _render_ssh_session(self, event: SecurityEvent) -> None:
        """Render syslog auth message for SSH session establishment."""
        rng = random.Random()
        auth = event.auth
        net = event.network
        event_data = {
            'timestamp': event.timestamp,
            'hostname': event.host.hostname,
            'facility': 10,  # authpriv
            'severity': 6,   # info
            'app_name': 'sshd',
            'pid': rng.randint(5000, 60000),
            'message': (
                f'Accepted password for {auth.username} from {net.src_ip} '
                f'port {net.src_port} ssh2'
            ),
        }
        self.emit_event(event_data)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Route to threaded or non-threaded path."""
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            rendered = self._render_event(event_data)
            self._buffer_event(rendered)

    def flush(self) -> None:
        """Flush with chronological sorting (syslog is append-only/ordered)."""
        with self._file_lock:
            self.buffer.sort()  # ISO timestamp prefix → lexicographic sort works
            self._flush_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render syslog event to text format.

        Format: <timestamp> <hostname> <app>[<pid>]: <message>
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'hostname': event_data.get('hostname'),
            'facility': event_data.get('facility'),
            'severity': event_data.get('severity'),
            'app_name': event_data.get('app_name'),
            'pid': event_data.get('pid'),
            'message': event_data.get('message')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
