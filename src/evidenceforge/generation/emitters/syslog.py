"""Syslog emitter for Linux system logs.

Renders syslog-format entries from SyslogContext on SecurityEvent.
All syslog message construction is done by ActivityGenerator — the emitter
just formats the context fields into the syslog template.
"""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class SyslogEmitter(HostMultiplexEmitter):
    """Emitter for Linux syslog format.

    Per-host FQDN directory routing: each Linux host gets its own syslog.log.
    Renders any SecurityEvent that carries a SyslogContext on a Linux host.
    """

    _log_filename = "syslog.log"
    _flat_filename = "syslog.log"
    _sort_flat_file = True

    # Context-driven: handles any event type that carries SyslogContext
    _supported_types: set[str] = set()

    def can_handle(self, event: SecurityEvent) -> bool:
        """Syslog emitter handles any event with SyslogContext on a Linux host."""
        return (
            event.syslog is not None
            and event.host is not None
            and event.host.os_category == "linux"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Render syslog entry from SyslogContext."""
        if event.syslog is None:
            raise NotImplementedError(
                f"SyslogEmitter: event has no SyslogContext (event_type={event.event_type})"
            )
        ctx = event.syslog
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname,
            "app_name": ctx.app_name,
            "pid": ctx.pid,
            "facility": ctx.facility,
            "severity": ctx.severity,
            "message": ctx.message,
            "_host_fqdn": event.host.fqdn or event.host.hostname,
        }
        self.emit_event(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route syslog event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        ts = event_data.get("timestamp")
        if isinstance(ts, str):
            from evidenceforge.utils.time import parse_iso8601

            ts = parse_iso8601(ts)
        context = {
            "timestamp": ts,
            "hostname": event_data.get("hostname"),
            "facility": event_data.get("facility"),
            "severity": event_data.get("severity"),
            "app_name": event_data.get("app_name"),
            "pid": event_data.get("pid"),
            "message": event_data.get("message"),
        }
        rendered = self._template.render(**context)
        return rendered.strip()
