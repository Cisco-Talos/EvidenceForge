"""Web server access log emitter."""

from typing import Any

from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class WebEmitter(HostMultiplexEmitter):
    """Emitter for W3C web server access logs (Apache/Nginx Combined Log Format).

    Per-host FQDN directory routing: each web server gets its own access log.
    """

    _log_filename = "web_access.log"
    _supported_types: set[str] = set()

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route web access event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop('_host_fqdn', '')
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render web access log entry.

        Format: <client_ip> - <username> [<timestamp>] "<method> <path> <protocol>" <status> <bytes> "<referer>" "<user_agent>"
        """
        context = {
            'timestamp': event_data.get('timestamp'),
            'client_ip': event_data.get('client_ip'),
            'username': event_data.get('username'),
            'method': event_data.get('method'),
            'path': event_data.get('path'),
            'protocol': event_data.get('protocol'),
            'status_code': event_data.get('status_code'),
            'bytes_sent': event_data.get('bytes_sent'),
            'referer': event_data.get('referer'),
            'user_agent': event_data.get('user_agent')
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()
