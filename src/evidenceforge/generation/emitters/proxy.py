"""HTTP/HTTPS forward proxy access log emitter (W3C Extended format)."""

from typing import Any

from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class ProxyEmitter(HostMultiplexEmitter):
    """Emitter for forward proxy access logs (W3C Extended Log Format).

    Per-host FQDN directory routing: each proxy server gets its own access log.
    """

    _log_filename = "proxy_access.log"
    _supported_types: set[str] = set()  # raw-only via generate_raw()

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route proxy access event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop('_host_fqdn', '')
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render proxy access log entry in W3C Extended format."""
        context = {
            'timestamp': event_data.get('timestamp'),
            'client_ip': event_data.get('client_ip'),
            'username': event_data.get('username'),
            'method': event_data.get('method'),
            'url': event_data.get('url'),
            'status_code': event_data.get('status_code'),
            'sc_bytes': event_data.get('sc_bytes'),
            'cs_bytes': event_data.get('cs_bytes'),
            'time_taken': event_data.get('time_taken'),
            'user_agent': event_data.get('user_agent'),
            'host': event_data.get('host'),
            'content_type': event_data.get('content_type'),
            'cache_result': event_data.get('cache_result'),
        }
        rendered = self._template.render(**context)
        return rendered.strip()
