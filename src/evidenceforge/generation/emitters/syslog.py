# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Syslog emitter for Linux system logs.

Renders syslog-format entries from SyslogContext on SecurityEvent.
All syslog message construction is done by ActivityGenerator — the emitter
just formats the context fields into the syslog template.
"""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
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
        return event.syslog is not None and self._linux_host(event) is not None

    @staticmethod
    def _linux_host(event: SecurityEvent) -> "HostContext | None":
        """Return the Linux host that owns the syslog event.

        For logon events, SyslogContext is attached to the destination host
        (target of the authentication), so prefer ``dst_host`` to ensure
        per-host routing writes to the correct host directory.
        """
        if event.event_type == "logon":
            if event.dst_host and event.dst_host.os_category == "linux":
                return event.dst_host
            if event.src_host and event.src_host.os_category == "linux":
                return event.src_host
            return None

        if event.src_host and event.src_host.os_category == "linux":
            return event.src_host
        if event.dst_host and event.dst_host.os_category == "linux":
            return event.dst_host
        return None

    def emit(self, event: SecurityEvent) -> None:
        """Render syslog entry from SyslogContext."""
        if event.syslog is None:
            raise NotImplementedError(
                f"SyslogEmitter: event has no SyslogContext (event_type={event.event_type})"
            )
        host = self._linux_host(event)
        ctx = event.syslog
        event_data = {
            "timestamp": event.timestamp,
            "hostname": host.hostname if host else "",
            "app_name": ctx.app_name,
            "pid": ctx.pid,
            "facility": ctx.facility,
            "severity": ctx.severity,
            "message": ctx.message,
            "_host_fqdn": (host.fqdn or host.hostname) if host else "",
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
