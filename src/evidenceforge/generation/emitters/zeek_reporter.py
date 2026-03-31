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

"""Zeek reporter.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekReporterEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek reporter.log format (NDJSON).

    Handles sensor_startup events and raw dict rendering for backward compat.
    """

    _log_filename = "reporter.json"
    _flat_filename = "zeek_reporter.json"
    _supported_types: set[str] = {"sensor_startup"}

    def emit(self, event: SecurityEvent) -> None:
        """Render sensor startup reporter.log entries."""
        if event.event_type != "sensor_startup":
            return
        hostname = event.src_host.hostname if event.src_host else "unknown"
        # Reporter startup messages are stored in shell.command field
        level = "Reporter::INFO"
        message = ""
        if event.shell:
            # Format: "level|message"
            parts = event.shell.command.split("|", 1)
            if len(parts) == 2:
                level, message = parts
            else:
                message = event.shell.command
        event_data = {
            "ts": event.timestamp,
            "level": level,
            "message": message,
            "location": "",
            "_sensor_hostnames": [hostname],
        }
        rendered = self._render_event(event_data)
        if rendered:
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
