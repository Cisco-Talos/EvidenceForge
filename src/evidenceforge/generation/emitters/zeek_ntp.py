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

"""Zeek ntp.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekNtpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ntp.log format (NDJSON).

    Generates NTP protocol logs. Shares conn.log UID via NetworkContext.
    """

    _log_filename = "ntp.json"
    _flat_filename = "zeek_ntp.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.ntp is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        ntp = event.ntp
        event_data: dict[str, Any] = {
            "ts": event.timestamp,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "version": ntp.version,
            "mode": ntp.mode,
            "stratum": ntp.stratum,
            "poll": ntp.poll,
            "precision": ntp.precision,
            "root_delay": ntp.root_delay,
            "root_disp": ntp.root_disp,
            "ref_id": ntp.ref_id,
            "ref_time": ntp.ref_ts,
            "org_time": ntp.org_ts,
            "rec_time": ntp.rec_ts,
            "xmt_time": ntp.xmt_ts,
            "num_exts": ntp.num_exts,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
