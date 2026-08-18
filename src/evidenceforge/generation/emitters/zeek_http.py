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

"""Zeek http.log emitter."""

from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.generation.emitters.zeek_base import (
    SensorMultiplexEmitter,
    direct_zeek_source_time,
    zeek_format_observed,
)
from evidenceforge.generation.network_observation import network_source_timing_key


def _file_vectors(
    http: Any, side: str
) -> tuple[list[str] | None, list[str] | None, list[str] | None]:
    """Return one side's Zeek HTTP file vectors when file IDs are visible."""

    fuids = list(getattr(http, f"{side}_fuids", []) or [])
    if not fuids:
        return None, None, None
    filenames = list(getattr(http, f"{side}_filenames", []) or [])
    mime_types = list(getattr(http, f"{side}_mime_types", []) or [])
    return (
        fuids,
        filenames or None,
        mime_types or None,
    )


class ZeekHttpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek http.log format (NDJSON).

    Generates HTTP request/response logs. Requires both NetworkTransactionPlan and HttpContext.
    Shares conn.log UID via event.network.zeek_uid.
    """

    _log_filename = "http.json"
    _flat_filename = "zeek_http.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        if event.event_type not in self._supported_types:
            return False
        if event.network is None or event.protocol.http is None:
            return False
        # Standard Zeek cannot inspect TLS-encrypted traffic — only emit
        # http.log for unencrypted HTTP connections
        if event.network.service == "ssl" or (
            event.network.dst_port == 443 and event.network.service != "http"
        ):
            return False
        return True

    def emit(self, event: CanonicalOccurrence) -> None:
        net = event.network
        http = event.protocol.http
        orig_fuids, orig_filenames, orig_mime_types = _file_vectors(http, "orig")
        resp_fuids, resp_filenames, resp_mime_types = _file_vectors(http, "resp")
        any_fuids = bool(orig_fuids or resp_fuids)
        timing_key = network_source_timing_key("zeek_http")
        event_ts = (
            http.canonical_request_time or net.started_at
            if event.network_observations_planned
            else direct_zeek_source_time(event, timing_key)
        )
        if any_fuids and not zeek_format_observed(event, "zeek_files"):
            orig_fuids = None
            orig_filenames = None
            orig_mime_types = None
            resp_fuids = None
            resp_filenames = None
            resp_mime_types = None
        event_data: dict[str, Any] = {
            "ts": event_ts,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "trans_depth": http.trans_depth,
            "method": http.method,
            "host": http.host,
            "uri": http.uri,
            "version": http.version or None,
            "user_agent": http.user_agent or None,
            "request_body_len": http.request_body_len,
            "response_body_len": http.response_body_len,
            "status_code": http.status_code,
            "status_msg": http.status_msg,
            "tags": http.tags if http.tags else None,
            "referrer": http.referrer or None,
            "orig_fuids": orig_fuids,
            "orig_filenames": orig_filenames,
            "orig_mime_types": orig_mime_types,
            "resp_fuids": resp_fuids,
            "resp_filenames": resp_filenames,
            "resp_mime_types": resp_mime_types,
            "_source_timing_key": timing_key,
            **self._sensor_metadata(event, self.format_def.name),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "version",
            "user_agent",
            "tags",
            "referrer",
            "orig_fuids",
            "orig_filenames",
            "orig_mime_types",
            "resp_fuids",
            "resp_filenames",
            "resp_mime_types",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
