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

from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter, zeek_format_observed
from evidenceforge.generation.source_timing import SourceTimingPlanner

_MIN_HTTP_TRANSACTION_TIMESTAMP_GAP = timedelta(milliseconds=1)
_MIN_HTTP_FILE_TIMESTAMP_GAP = timedelta(milliseconds=2)
_SOURCE_TIMING = SourceTimingPlanner()


def _response_file_vectors(http: Any) -> tuple[list[str] | None, list[str] | None]:
    """Return Zeek HTTP response file vectors only when file IDs are visible."""
    resp_fuids = list(getattr(http, "resp_fuids", []) or [])
    if not resp_fuids:
        return None, None
    resp_mime_types = list(getattr(http, "resp_mime_types", []) or [])
    if len(resp_mime_types) == len(resp_fuids):
        return resp_fuids, resp_mime_types
    if len(resp_mime_types) == 1:
        return resp_fuids, resp_mime_types * len(resp_fuids)
    return resp_fuids, None


class ZeekHttpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek http.log format (NDJSON).

    Generates HTTP request/response logs. Requires both NetworkContext and HttpContext.
    Shares conn.log UID via event.network.zeek_uid.
    """

    _log_filename = "http.json"
    _flat_filename = "zeek_http.json"
    _supported_types: set[str] = {"connection"}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._last_http_ts_by_uid: dict[tuple[str, str, int, str, int], datetime] = {}
        self._conn_bounds_by_uid: dict[
            tuple[str, str, int, str, int], tuple[datetime, datetime | None]
        ] = {}

    def can_handle(self, event: SecurityEvent) -> bool:
        if event.event_type not in self._supported_types:
            return False
        if event.network is None or event.http is None:
            return False
        # Standard Zeek cannot inspect TLS-encrypted traffic — only emit
        # http.log for unencrypted HTTP connections
        if event.network.service == "ssl" or (
            event.network.dst_port == 443 and event.network.service != "http"
        ):
            return False
        return True

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        http = event.http
        uid_key = (net.zeek_uid, net.src_ip, net.src_port, net.dst_ip, net.dst_port)
        conn_ts = _SOURCE_TIMING.source_time(
            event,
            "source.zeek_conn_start",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
            not_before=event.timestamp,
        )
        within = None
        latest_ts = None
        resp_fuids, resp_mime_types = _response_file_vectors(http)
        if net.duration is not None and net.duration > 0:
            tail_gap = _MIN_HTTP_FILE_TIMESTAMP_GAP if resp_fuids else timedelta(microseconds=1)
            latest_ts = conn_ts + timedelta(seconds=max(0.0, net.duration)) - tail_gap
            if latest_ts < conn_ts:
                latest_ts = conn_ts
            within = (conn_ts, latest_ts)
        cached_bounds = self._conn_bounds_by_uid.get(uid_key)
        if cached_bounds is not None:
            conn_ts, latest_ts = cached_bounds
            if resp_fuids and latest_ts is not None:
                reserve = _MIN_HTTP_FILE_TIMESTAMP_GAP - timedelta(microseconds=1)
                latest_ts = max(conn_ts, latest_ts - reserve)
            within = (conn_ts, latest_ts) if latest_ts is not None else None
        else:
            self._conn_bounds_by_uid[uid_key] = (conn_ts, latest_ts)
        http_seed_parts = (
            net.zeek_uid,
            net.src_ip,
            net.src_port,
            net.dst_ip,
            net.dst_port,
            event.timestamp,
        )
        event_ts = _SOURCE_TIMING.source_time(
            event,
            "source.zeek_http_request",
            seed_parts=http_seed_parts,
            not_before=conn_ts,
            within=within,
        )
        previous_ts = self._last_http_ts_by_uid.get(uid_key)
        if previous_ts is not None and event_ts <= previous_ts:
            event_ts = previous_ts + _MIN_HTTP_TRANSACTION_TIMESTAMP_GAP
        if latest_ts is not None and event_ts > latest_ts:
            event_ts = latest_ts
        self._last_http_ts_by_uid[uid_key] = event_ts
        _SOURCE_TIMING.record_source_time(
            event,
            "source.zeek_http_request",
            event_ts,
            seed_parts=http_seed_parts,
        )
        if resp_fuids and not zeek_format_observed(event, "zeek_files"):
            resp_fuids = None
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
            "resp_fuids": resp_fuids,
            "resp_mime_types": resp_mime_types,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "version",
            "user_agent",
            "tags",
            "referrer",
            "resp_fuids",
            "resp_mime_types",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
