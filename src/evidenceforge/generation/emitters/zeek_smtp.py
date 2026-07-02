# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Zeek smtp.log emitter."""

import json
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter, zeek_format_observed
from evidenceforge.generation.source_timing import SourceTimingPlanner

_SOURCE_TIMING = SourceTimingPlanner()


class ZeekSmtpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek smtp.log format (NDJSON)."""

    _log_filename = "smtp.json"
    _flat_filename = "zeek_smtp.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.smtp is not None
            and event.network.service == "smtp"
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        smtp = event.smtp
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
        if net.duration is not None and net.duration > 0:
            latest = conn_ts + timedelta(seconds=max(0.0, net.duration)) - timedelta(microseconds=1)
            within = (conn_ts, max(conn_ts, latest))
        smtp_ts = _SOURCE_TIMING.source_time(
            event,
            "source.zeek_smtp_transaction",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
            not_before=conn_ts,
            within=within,
        )
        protected = smtp.encrypted_message
        fuids = smtp.fuids if smtp.fuids and zeek_format_observed(event, "zeek_files") else []
        event_data: dict[str, Any] = {
            "ts": smtp_ts,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "trans_depth": smtp.trans_depth,
            "helo": smtp.helo,
            "mailfrom": None if protected else smtp.mailfrom,
            "rcptto": None if protected else smtp.rcptto,
            "last_reply": None if protected else smtp.last_reply,
            "path": None if protected else smtp.path or [net.dst_ip, net.src_ip],
            "tls": smtp.tls,
            "date": None if protected else smtp.date,
            "from": None if protected else smtp.from_header,
            "to": None if protected else smtp.to_header,
            "msg_id": None if protected else smtp.msg_id,
            "subject": None if protected else smtp.subject,
            "user_agent": None if protected else smtp.user_agent,
            "fuids": None if protected or not fuids else fuids,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        for field in (
            "mailfrom",
            "rcptto",
            "last_reply",
            "path",
            "date",
            "from",
            "to",
            "msg_id",
            "subject",
            "user_agent",
            "fuids",
        ):
            event_data.setdefault(field, None)
        rendered: dict[str, Any] = {}
        for key, value in event_data.items():
            if key.startswith("_") or value is None:
                continue
            if key == "ts" and isinstance(value, datetime):
                rendered[key] = round(value.timestamp(), 6)
            else:
                rendered[key] = value
        return json.dumps(rendered, separators=(",", ":"))
