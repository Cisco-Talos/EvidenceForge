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

"""Cisco ASA firewall syslog emitter.

Renders ASA-format syslog entries for connection events observed by firewall
sensors. Produces Built/Teardown pairs for permitted connections and Deny
records for blocked connections.

Per-sensor directory routing: each firewall sensor gets its own cisco_asa.log.
"""

import ipaddress
from datetime import timedelta
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter

# ASA facility: local4 (20)
_ASA_FACILITY = 20

# Teardown reason strings weighted by likelihood
_TEARDOWN_REASONS = [
    "TCP FINs",
    "TCP FINs",
    "TCP FINs",
    "TCP Reset-O",
    "TCP Reset-I",
    "Conn-timeout",
    "SYN Timeout",
]


class CiscoAsaEmitter(SensorMultiplexEmitter):
    """Emitter for Cisco ASA firewall syslog format.

    Per-sensor directory routing: each firewall sensor gets its own log file.

    Handles all connection events visible to firewall sensors. Unlike Snort
    (which requires IdsContext), the ASA emitter renders every connection it
    sees -- either as a permit (Built/Teardown) or deny (Deny) record.
    """

    _log_filename = "cisco_asa.log"
    _flat_filename = "cisco_asa.log"
    _supported_types: set[str] = {"connection"}

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        sensor_hostnames: list[str] | None = None,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded, sensor_hostnames)
        # Per-sensor monotonically increasing connection ID counter
        self._conn_id_counters: dict[str, int] = {}
        # Network segment config for interface resolution (set by emitter_setup)
        self._segment_config: list[dict[str, str]] = []
        # Per-sensor interface mappings (set by emitter_setup)
        self._sensor_interfaces: dict[str, dict[str, str]] = {}

    def _next_conn_id(self, sensor_hostname: str) -> int:
        """Get next monotonically increasing connection ID for a sensor."""
        current = self._conn_id_counters.get(sensor_hostname, 100000)
        self._conn_id_counters[sensor_hostname] = current + 1
        return current

    def _resolve_interface(self, ip: str, sensor_hostname: str) -> str:
        """Resolve an IP address to an ASA interface name.

        Looks up which segment the IP belongs to, then maps the segment name
        to an interface name via the sensor's interfaces dict. Falls back to
        segment name, then "outside" for unknown IPs.
        """
        interfaces = self._sensor_interfaces.get(sensor_hostname, {})
        for seg in self._segment_config:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(seg["cidr"], strict=False):
                    seg_name = seg["name"]
                    return interfaces.get(seg_name, seg_name)
            except (ValueError, KeyError):
                continue
        return interfaces.get("_default", "outside")

    @staticmethod
    def _pri(severity: int) -> int:
        """Calculate syslog priority from ASA severity."""
        return _ASA_FACILITY * 8 + severity

    @staticmethod
    def _format_duration(seconds: float | None) -> str:
        """Format duration as H:MM:SS."""
        if seconds is None or seconds <= 0:
            return "0:00:00"
        td = timedelta(seconds=int(seconds))
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        secs = total_seconds % 60
        return f"{hours}:{minutes:02d}:{secs:02d}"

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle all connection events with network context."""
        return event.event_type in self._supported_types and event.network is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render ASA syslog records from a connection event.

        For permitted connections: emits a Built record + Teardown record.
        For denied connections: emits a single Deny record.
        """
        net = event.network
        if net is None:
            return

        fw = event.firewall
        is_deny = fw is not None and fw.action == "deny"
        protocol = (net.protocol or "tcp").lower()

        # Get sensor routing from visibility metadata
        sensor_hosts: list[str] = []
        if hasattr(event, "_sensor_hostnames_by_format"):
            sensor_hosts = event._sensor_hostnames_by_format.get("cisco_asa", [])
        if not sensor_hosts:
            sensor_hosts = self._sensor_hostnames or [""]

        for sensor_hostname in sensor_hosts:
            src_iface = self._resolve_interface(net.src_ip, sensor_hostname)
            dst_iface = self._resolve_interface(net.dst_ip, sensor_hostname)
            conn_id = self._next_conn_id(sensor_hostname)
            fw_hostname = sensor_hostname or "fw01"

            if is_deny:
                self._emit_deny(event, net, fw, src_iface, dst_iface, sensor_hostname, fw_hostname)
            else:
                self._emit_built(
                    event,
                    net,
                    protocol,
                    conn_id,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                )
                self._emit_teardown(
                    event,
                    net,
                    protocol,
                    conn_id,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                )

    def _emit_built(
        self,
        event: SecurityEvent,
        net: Any,
        protocol: str,
        conn_id: int,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a Built connection record (302013/302015/302020)."""
        # Determine direction: if src is "outside", it's inbound
        direction = "inbound" if src_iface == "outside" else "outbound"

        if protocol == "icmp":
            msg_id = 302020
            icmp_type = net.dst_port if net.dst_port else 8  # Default echo request
            message = (
                f"Built {direction} ICMP connection for faddr "
                f"{dst_iface}:{net.dst_ip}/{icmp_type} "
                f"gaddr {src_iface}:{net.src_ip}/0 "
                f"laddr {src_iface}:{net.src_ip}/0"
            )
        else:
            msg_id = 302013 if protocol == "tcp" else 302015
            proto_upper = protocol.upper()
            message = (
                f"Built {direction} {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} "
                f"({net.src_ip}/{net.src_port}) to "
                f"{dst_iface}:{net.dst_ip}/{net.dst_port} "
                f"({net.dst_ip}/{net.dst_port})"
            )

        event_data = {
            "timestamp": event.timestamp,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": msg_id,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _emit_teardown(
        self,
        event: SecurityEvent,
        net: Any,
        protocol: str,
        conn_id: int,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a Teardown connection record (302014/302016/302021)."""
        duration = self._format_duration(net.duration)
        total_bytes = (net.orig_bytes or 0) + (net.resp_bytes or 0)
        teardown_ts = event.timestamp
        if net.duration and net.duration > 0:
            teardown_ts = event.timestamp + timedelta(seconds=net.duration)

        if protocol == "icmp":
            msg_id = 302021
            icmp_type = net.dst_port if net.dst_port else 8
            message = (
                f"Teardown ICMP connection for faddr "
                f"{dst_iface}:{net.dst_ip}/{icmp_type} "
                f"gaddr {src_iface}:{net.src_ip}/0 "
                f"laddr {src_iface}:{net.src_ip}/0"
            )
        else:
            msg_id = 302014 if protocol == "tcp" else 302016
            proto_upper = protocol.upper()
            # Pick a realistic teardown reason
            import hashlib

            reason_idx = int(hashlib.md5(f"{conn_id}".encode()).hexdigest()[:4], 16) % len(
                _TEARDOWN_REASONS
            )
            reason = _TEARDOWN_REASONS[reason_idx] if protocol == "tcp" else ""
            message = (
                f"Teardown {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} to "
                f"{dst_iface}:{net.dst_ip}/{net.dst_port} "
                f"duration {duration} bytes {total_bytes}"
            )
            if reason:
                message += f" {reason}"

        event_data = {
            "timestamp": teardown_ts,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": msg_id,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _emit_deny(
        self,
        event: SecurityEvent,
        net: Any,
        fw: Any,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a Deny record (106023)."""
        protocol = (net.protocol or "tcp").lower()
        acl_name = (fw.access_group if fw else "") or "outside_access_in"

        if protocol == "icmp":
            icmp_type = net.dst_port if net.dst_port else 8
            icmp_code = 0
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip} "
                f"dst {dst_iface}:{net.dst_ip} "
                f"(type {icmp_type}, code {icmp_code}) "
                f'by access-group "{acl_name}" [0x0, 0x0]'
            )
        else:
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip}/{net.src_port} "
                f"dst {dst_iface}:{net.dst_ip}/{net.dst_port} "
                f'by access-group "{acl_name}" [0x0, 0x0]'
            )

        event_data = {
            "timestamp": event.timestamp,
            "hostname": fw_hostname,
            "severity": 4,
            "msg_id": 106023,
            "message": message,
            "pri": self._pri(4),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Render and route to sensor writers.

        Overrides the base class _dispatch to skip Zeek UID derivation
        (firewalls don't use UIDs).
        """
        sensor_hostnames = event_data.pop("_sensor_hostnames", None)
        rendered = self._render_event(event_data)
        if rendered is None:
            return
        self.emit_to_sensors(rendered, sensor_hostnames)

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render ASA syslog line via Jinja2 template."""
        context = {
            "timestamp": event_data.get("timestamp"),
            "hostname": event_data.get("hostname"),
            "severity": event_data.get("severity"),
            "msg_id": event_data.get("msg_id"),
            "message": event_data.get("message"),
            "pri": event_data.get("pri"),
        }
        rendered = self._template.render(**context)
        return rendered.strip()
