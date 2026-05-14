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

import hashlib
import ipaddress
import math
import re
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter

# ASA facility: local4 (20)
_ASA_FACILITY = 20

_TCP_SUCCESS_TEARDOWN_REASONS = ("TCP FINs", "TCP FINs", "TCP FINs", "TCP Reset-O", "TCP Reset-I")
_TCP_PARTIAL_TEARDOWN_REASONS = ("Conn-timeout", "TCP Reset-O", "TCP Reset-I")


def _asa_timestamp_sort_key(line: str) -> str:
    """Extract timestamp from ASA syslog line for chronological sorting.

    Format: <NNN>Mon DD HH:MM:SS hostname ...
    Returns the timestamp portion so entries sort chronologically
    regardless of message ID.
    """
    gt = line.find(">")
    if gt >= 0:
        return line[gt + 1 : gt + 16]
    return line


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
    _sort_before_flush = True
    _sort_key_func = staticmethod(_asa_timestamp_sort_key)

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        sensor_hostnames: list[str] | None = None,
    ):
        super().__init__(format_def, output_path, buffer_size, threaded, sensor_hostnames)
        # Per-sensor temporary connection ID counters. Final visible IDs are
        # normalized after sorted flush so they follow log order without
        # exposing timestamp buckets.
        self._conn_id_sequences: dict[str, int] = {}
        # Network segment config for interface resolution (set by emitter_setup)
        self._segment_config: list[dict[str, str]] = []
        # Per-sensor interface mappings (set by emitter_setup)
        self._sensor_interfaces: dict[str, dict[str, str]] = {}
        # VIP→real_ip for interface resolution (set by emitter_setup)
        self._vip_to_real_ip: dict[str, str] = {}
        self._output_end_time: datetime | None = None

        # Threat detection: per-(sensor, src_ip) deny rate tracking
        self._deny_timestamps: dict[tuple[str, str], deque[datetime]] = {}
        self._last_alert_time: dict[tuple[str, str], datetime | None] = {}
        # Configurable thresholds (ASA defaults for scanning detection)
        self._td_burst_threshold: int = 10  # drops/sec to trigger burst alert
        self._td_avg_threshold: int = 5  # drops/sec to trigger average alert
        self._td_burst_window: int = 20  # seconds for burst rate calculation
        self._td_avg_window: int = 60  # seconds for average rate calculation
        self._td_cooldown: int = 20  # seconds between re-firings (= burst period)

    def _next_conn_id(self, sensor_hostname: str, ts: Any = None) -> int:
        """Get a deterministic temporary ASA connection ID."""
        seed = int(hashlib.md5(sensor_hostname.encode()).hexdigest()[:8], 16)
        current = self._conn_id_sequences.get(sensor_hostname)
        if current is None:
            current = 1_000_000 + seed % 500_000
        gap = 1 + int(hashlib.md5(f"{sensor_hostname}:{current}".encode()).hexdigest()[:2], 16) % 5
        next_id = current + gap
        self._conn_id_sequences[sensor_hostname] = next_id
        return next_id

    def close(self) -> None:
        """Close all writers and normalize visible connection IDs once.

        Barrier flushes can happen many times during long generations. Keep
        them append-only, and defer the whole-file ID normalization until the
        final close after writers have performed their final global sort.
        """
        super().close()
        self._normalize_visible_connection_ids()

    def _normalize_visible_connection_ids(self) -> None:
        """Rewrite rendered ASA connection IDs in visible chronological order."""
        with self._writers_lock:
            writers = list(self._writers.items())
        for sensor_hostname, writer in writers:
            self._normalize_connection_ids_in_file(writer.output_path, sensor_hostname)

    @staticmethod
    def _normalize_connection_ids_in_file(path: Path, sensor_hostname: str) -> None:
        if not path.exists():
            return
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return

        seed = int(hashlib.md5(sensor_hostname.encode()).hexdigest()[:8], 16)
        current = 1_000_000 + seed % 500_000
        mapping: dict[str, int] = {}
        changed = False
        normalized: list[str] = []
        pattern = re.compile(r"(connection )(\d+)( for)")
        for line in lines:
            match = pattern.search(line)
            if match is None:
                normalized.append(line)
                continue
            old_id = match.group(2)
            if int(old_id) < 1_000_000:
                normalized.append(line)
                continue
            if old_id not in mapping:
                gap_seed = f"{sensor_hostname}:{current}:{len(mapping)}"
                gap = 1 + int(hashlib.md5(gap_seed.encode()).hexdigest()[:2], 16) % 5
                current += gap
                mapping[old_id] = current
            new_id = str(mapping[old_id])
            normalized.append(pattern.sub(rf"\g<1>{new_id}\g<3>", line, count=1))
            changed = changed or new_id != old_id
        if changed:
            path.write_text("\n".join(normalized) + "\n", encoding="utf-8")

    @staticmethod
    def _teardown_reason(net: Any, protocol: str, conn_id: int) -> str:
        """Choose an ASA teardown reason consistent with connection outcome."""
        if protocol != "tcp":
            return ""
        state = getattr(net, "conn_state", "") or ""
        payload_bytes = (getattr(net, "orig_bytes", 0) or 0) + (getattr(net, "resp_bytes", 0) or 0)
        if state in {"S0", "S1", "SH", "SHR"} and payload_bytes == 0:
            return "SYN Timeout"
        if state in {"REJ", "RSTO"}:
            return "TCP Reset-O"
        if state == "RSTR":
            return "TCP Reset-I"
        reasons = _TCP_SUCCESS_TEARDOWN_REASONS if payload_bytes else _TCP_PARTIAL_TEARDOWN_REASONS
        reason_idx = int(hashlib.md5(f"{conn_id}".encode()).hexdigest()[:4], 16) % len(reasons)
        return reasons[reason_idx]

    def _resolve_interface(self, ip: str, sensor_hostname: str) -> str:
        """Resolve an IP address to an ASA interface name.

        Looks up which segment the IP belongs to, then maps the segment name
        to an interface name via the sensor's interfaces dict. Falls back to
        segment name, then "outside" for unknown IPs.

        VIPs (public NAT addresses) are resolved via their real_ip's segment.
        """
        # Resolve VIP → real_ip for segment lookup
        lookup_ip = self._vip_to_real_ip.get(ip, ip) if self._vip_to_real_ip else ip
        interfaces = self._sensor_interfaces.get(sensor_hostname, {})
        for seg in self._segment_config:
            try:
                if ipaddress.ip_address(lookup_ip) in ipaddress.ip_network(
                    seg["cidr"], strict=False
                ):
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

    @staticmethod
    def _teardown_duration_seconds(net: Any, protocol: str, reason: str, conn_id: int) -> float:
        """Return teardown duration, including realistic SYN timeout waits."""
        duration = getattr(net, "duration", None)
        if protocol == "tcp" and reason == "SYN Timeout" and (duration is None or duration < 1):
            return float(15 + (conn_id % 31))
        return float(duration or 0)

    @staticmethod
    def _format_teardown_duration(net: Any, protocol: str, reason: str, conn_id: int) -> str:
        """Format teardown duration, including realistic SYN timeout waits."""
        seconds = CiscoAsaEmitter._teardown_duration_seconds(net, protocol, reason, conn_id)
        return CiscoAsaEmitter._format_duration(seconds)

    def _is_after_output_end(self, timestamp: datetime) -> bool:
        """Return whether a source-native timestamp falls beyond the collection window."""
        if self._output_end_time is None:
            return False
        ts = timestamp
        gate = self._output_end_time
        if ts.tzinfo is not None and gate.tzinfo is None:
            ts = ts.replace(tzinfo=None)
        elif ts.tzinfo is None and gate.tzinfo is not None:
            gate = gate.replace(tzinfo=None)
        return ts > gate

    @staticmethod
    def _teardown_byte_count(net: Any, protocol: str, conn_id: int) -> int:
        """Return ASA source-native byte accounting for a connection teardown."""
        orig_payload = getattr(net, "orig_bytes", 0) or 0
        resp_payload = getattr(net, "resp_bytes", 0) or 0
        payload_total = orig_payload + resp_payload
        if payload_total <= 0:
            return 0

        orig_ip_bytes = getattr(net, "orig_ip_bytes", None)
        resp_ip_bytes = getattr(net, "resp_ip_bytes", None)
        if orig_ip_bytes is not None or resp_ip_bytes is not None:
            base_total = (orig_ip_bytes or orig_payload) + (resp_ip_bytes or resp_payload)
        else:
            packet_total = (getattr(net, "orig_pkts", 0) or 0) + (getattr(net, "resp_pkts", 0) or 0)
            if packet_total <= 0:
                packet_total = max(1, math.ceil(payload_total / 1460))
                if protocol == "tcp":
                    packet_total += 2
            header_bytes = 28 if protocol in {"udp", "icmp"} else 40
            base_total = payload_total + packet_total * header_bytes

        variance_seed = (
            f"asa-bytes:{conn_id}:{getattr(net, 'src_ip', '')}:{getattr(net, 'dst_ip', '')}"
        )
        variance = int(hashlib.md5(variance_seed.encode()).hexdigest()[:4], 16) % 96
        if protocol == "tcp":
            variance += 20
        return max(payload_total + 1, int(base_total) + variance)

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
            if fw is not None:
                src_iface = fw.src_interface or src_iface
                dst_iface = fw.dst_interface or dst_iface
            conn_id = (
                fw.connection_id
                if fw is not None and fw.connection_id > 0
                else self._next_conn_id(sensor_hostname, event.timestamp)
            )
            fw_hostname = sensor_hostname or "fw01"

            if is_deny:
                if src_iface == dst_iface and event.nat is None:
                    continue
                if self._should_suppress_outside_private_deny(
                    net, src_iface, dst_iface, sensor_hostname
                ):
                    continue
                self._emit_deny(event, net, fw, src_iface, dst_iface, sensor_hostname, fw_hostname)
            else:
                if src_iface == dst_iface and event.nat is None:
                    continue
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
                if event.nat and event.nat.nat_type != "static":
                    self._emit_nat_built(
                        event, net, protocol, src_iface, dst_iface, sensor_hostname, fw_hostname
                    )
                teardown_emitted = self._emit_teardown(
                    event,
                    net,
                    protocol,
                    conn_id,
                    src_iface,
                    dst_iface,
                    sensor_hostname,
                    fw_hostname,
                )
                if event.nat and event.nat.nat_type != "static":
                    if teardown_emitted:
                        self._emit_nat_teardown(
                            event, net, protocol, src_iface, dst_iface, sensor_hostname, fw_hostname
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
            if direction == "inbound":
                foreign_iface, foreign_ip = src_iface, net.src_ip
                global_iface, global_ip = dst_iface, net.dst_ip
                local_iface, local_ip = dst_iface, net.dst_ip
            else:
                foreign_iface, foreign_ip = dst_iface, net.dst_ip
                global_iface, global_ip = src_iface, net.src_ip
                local_iface, local_ip = src_iface, net.src_ip
            message = (
                f"Built {direction} ICMP connection for faddr "
                f"{foreign_iface}:{foreign_ip}/{icmp_type} "
                f"gaddr {global_iface}:{global_ip}/0 "
                f"laddr {local_iface}:{local_ip}/0"
            )
        else:
            msg_id = 302013 if protocol == "tcp" else 302015
            proto_upper = protocol.upper()
            # ASA format: iface:real_ip/port (mapped_ip/port)
            # For inbound static NAT: dst main=real_ip, dst parens=VIP
            # For outbound PAT: src main=real_ip, src parens=mapped_ip
            nat = event.nat
            is_inbound_nat = (
                nat is not None
                and nat.nat_type == "static"
                and nat.mapped_dst_ip
                and nat.mapped_dst_ip != net.dst_ip
            )
            if is_inbound_nat:
                # Inbound: dst shows real_ip (post-NAT) as main, VIP in parens
                display_dst_ip, display_dst_port = nat.mapped_dst_ip, nat.mapped_dst_port
                paren_dst_ip, paren_dst_port = net.dst_ip, net.dst_port
            else:
                display_dst_ip, display_dst_port = net.dst_ip, net.dst_port
                paren_dst_ip = nat.mapped_dst_ip if nat else net.dst_ip
                paren_dst_port = nat.mapped_dst_port if nat else net.dst_port
            m_src_ip = nat.mapped_src_ip if nat else net.src_ip
            m_src_port = nat.mapped_src_port if nat else net.src_port
            message = (
                f"Built {direction} {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} "
                f"({m_src_ip}/{m_src_port}) to "
                f"{dst_iface}:{display_dst_ip}/{display_dst_port} "
                f"({paren_dst_ip}/{paren_dst_port})"
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
    ) -> bool:
        """Emit a Teardown connection record (302014/302016/302021)."""
        reason = self._teardown_reason(net, protocol, conn_id)
        duration_seconds = self._teardown_duration_seconds(net, protocol, reason, conn_id)
        duration = self._format_duration(duration_seconds)
        total_bytes = self._teardown_byte_count(net, protocol, conn_id)
        teardown_ts = event.timestamp + timedelta(seconds=duration_seconds)
        if self._is_after_output_end(teardown_ts):
            return False

        if protocol == "icmp":
            msg_id = 302021
            icmp_type = net.dst_port if net.dst_port else 8
            direction = "inbound" if src_iface == "outside" else "outbound"
            if direction == "inbound":
                foreign_iface, foreign_ip = src_iface, net.src_ip
                global_iface, global_ip = dst_iface, net.dst_ip
                local_iface, local_ip = dst_iface, net.dst_ip
            else:
                foreign_iface, foreign_ip = dst_iface, net.dst_ip
                global_iface, global_ip = src_iface, net.src_ip
                local_iface, local_ip = src_iface, net.src_ip
            message = (
                f"Teardown ICMP connection for faddr "
                f"{foreign_iface}:{foreign_ip}/{icmp_type} "
                f"gaddr {global_iface}:{global_ip}/0 "
                f"laddr {local_iface}:{local_ip}/0"
            )
        else:
            msg_id = 302014 if protocol == "tcp" else 302016
            proto_upper = protocol.upper()
            # Inbound static NAT: teardown shows real (post-NAT) dst IP
            nat = event.nat
            is_inbound_nat = (
                nat is not None
                and nat.nat_type == "static"
                and nat.mapped_dst_ip
                and nat.mapped_dst_ip != net.dst_ip
            )
            td_dst_ip = nat.mapped_dst_ip if is_inbound_nat else net.dst_ip
            td_dst_port = nat.mapped_dst_port if is_inbound_nat else net.dst_port
            message = (
                f"Teardown {proto_upper} connection {conn_id} for "
                f"{src_iface}:{net.src_ip}/{net.src_port} to "
                f"{dst_iface}:{td_dst_ip}/{td_dst_port} "
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
        return True

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
        deny_hash_a = getattr(fw, "deny_hash_a", "0x0") if fw else "0x0"
        deny_hash_b = getattr(fw, "deny_hash_b", "0x0") if fw else "0x0"

        if protocol == "icmp":
            icmp_type = net.dst_port if net.dst_port else 8
            icmp_code = 0
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip} "
                f"dst {dst_iface}:{net.dst_ip} "
                f"(type {icmp_type}, code {icmp_code}) "
                f'by access-group "{acl_name}" [{deny_hash_a}, {deny_hash_b}]'
            )
        else:
            message = (
                f"Deny {protocol} src {src_iface}:{net.src_ip}/{net.src_port} "
                f"dst {dst_iface}:{net.dst_ip}/{net.dst_port} "
                f'by access-group "{acl_name}" [{deny_hash_a}, {deny_hash_b}]'
            )

        event_data = {
            "timestamp": event.timestamp,
            "hostname": fw_hostname,
            "severity": 4,
            "msg_id": fw.msg_id if fw and fw.msg_id > 0 else 106023,
            "message": message,
            "pri": self._pri(4),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)
        # Check threat detection thresholds after each deny
        self._check_threat_detection(net.src_ip, event.timestamp, sensor_hostname, fw_hostname)

    def _should_suppress_outside_private_deny(
        self,
        net: Any,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
    ) -> bool:
        """Suppress impossible outside denies to unmapped private post-NAT hosts."""
        if src_iface != "outside" or dst_iface != "dmz":
            return False
        try:
            dst_addr = ipaddress.ip_address(net.dst_ip)
        except ValueError:
            return False
        if not dst_addr.is_private:
            return False
        return net.dst_ip not in set(self._vip_to_real_ip.values())

    def _emit_nat_built(
        self,
        event: SecurityEvent,
        net: Any,
        protocol: str,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a NAT translation Built record (305011)."""
        nat = event.nat
        if nat is None:
            return
        nat_label = "dynamic" if nat.nat_type == "dynamic_pat" else "static"
        proto_upper = protocol.upper()
        # Determine if source or destination was translated
        is_src_nat = nat.mapped_src_ip != net.src_ip
        if is_src_nat:
            mapped_src_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            message = (
                f"Built {nat_label} {proto_upper} translation from "
                f"{src_iface}:{net.src_ip}/{net.src_port} to "
                f"{mapped_src_iface}:{nat.mapped_src_ip}/{nat.mapped_src_port}"
            )
        else:
            # Destination NAT (static inbound): public IP is on outside,
            # real IP is on dmz/inside
            public_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            real_iface = self._resolve_interface(nat.mapped_dst_ip, sensor_hostname)
            message = (
                f"Built {nat_label} {proto_upper} translation from "
                f"{public_iface}:{net.dst_ip}/{net.dst_port} to "
                f"{real_iface}:{nat.mapped_dst_ip}/{nat.mapped_dst_port}"
            )
        event_data = {
            "timestamp": event.timestamp,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": 305011,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _emit_nat_teardown(
        self,
        event: SecurityEvent,
        net: Any,
        protocol: str,
        src_iface: str,
        dst_iface: str,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Emit a NAT translation Teardown record (305012)."""
        nat = event.nat
        if nat is None:
            return
        nat_label = "dynamic" if nat.nat_type == "dynamic_pat" else "static"
        proto_upper = protocol.upper()
        duration = self._format_duration(net.duration)
        teardown_ts = event.timestamp
        if net.duration and net.duration > 0:
            teardown_ts = event.timestamp + timedelta(seconds=net.duration)
        if self._is_after_output_end(teardown_ts):
            return
        is_src_nat = nat.mapped_src_ip != net.src_ip
        if is_src_nat:
            mapped_src_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            message = (
                f"Teardown {nat_label} {proto_upper} translation from "
                f"{src_iface}:{net.src_ip}/{net.src_port} to "
                f"{mapped_src_iface}:{nat.mapped_src_ip}/{nat.mapped_src_port} "
                f"duration {duration}"
            )
        else:
            # Destination NAT teardown: same interface mapping as 305011
            public_iface = self._sensor_interfaces.get(sensor_hostname, {}).get(
                "_default", "outside"
            )
            real_iface = self._resolve_interface(nat.mapped_dst_ip, sensor_hostname)
            message = (
                f"Teardown {nat_label} {proto_upper} translation from "
                f"{public_iface}:{net.dst_ip}/{net.dst_port} to "
                f"{real_iface}:{nat.mapped_dst_ip}/{nat.mapped_dst_port} "
                f"duration {duration}"
            )
        event_data = {
            "timestamp": teardown_ts,
            "hostname": fw_hostname,
            "severity": 6,
            "msg_id": 305012,
            "message": message,
            "pri": self._pri(6),
            "_sensor_hostnames": [sensor_hostname] if sensor_hostname else None,
        }
        self._dispatch(event_data)

    def _check_threat_detection(
        self,
        src_ip: str,
        timestamp: datetime,
        sensor_hostname: str,
        fw_hostname: str,
    ) -> None:
        """Check deny rates against threat detection thresholds; emit 733100 if exceeded.

        Models ASA basic threat detection for scanning. Both burst and average
        rates must exceed their thresholds before an alert fires. After firing,
        a cooldown period (= ASA burst period) prevents duplicate alerts.
        """
        if self._td_burst_threshold <= 0:
            return  # Threat detection disabled

        key = (sensor_hostname, src_ip)

        # Track this deny
        timestamps = self._deny_timestamps.setdefault(key, deque())
        timestamps.append(timestamp)

        # Keep only the data needed for active burst/average windows.
        # This bounds memory growth for sustained deny traffic.
        max_window = max(self._td_burst_window, self._td_avg_window)
        max_cutoff = timestamp - timedelta(seconds=max_window)
        while timestamps and timestamps[0] < max_cutoff:
            timestamps.popleft()

        # Cooldown check: don't fire more than once per burst period
        last_alert = self._last_alert_time.get(key)
        if last_alert and (timestamp - last_alert).total_seconds() < self._td_cooldown:
            return

        # Calculate burst rate (drops in last burst_window seconds)
        burst_cutoff = timestamp - timedelta(seconds=self._td_burst_window)
        avg_cutoff = timestamp - timedelta(seconds=self._td_avg_window)
        burst_count = 0
        avg_count = 0
        for deny_ts in timestamps:
            if deny_ts >= avg_cutoff:
                avg_count += 1
            if deny_ts >= burst_cutoff:
                burst_count += 1
        burst_rate = burst_count / self._td_burst_window
        avg_rate = avg_count / self._td_avg_window

        # Both rates must exceed thresholds (matching real ASA behavior)
        if burst_rate < self._td_burst_threshold or avg_rate < self._td_avg_threshold:
            return

        # Fire 733100
        self._last_alert_time[key] = timestamp
        total_count = len(timestamps)

        message = (
            f"[Scanning] drop rate-1 exceeded. "
            f"Current burst rate is {int(burst_rate)} per second, "
            f"max configured rate is {self._td_burst_threshold}; "
            f"Current average rate is {int(avg_rate)} per second, "
            f"max configured rate is {self._td_avg_threshold}; "
            f"Cumulative total count is {total_count}"
        )
        event_data = {
            "timestamp": timestamp,
            "hostname": fw_hostname,
            "severity": 4,
            "msg_id": 733100,
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
