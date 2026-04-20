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

"""Emitter for EDR/XDR host telemetry in eCAR format."""

import json
import uuid
from datetime import datetime
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class EcarEmitter(HostMultiplexEmitter):
    """Emitter for eCAR (extended Cyber Analytics Repository) format.

    Per-host FQDN directory routing: each host gets its own ecar.json.

    Dual-host model: connection events emit OUTBOUND on src_host and
    INBOUND on dst_host.  Other events use the appropriate host per
    event type (dst_host for logon, src_host for process, etc.).
    """

    _log_filename = "ecar.json"
    _flat_filename = "ecar.json"

    _supported_types: set[str] = {
        "logon",
        "logoff",
        "failed_logon",
        "process_create",
        "process_terminate",
        "system_process_create",
        "ssh_session",
        "connection",
        "file_create",
        "file_modify",
        "file_delete",
        "registry_modify",
        "module_load",
        "create_remote_thread",
        "process_access",
        "service_installed",
    }

    def can_handle(self, event: SecurityEvent) -> bool:
        """eCAR handles events regardless of OS (cross-platform EDR).

        Firewall deny events are excluded — the firewall blocked the
        connection before it reached the endpoint, so the EDR wouldn't see it.
        """
        if event.firewall is not None and event.firewall.action == "deny":
            return False
        return event.event_type in self._supported_types

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        renderer = {
            "logon": self._render_logon,
            "logoff": self._render_logoff,
            "failed_logon": self._render_failed_logon,
            "process_create": self._render_process_create,
            "process_terminate": self._render_process_terminate,
            "system_process_create": self._render_process_create,  # Same rendering
            "ssh_session": self._render_logon,  # SSH session = LOGIN event in EDR
            "connection": self._render_connection,
            "file_create": self._render_file_event,
            "file_modify": self._render_file_event,
            "file_delete": self._render_file_event,
            "registry_modify": self._render_registry_event,
            "module_load": self._render_module_event,
            "create_remote_thread": self._render_create_remote_thread,
            "process_access": self._render_process_access,
            "service_installed": self._render_service_installed,
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(f"EcarEmitter: no render method for {event.event_type}")
        renderer(event)

    @staticmethod
    def _host_fqdn(host: HostContext | None) -> str:
        """Extract FQDN from a HostContext for per-host routing."""
        if host:
            return host.fqdn or host.hostname
        return ""

    @staticmethod
    def _host_name(host: HostContext | None) -> str:
        """Extract hostname from a HostContext."""
        return host.hostname if host else ""

    @staticmethod
    def _apply_edr_context(event_data: dict[str, Any], event: SecurityEvent) -> None:
        """Copy objectID, actorID, and tid from EdrContext into event_data."""
        if event.edr:
            if event.edr.object_id:
                event_data["objectID"] = event.edr.object_id
            if event.edr.actor_id:
                event_data["actorID"] = event.edr.actor_id
            if event.edr.tid != -1:
                event_data["tid"] = event.edr.tid

    def _render_logon(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGIN event (logged on dst_host)."""
        host = event.dst_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": event.auth.source_ip,
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGOUT event (logged on dst_host)."""
        host = event.dst_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGOUT",
            "principal": event.auth.username,
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGIN with failure_reason (logged on dst_host)."""
        host = event.dst_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": event.auth.source_ip,
            "failure_reason": "bad_password",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/CREATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "CREATE",
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "principal": proc.username,
            "image_path": proc.image,
            "command_line": proc.command_line,
            "_host_fqdn": self._host_fqdn(host),
        }
        if proc.parent_image:
            event_data["parent_image_path"] = proc.parent_image
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/TERMINATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "TERMINATE",
            "pid": proc.pid,
            "principal": proc.username,
            "image_path": proc.image,
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_file_event(self, event: SecurityEvent) -> None:
        """Render eCAR FILE event from canonical FileContext (logged on src_host)."""
        host = event.src_host
        action_map = {"file_create": "CREATE", "file_modify": "MODIFY", "file_delete": "DELETE"}
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "FILE",
            "action": action_map.get(event.event_type, "CREATE"),
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_registry_event(self, event: SecurityEvent) -> None:
        """Render eCAR REGISTRY event from canonical RegistryContext (logged on src_host)."""
        host = event.src_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "REGISTRY",
            "action": "MODIFY",
            "pid": event.registry.pid if event.registry else -1,
            "principal": event.auth.username if event.auth else "",
            "registry_key": event.registry.key if event.registry else "",
            "registry_value": event.registry.value if event.registry else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_module_event(self, event: SecurityEvent) -> None:
        """Render eCAR MODULE/LOAD event from canonical FileContext (logged on src_host)."""
        host = event.src_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "MODULE",
            "action": "LOAD",
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_connection(self, event: SecurityEvent) -> None:
        """Render eCAR FLOW/CONNECT events -- OUTBOUND on src_host, INBOUND on dst_host.

        For internal-to-internal connections, emits TWO records (one per host).
        For external-to-internal, emits only the INBOUND on dst_host.
        For internal-to-external, emits only the OUTBOUND on src_host.
        """
        net = event.network

        # OUTBOUND FLOW on source host (if source is internal/known)
        if event.src_host:
            event_data = {
                "timestamp": event.timestamp,
                "hostname": event.src_host.hostname,
                "object": "FLOW",
                "action": "CONNECT",
                "direction": "OUTBOUND",
                "pid": net.initiating_pid,
                "src_ip": net.src_ip,
                "src_port": net.src_port,
                "dst_ip": net.dst_ip,
                "dst_port": net.dst_port,
                "protocol": net.protocol,
                "_host_fqdn": self._host_fqdn(event.src_host),
            }
            self._apply_edr_context(event_data, event)
            self.emit_event(event_data)

        # INBOUND FLOW on destination host (if destination is internal/known)
        if event.dst_host:
            # Host-based EDR sees the local interface IP, not the NAT VIP
            dst_ip = net.dst_ip
            if event.nat and event.nat.mapped_dst_ip and event.nat.mapped_dst_ip != net.dst_ip:
                dst_ip = event.nat.mapped_dst_ip
            event_data = {
                "timestamp": event.timestamp,
                "hostname": event.dst_host.hostname,
                "object": "FLOW",
                "action": "CONNECT",
                "direction": "INBOUND",
                "pid": -1,  # Destination doesn't know the initiating PID
                "src_ip": net.src_ip,
                "src_port": net.src_port,
                "dst_ip": dst_ip,
                "dst_port": net.dst_port,
                "protocol": net.protocol,
                "_host_fqdn": self._host_fqdn(event.dst_host),
            }
            # INBOUND flow gets its own objectID (separate telemetry observation)
            self.emit_event(event_data)

    def _render_create_remote_thread(self, event: SecurityEvent) -> None:
        """Render eCAR THREAD/REMOTE_CREATE event (logged on src_host).

        Maps Sysmon Event 8 (CreateRemoteThread) to eCAR format.
        Source process creates a thread in a different target process.

        OpTC field structure: objectID = new thread UUID, actorID = source
        process UUID, tgt_pid_uuid = target process UUID in properties.
        """
        import random as rng_mod

        host = event.src_host
        proc = event.process
        auth = event.auth
        target_pid = int(auth.source_port) if auth and auth.source_port else -1
        src_tid = rng_mod.randint(1000, 9999)
        tgt_tid = rng_mod.randint(1000, 9999)
        # x86-64 canonical addresses: page-aligned, proper ranges
        _kstack_base = 0xFFFFF80000000000 + (rng_mod.randint(0, 0xFFFFF) << 12)
        _ustack_base = 0x000000C0000000 + (rng_mod.randint(0, 0xFFF) << 12)
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "THREAD",
            "action": "REMOTE_CREATE",
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "tid": src_tid,
            "principal": proc.username if proc.username else "NT AUTHORITY\\SYSTEM",
            "image_path": proc.image,
            "src_pid": str(proc.pid),
            "src_tid": str(src_tid),
            "tgt_pid": str(target_pid),
            "tgt_pid_uuid": str(uuid.uuid4()),
            "tgt_tid": str(tgt_tid),
            "start_address": f"00007ff{rng_mod.randint(0x0, 0xF):x}{rng_mod.randint(0x0000, 0xFFFF):04x}0000",
            "stack_base": f"{_kstack_base:016x}",
            "stack_limit": f"{_kstack_base - 0x6000:016x}",
            "user_stack_base": f"{_ustack_base:016x}",
            "user_stack_limit": f"{_ustack_base - 0x100000:016x}",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_access(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/OPEN event (logged on src_host).

        Maps Sysmon Event 10 (ProcessAccess) to eCAR format.
        Source process opens a handle to target process with access rights.

        OpTC field structure: objectID = target process UUID,
        actorID = source process UUID, image_path = source image,
        command_line = target command line.
        """
        import random as rng_mod

        host = event.src_host
        proc = event.process
        auth = event.auth
        target_image = auth.target_server if auth and auth.target_server else ""
        granted_access = auth.failure_status if auth and auth.failure_status else "0x0"
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "OPEN",
            "objectID": str(uuid.uuid4()),  # Target process UUID
            "actorID": str(uuid.uuid4()),  # Source process UUID
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "tid": rng_mod.randint(1000, 9999),
            "principal": proc.username if proc.username else "NT AUTHORITY\\SYSTEM",
            "image_path": proc.image,
            "command_line": target_image,  # OpTC puts target command_line here
            "parent_image_path": proc.parent_image or proc.image,
            "granted_access": granted_access,
            "_host_fqdn": self._host_fqdn(host),
        }
        self.emit_event(event_data)

    def _render_service_installed(self, event: SecurityEvent) -> None:
        """Render eCAR SERVICE/CREATE event (logged on src_host)."""
        host = event.src_host
        service = event.service
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "SERVICE",
            "action": "CREATE",
            "pid": -1,
            "principal": event.auth.username if event.auth else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        if service:
            event_data["service_name"] = service.service_name
            event_data["image_path"] = service.service_file_name
            event_data["service_account"] = service.service_account
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route event to per-host writer."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    # Property keys that belong in the eCAR properties map.
    _PROPERTY_KEYS = (
        "command_line",
        "image_path",
        "parent_image_path",
        "file_path",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "direction",
        "md5",
        "sha256",
        "registry_key",
        "registry_value",
        "failure_reason",
        "src_pid",
        "src_tid",
        "tgt_pid",
        "tgt_tid",
        "tgt_pid_uuid",
        "start_address",
        "stack_base",
        "stack_limit",
        "user_stack_base",
        "user_stack_limit",
        "granted_access",
        "service_name",
        "service_account",
    )

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render eCAR event to compact NDJSON.

        Builds the record as a Python dict and serializes directly with
        json.dumps, bypassing the Jinja2 template.  This avoids the fragile
        comma-handling logic in the old template and enforces spec compliance:
        pid/tid always present (-1 sentinel), all property values are strings.
        """
        # Convert timestamp to milliseconds since epoch
        ts = event_data["timestamp"]
        timestamp_ms = int(ts.timestamp() * 1000) if isinstance(ts, datetime) else int(ts * 1000)

        record: dict[str, Any] = {
            "timestamp_ms": timestamp_ms,
            "id": event_data.get("id") or str(uuid.uuid4()),
            "hostname": event_data.get("hostname", ""),
            "object": event_data["object"],
            "action": event_data["action"],
            "objectID": event_data.get("objectID") or str(uuid.uuid4()),
        }

        if event_data.get("actorID"):
            record["actorID"] = event_data["actorID"]

        # pid and tid are always present per eCAR spec (-1 = unavailable).
        # ppid is only emitted for PROCESS events.
        record["pid"] = event_data["pid"] if event_data.get("pid") is not None else -1
        record["tid"] = event_data["tid"] if event_data.get("tid") is not None else -1
        if "ppid" in event_data:
            record["ppid"] = event_data["ppid"] if event_data["ppid"] is not None else -1

        if event_data.get("principal"):
            record["principal"] = event_data["principal"]

        # Properties: all values must be strings per eCAR spec.
        props: dict[str, str] = {}
        for key in self._PROPERTY_KEYS:
            val = event_data.get(key)
            if val is not None:
                props[key] = str(val)
        record["properties"] = props

        return json.dumps(record, separators=(",", ":"))
