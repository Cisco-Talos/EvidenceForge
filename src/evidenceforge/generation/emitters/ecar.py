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
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed

_ECAR_SORT_PRIORITY = {
    ("USER_SESSION", "LOGIN"): 0,
    ("PROCESS", "CREATE"): 1,
    ("MODULE", "LOAD"): 2,
    ("REGISTRY", "MODIFY"): 3,
    ("FILE", "CREATE"): 4,
    ("FILE", "READ"): 5,
    ("FILE", "WRITE"): 6,
    ("FLOW", "CONNECT"): 7,
    ("THREAD", "REMOTE_CREATE"): 8,
    ("PROCESS", "OPEN"): 9,
    ("PROCESS", "TERMINATE"): 10,
    ("USER_SESSION", "LOGOUT"): 11,
}

_INBOUND_SERVICE_PID_CANDIDATES: dict[int, tuple[str, ...]] = {
    22: ("sshd",),
    80: ("nginx", "apache2", "httpd"),
    443: ("nginx", "apache2", "httpd"),
    445: ("smbd", "lanmanserver"),
    1433: ("sqlservr",),
    3306: ("mysqld",),
    3389: ("svchost_termservice", "svchost_netsvcs"),
    5432: ("postgres",),
    8080: ("squid", "nginx", "apache2", "httpd"),
}


def _ecar_sort_key(line: str) -> tuple[int, int, str]:
    """Extract timestamp_ms for chronological per-host eCAR output sorting."""
    try:
        record = json.loads(line)
        priority = _ECAR_SORT_PRIORITY.get((record.get("object"), record.get("action")), 50)
        return int(record.get("timestamp_ms", 0)), priority, line
    except (TypeError, ValueError, json.JSONDecodeError):
        return 0, 50, line


class EcarEmitter(HostMultiplexEmitter):
    """Emitter for eCAR (extended Cyber Analytics Repository) format.

    Per-host FQDN directory routing: each host gets its own ecar.json.

    Dual-host model: connection events emit OUTBOUND on src_host and
    INBOUND on dst_host.  Other events use the appropriate host per
    event type (dst_host for logon, src_host for process, etc.).
    """

    _log_filename = "ecar.json"
    _flat_filename = "ecar.json"
    _sort_flat_file = True
    _sort_key = staticmethod(_ecar_sort_key)
    _defer_sorted_flush_until_close = True

    _supported_types: set[str] = {
        "logon",
        "logoff",
        "failed_logon",
        "process_create",
        "process_terminate",
        "system_process_create",
        "ssh_session",
        "connection",
        "file_read",
        "file_create",
        "file_modify",
        "file_delete",
        "registry_modify",
        "module_load",
        "image_load",
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
            "file_read": self._render_file_event,
            "file_create": self._render_file_event,
            "file_modify": self._render_file_event,
            "file_delete": self._render_file_event,
            "registry_modify": self._render_registry_event,
            "module_load": self._render_module_event,
            "image_load": self._render_module_event,
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

    @staticmethod
    def _stable_tid(hostname: str, pid: int, timestamp: datetime, salt: str) -> int:
        """Return a plausible source thread ID for process-owned eCAR events."""
        if pid <= 0:
            return -1
        bucket_ms = int(timestamp.timestamp() * 1000)
        return 1000 + (_stable_seed(f"ecar_tid:{hostname}:{pid}:{bucket_ms}:{salt}") % 60000)

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
            "outcome": "success",
            "logon_type": event.auth.logon_type,
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
        """Render eCAR failed USER_SESSION/LOGIN attempt on dst_host."""
        host = event.dst_host
        event_data = {
            "timestamp": event.timestamp,
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": event.auth.source_ip,
            "outcome": "failure",
            "session_lifecycle": "attempt_failed",
            "failure_reason": "bad_password",
            "_host_fqdn": self._host_fqdn(host),
        }
        if getattr(host, "os_category", "") == "windows":
            event_data["status_code"] = event.auth.failure_status
            event_data["sub_status"] = event.auth.failure_substatus
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/CREATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_ts = self._process_create_timestamp(event, proc)
        event_data = {
            "timestamp": event_ts,
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
        event_data.setdefault(
            "tid",
            self._stable_tid(self._host_name(host), proc.pid, event_ts, "process_create"),
        )
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
        event_data.setdefault(
            "tid",
            self._stable_tid(self._host_name(host), proc.pid, event.timestamp, "process_terminate"),
        )
        self.emit_event(event_data)

    def _render_file_event(self, event: SecurityEvent) -> None:
        """Render eCAR FILE event from canonical FileContext (logged on src_host)."""
        host = event.src_host
        proc = event.process
        action_map = {
            "file_read": "READ",
            "file_create": "CREATE",
            "file_modify": "WRITE",
            "file_delete": "DELETE",
        }
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, proc),
            "hostname": self._host_name(host),
            "object": "FILE",
            "action": action_map.get(event.event_type, "CREATE"),
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_edr_context(event_data, event)
        event_data.setdefault(
            "tid",
            self._stable_tid(self._host_name(host), event_data["pid"], event.timestamp, "file"),
        )
        self.emit_event(event_data)

    def _render_registry_event(self, event: SecurityEvent) -> None:
        """Render eCAR REGISTRY event from canonical RegistryContext (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, proc),
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
        event_data.setdefault(
            "tid",
            self._stable_tid(self._host_name(host), event_data["pid"], event.timestamp, "registry"),
        )
        self.emit_event(event_data)

    def _render_module_event(self, event: SecurityEvent) -> None:
        """Render eCAR MODULE/LOAD event from canonical ImageLoadContext."""
        host = event.src_host
        proc = event.process
        module_path = ""
        if event.image_load is not None:
            module_path = event.image_load.image_loaded
        elif event.file is not None:
            module_path = event.file.path
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, proc),
            "hostname": self._host_name(host),
            "object": "MODULE",
            "action": "LOAD",
            "pid": proc.pid if proc else (event.file.pid if event.file else -1),
            "principal": event.auth.username if event.auth else "",
            "file_path": module_path,
            "_host_fqdn": self._host_fqdn(host),
        }
        if proc:
            event_data["image_path"] = proc.image
        self._apply_edr_context(event_data, event)
        event_data.setdefault(
            "tid",
            self._stable_tid(self._host_name(host), event_data["pid"], event.timestamp, "module"),
        )
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
            event_ts = event.timestamp + sample_timing_delta(
                "source.ecar_flow",
                seed_parts=(
                    "outbound",
                    event.src_host.hostname,
                    net.initiating_pid,
                    net.src_ip,
                    net.src_port,
                    net.dst_ip,
                    net.dst_port,
                    event.timestamp,
                ),
            )
            if event.process is not None:
                event_ts = max(event_ts, self._after_process_create_timestamp(event, event.process))
            event_data = {
                "timestamp": event_ts,
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
            listener_observed = self._inbound_listener_observed(event)
            inbound_pid = self._resolve_inbound_service_pid(event) if listener_observed else -1
            event_ts = event.timestamp + sample_timing_delta(
                "source.ecar_flow",
                seed_parts=(
                    "inbound",
                    event.dst_host.hostname,
                    net.initiating_pid,
                    net.src_ip,
                    net.src_port,
                    net.dst_ip,
                    net.dst_port,
                    event.timestamp,
                ),
            )
            # Host-based EDR sees the local interface IP, not the NAT VIP
            dst_ip = net.dst_ip
            if event.nat and event.nat.mapped_dst_ip and event.nat.mapped_dst_ip != net.dst_ip:
                dst_ip = event.nat.mapped_dst_ip
            event_data = {
                "timestamp": event_ts,
                "hostname": event.dst_host.hostname,
                "object": "FLOW",
                "action": "CONNECT",
                "direction": "INBOUND",
                "pid": inbound_pid,
                "src_ip": net.src_ip,
                "src_port": net.src_port,
                "dst_ip": dst_ip,
                "dst_port": net.dst_port,
                "protocol": net.protocol,
                "_host_fqdn": self._host_fqdn(event.dst_host),
            }
            if not listener_observed:
                event_data["outcome"] = "failure"
                event_data["connection_state"] = net.conn_state
            # INBOUND flow gets its own objectID (separate telemetry observation)
            self.emit_event(event_data)

    @staticmethod
    def _inbound_listener_observed(event: SecurityEvent) -> bool:
        """Return whether destination EDR should attribute the flow to a listener process."""
        net = event.network
        if net is None:
            return False
        if net.protocol.lower() != "tcp":
            return True
        if net.conn_state in {"REJ", "S0"}:
            return False
        history = net.history or ""
        if not net.conn_state and not history:
            return True
        # No responder handshake/data/reset marker means the connection never
        # progressed far enough for an application listener to own it.
        return any(marker in history for marker in ("h", "a", "d", "r", "f"))

    def _resolve_inbound_service_pid(self, event: SecurityEvent) -> int:
        """Resolve destination-local listener PID for host-observed inbound flows."""
        net = event.network
        host = event.dst_host
        if net is None or host is None:
            return -1

        system_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
        for candidate in _INBOUND_SERVICE_PID_CANDIDATES.get(net.dst_port, ()):
            pid = system_pids.get(candidate)
            if pid and pid > 0:
                return pid
        return -1

    def _render_create_remote_thread(self, event: SecurityEvent) -> None:
        """Render eCAR THREAD/REMOTE_CREATE event (logged on src_host).

        Maps Sysmon Event 8 (CreateRemoteThread) to eCAR format.
        Source process creates a thread in a different target process.

        OpTC field structure: objectID = new thread UUID, actorID = source
        process UUID, target_process_uuid = target process UUID in properties.
        """
        host = event.src_host
        proc = event.process
        auth = event.auth
        remote_thread = event.remote_thread
        target_pid = (
            remote_thread.target_pid
            if remote_thread is not None
            else int(auth.source_port)
            if auth and auth.source_port
            else -1
        )
        event_ts = self._after_process_create_timestamp(event, proc) + sample_timing_delta(
            "source.ecar_remote_thread",
            seed_parts=(
                host.hostname,
                proc.pid,
                target_pid,
                remote_thread.new_thread_id if remote_thread else 0,
                event.timestamp,
            ),
        )
        event_data = {
            "timestamp": event_ts,
            "hostname": self._host_name(host),
            "object": "THREAD",
            "action": "REMOTE_CREATE",
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "tid": remote_thread.source_thread_id if remote_thread else 0,
            "principal": proc.username if proc.username else "NT AUTHORITY\\SYSTEM",
            "image_path": proc.image,
            "src_pid": str(proc.pid),
            "src_tid": str(remote_thread.source_thread_id if remote_thread else 0),
            "target_pid": str(target_pid),
            "target_process_uuid": remote_thread.target_process_object_id
            if remote_thread
            else str(uuid.uuid4()),
            "tgt_tid": str(remote_thread.new_thread_id if remote_thread else 0),
            "start_address": f"{remote_thread.start_address:016x}" if remote_thread else "",
            "stack_base": f"{remote_thread.stack_base:016x}" if remote_thread else "",
            "stack_limit": f"{remote_thread.stack_limit:016x}" if remote_thread else "",
            "user_stack_base": f"{remote_thread.user_stack_base:016x}" if remote_thread else "",
            "user_stack_limit": f"{remote_thread.user_stack_limit:016x}" if remote_thread else "",
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
        host = event.src_host
        proc = event.process
        access = event.process_access
        target_image = access.target_image if access else ""
        target_pid = access.target_pid if access else -1
        granted_access = access.granted_access if access else "0x0"
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, proc),
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "OPEN",
            "objectID": event.edr.object_id if event.edr else str(uuid.uuid4()),
            "actorID": event.edr.actor_id if event.edr else str(uuid.uuid4()),
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "tid": access.source_thread_id if access else -1,
            "principal": proc.username if proc.username else "NT AUTHORITY\\SYSTEM",
            "image_path": proc.image,
            "command_line": proc.command_line,
            "parent_image_path": proc.parent_image or "",
            "target_pid": target_pid,
            "target_image_path": target_image,
            "target_process_uuid": access.target_process_object_id if access else "",
            "granted_access": granted_access,
            "_host_fqdn": self._host_fqdn(host),
        }
        self.emit_event(event_data)

    @staticmethod
    def _source_offset(
        event_type: str,
        hostname: str,
        pid: int,
        timestamp: datetime,
        *,
        minimum_ms: int,
        maximum_ms: int,
    ) -> timedelta:
        """Deterministic EDR collection latency for cross-source events."""
        from evidenceforge.utils.rng import _stable_seed

        span = maximum_ms - minimum_ms
        offset = minimum_ms + (
            _stable_seed(f"ecar:{event_type}:{hostname}:{pid}:{timestamp}") % span
        )
        return timedelta(milliseconds=offset)

    def _process_create_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Return the eCAR render timestamp for a process-create observation."""
        if proc is None:
            return event.timestamp
        host = event.src_host
        hostname = host.hostname if host is not None else ""
        start_time = proc.start_time or event.timestamp
        return start_time + self._source_offset(
            "process_create",
            hostname,
            proc.pid,
            start_time,
            minimum_ms=12,
            maximum_ms=250,
        )

    def _after_process_create_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Clamp dependent eCAR observations after their PROCESS/CREATE record."""
        if proc is None or proc.start_time is None:
            return event.timestamp
        process_create_ts = self._process_create_timestamp(event, proc)
        if event.timestamp > process_create_ts:
            return event.timestamp
        return process_create_ts + self._source_offset(
            "dependent_after_process_create",
            self._host_name(event.src_host),
            proc.pid,
            event.timestamp,
            minimum_ms=1,
            maximum_ms=35,
        )

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

    @staticmethod
    def _referenced_process_ids(record: dict[str, Any]) -> set[str]:
        """Return process object IDs referenced by an eCAR record."""
        refs = set()
        object_id = record.get("objectID")
        if object_id and not (
            record.get("object") == "PROCESS" and record.get("action") == "TERMINATE"
        ):
            refs.add(str(object_id))
        actor_id = record.get("actorID")
        if actor_id:
            refs.add(str(actor_id))
        props = record.get("properties") or {}
        for key in (
            "target_process_uuid",
            "target_process_object_id",
            "source_process_object_id",
        ):
            value = props.get(key)
            if value:
                refs.add(str(value))
        return refs

    @classmethod
    def _normalize_process_termination_order(cls, lines: list[str]) -> list[str]:
        """Move PROCESS/TERMINATE rows after later same-process references."""
        records: list[dict[str, Any] | None] = []
        latest_reference_ms: dict[str, int] = {}
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                records.append(None)
                continue
            records.append(record)
            timestamp_ms = int(record.get("timestamp_ms", 0))
            for process_id in cls._referenced_process_ids(record):
                latest_reference_ms[process_id] = max(
                    latest_reference_ms.get(process_id, 0),
                    timestamp_ms,
                )

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            if record.get("object") == "PROCESS" and record.get("action") == "TERMINATE":
                process_id = str(record.get("objectID", ""))
                latest_ms = latest_reference_ms.get(process_id)
                timestamp_ms = int(record.get("timestamp_ms", 0))
                if latest_ms is not None and latest_ms >= timestamp_ms:
                    stable_delay_ms = 100 + (sum(ord(ch) for ch in process_id) % 1900)
                    record["timestamp_ms"] = latest_ms + stable_delay_ms
                    line = json.dumps(record, separators=(",", ":"))
            normalized.append(line)
        return normalized

    @classmethod
    def _normalize_process_parent_order(cls, lines: list[str]) -> list[str]:
        """Move PROCESS/CREATE rows after visible parent PROCESS/CREATE rows.

        Raw eCAR records can contain arbitrary ``objectID``/``actorID`` or PID
        relationships, including self-parenting and cycles.  Cyclic parentage is
        unsatisfiable, so those edges are treated as unshiftable instead of
        repeatedly advancing timestamps forever during final flush.
        """
        records: list[dict[str, Any] | None] = []
        process_create_records: dict[str, dict[str, Any]] = {}
        pid_keys: dict[int, str] = {}
        for index, line in enumerate(lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                records.append(None)
                continue
            records.append(record)
            if record.get("object") != "PROCESS" or record.get("action") != "CREATE":
                continue
            key = str(record.get("objectID") or f"__process_create_{index}")
            process_create_records[key] = record
            try:
                pid = int(record.get("pid", -1))
            except (TypeError, ValueError):
                pid = -1
            if pid > 0:
                pid_keys[pid] = key

        if not process_create_records:
            return lines

        parent_keys: dict[str, str] = {}
        for key, record in process_create_records.items():
            parent_id = record.get("actorID")
            if parent_id is not None and str(parent_id) in process_create_records:
                parent_keys[key] = str(parent_id)
                continue
            try:
                parent_pid = int(record.get("ppid", -1))
            except (TypeError, ValueError):
                parent_pid = -1
            parent_key = pid_keys.get(parent_pid)
            if parent_key is not None:
                parent_keys[key] = parent_key

        cyclic_keys: set[str] = set()
        for key in process_create_records:
            path: list[str] = []
            seen: set[str] = set()
            current: str | None = key
            while current is not None:
                if current in seen:
                    cyclic_keys.update(path[path.index(current) :])
                    break
                if current in cyclic_keys:
                    break
                seen.add(current)
                path.append(current)
                parent_key = parent_keys.get(current)
                current = parent_key if parent_key in process_create_records else None

        max_passes = len(process_create_records)
        for _ in range(max_passes):
            changed = False
            create_times: dict[str, int] = {}
            for key, record in process_create_records.items():
                create_times[key] = int(record.get("timestamp_ms", 0))

            for key, record in process_create_records.items():
                if key in cyclic_keys:
                    continue
                parent_key = parent_keys.get(key)
                if parent_key is None or parent_key in cyclic_keys:
                    continue
                parent_ms = create_times.get(parent_key)
                timestamp_ms = int(record.get("timestamp_ms", 0))
                if parent_ms is not None and timestamp_ms <= parent_ms:
                    record["timestamp_ms"] = parent_ms + 1
                    changed = True
            if not changed:
                break

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
            else:
                normalized.append(json.dumps(record, separators=(",", ":")))
        return normalized

    @staticmethod
    def _semantic_dedup_key(record: dict[str, Any]) -> str:
        """Return an eCAR semantic identity that ignores generated UUID fields."""
        comparable = {
            key: value for key, value in record.items() if key not in {"id", "objectID", "actorID"}
        }
        props = comparable.get("properties")
        if isinstance(props, dict):
            comparable["properties"] = {key: props[key] for key in sorted(props)}
        return json.dumps(comparable, sort_keys=True, separators=(",", ":"))

    def _deduplicate_semantic_events(self, lines: list[str]) -> list[str]:
        """Drop exact duplicate eCAR facts emitted with fresh UUID wrappers."""
        seen: set[str] = set()
        deduped: list[str] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                deduped.append(line)
                continue
            key = self._semantic_dedup_key(record)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(line)
        return deduped

    def flush(self, force: bool = False) -> None:
        """Flush per-host eCAR records after final lifecycle normalization."""
        if force:
            with self._writers_lock:
                writers = list(self._writers.values())
            for writer in writers:
                with writer._lock:
                    writer.buffer = self._normalize_process_parent_order(writer.buffer)
                    writer.buffer = self._normalize_process_termination_order(writer.buffer)
                    writer.buffer = self._deduplicate_semantic_events(writer.buffer)
        super().flush(force=force)

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
        "outcome",
        "session_lifecycle",
        "status_code",
        "sub_status",
        "src_pid",
        "src_tid",
        "tgt_tid",
        "start_address",
        "stack_base",
        "stack_limit",
        "user_stack_base",
        "user_stack_limit",
        "granted_access",
        "target_pid",
        "target_image_path",
        "target_process_uuid",
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
