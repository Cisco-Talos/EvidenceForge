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
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.activity.endpoint_noise import ecar_flow_identity_config
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.windows_ids import align_windows_id

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
    53: ("dns", "svchost_netsvcs", "svchost_net_svc"),
    88: ("lsass",),
    123: ("timesyncd", "chronyd", "svchost_netsvcs"),
    389: ("lsass",),
    22: ("sshd",),
    80: ("nginx", "apache2", "httpd"),
    443: ("nginx", "apache2", "httpd"),
    445: ("system", "smbd", "lanmanserver"),
    1433: ("sqlservr",),
    3306: ("mysqld",),
    3389: ("svchost_termservice", "svchost_netsvcs"),
    5432: ("postgres",),
    8080: ("squid", "nginx", "apache2", "httpd"),
}

_ECAR_FAILURE_REASON_BY_SUBSTATUS = {
    "0xc0000064": "unknown_user",
    "0xc000006a": "bad_password",
    "0xc0000072": "account_disabled",
    "0xc0000234": "account_locked",
}

_ECAR_FAILURE_REASON_BY_WINDOWS_CODE = {
    "%%2304": "account_locked",
    "%%2307": "account_disabled",
    "%%2313": "bad_password",
}

_SOURCE_TIMING = SourceTimingPlanner()

_SERVICE_PRINCIPAL_NAMES = {
    "system",
    "local service",
    "network service",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "apache",
    "mysql",
    "nginx",
    "postgres",
    "postfix",
    "squid",
    "sshd",
    "www-data",
}


def _ecar_sort_key(line: str) -> tuple[int, int, str]:
    """Extract timestamp_ms for chronological per-host eCAR output sorting."""
    try:
        record = json.loads(line)
        priority = _ECAR_SORT_PRIORITY.get((record.get("object"), record.get("action")), 50)
        return int(record.get("timestamp_ms", 0)), priority, line
    except (TypeError, ValueError, json.JSONDecodeError):
        return 0, 50, line


def _ecar_failed_logon_reason(auth: Any, os_category: str) -> str:
    """Map native failed-auth codes into stable eCAR reason vocabulary."""
    if os_category != "windows":
        return "bad_password"
    substatus = str(getattr(auth, "failure_substatus", "") or "").lower()
    if substatus in _ECAR_FAILURE_REASON_BY_SUBSTATUS:
        return _ECAR_FAILURE_REASON_BY_SUBSTATUS[substatus]
    reason = str(getattr(auth, "failure_reason", "") or "")
    return _ECAR_FAILURE_REASON_BY_WINDOWS_CODE.get(reason, "authentication_failure")


def _ecar_non_windows_session_type(event: SecurityEvent) -> str:
    """Return an OS-native session label for non-Windows eCAR sessions."""
    if event.event_type == "ssh_session":
        return "ssh"
    if event.event_type == "failed_logon":
        source_ip = _ecar_session_source_ip(event)
        if source_ip and source_ip != "-":
            return "remote"
    logon_type = getattr(event.auth, "logon_type", 0)
    if logon_type == 5:
        return "service"
    source_ip = _ecar_session_source_ip(event)
    if source_ip == "-":
        return "local"
    if logon_type == 10:
        return "ssh"
    if logon_type == 3:
        return "remote"
    if logon_type in {2, 7, 11}:
        return "local"
    return "session"


def _ecar_session_source_ip(event: SecurityEvent) -> str:
    """Return a source IP suitable for endpoint USER_SESSION telemetry."""
    source_ip = str(getattr(event.auth, "source_ip", "") or "")
    if not source_ip or source_ip == "-":
        return "-"
    host = event.dst_host
    if host is not None and source_ip == getattr(host, "ip", ""):
        return "-"
    return source_ip


def _ecar_probability_enabled(key: str, probability: float) -> bool:
    """Return whether a stable per-record probability gate is enabled."""
    clamped = max(0.0, min(1.0, float(probability)))
    if clamped <= 0.0:
        return False
    if clamped >= 1.0:
        return True
    return (_stable_seed(key) % 10_000) / 10_000.0 < clamped


def _flow_principal_probability(username: str, direction: str) -> float:
    """Return the configured probability for FLOW principal attribution."""
    cfg = ecar_flow_identity_config()
    normalized = username.strip().lower()
    if direction == "INBOUND":
        return float(cfg.get("inbound_listener_probability", 0.36))
    if normalized == "root":
        return float(cfg.get("root_process_probability", 0.42))
    if normalized in _SERVICE_PRINCIPAL_NAMES:
        return float(cfg.get("service_process_probability", 0.48))
    return float(cfg.get("user_process_probability", 0.88))


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
    _output_end_time: datetime | None = None
    _stale_process_reference_grace_ms = 5 * 60 * 1000
    _post_termination_dependent_grace_ms = 30 * 1000
    _pre_process_flow_identity_repair_grace_ms = 30 * 1000

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize per-source ordering memory for cross-event eCAR contracts."""
        super().__init__(*args, **kwargs)
        self._remote_inbound_flow_times: dict[tuple[str, str, int, str, int], datetime] = {}

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
        if (
            event.event_type == "connection"
            and event.network is not None
            and event.network.application_layer_only
        ):
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
    def _stable_tid(
        hostname: str,
        pid: int,
        timestamp: datetime,
        salt: str,
        os_category: str = "",
    ) -> int:
        """Return a plausible source thread ID for process-owned eCAR events."""
        if pid <= 0:
            return -1
        if os_category == "linux":
            return pid
        bucket_ms = int(timestamp.timestamp() * 1000)
        tid = 1000 + (_stable_seed(f"ecar_tid:{hostname}:{pid}:{bucket_ms}:{salt}") % 60000)
        if os_category == "windows":
            return align_windows_id(tid)
        return tid

    @staticmethod
    def _stable_record_uuid(
        kind: str,
        event_data: dict[str, Any],
        timestamp_ms: int,
        *extra: object,
    ) -> str:
        """Return a stable UUID for eCAR fields that are source-generated."""
        comparable = {
            key: value
            for key, value in event_data.items()
            if key not in {"id", "objectID", "actorID", "_host_fqdn", "timestamp"}
        }
        comparable["timestamp_ms"] = timestamp_ms
        payload = json.dumps(comparable, sort_keys=True, default=str, separators=(",", ":"))
        return stable_uuid(f"ecar-{kind}", payload, *extra)

    def _render_logon(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGIN event (logged on dst_host)."""
        host = event.dst_host
        event_data = {
            "timestamp": self._session_timestamp(event, host, "login"),
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": _ecar_session_source_ip(event),
            "outcome": "success",
            "_host_fqdn": self._host_fqdn(host),
        }
        if getattr(host, "os_category", "") == "windows":
            event_data["logon_type"] = event.auth.logon_type
        else:
            event_data["session_type"] = _ecar_non_windows_session_type(event)
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGOUT event (logged on dst_host)."""
        host = event.dst_host
        event_data = {
            "timestamp": self._session_timestamp(event, host, "logout"),
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGOUT",
            "principal": event.auth.username,
            "_host_fqdn": self._host_fqdn(host),
        }
        source_ip = _ecar_session_source_ip(event)
        if source_ip != "-":
            event_data["src_ip"] = source_ip
        if source_ip != "-" and event.auth.source_port:
            event_data["src_port"] = event.auth.source_port
        if getattr(host, "os_category", "") != "windows":
            event_data["session_type"] = _ecar_non_windows_session_type(event)
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render eCAR failed USER_SESSION/LOGIN attempt on dst_host."""
        host = event.dst_host
        event_data = {
            "timestamp": self._session_timestamp(event, host, "failed_login"),
            "hostname": self._host_name(host),
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": _ecar_session_source_ip(event),
            "outcome": "failure",
            "session_lifecycle": "attempt_failed",
            "failure_reason": _ecar_failed_logon_reason(
                event.auth, getattr(host, "os_category", "")
            ),
            "_host_fqdn": self._host_fqdn(host),
        }
        if getattr(host, "os_category", "") == "windows":
            event_data["status_code"] = event.auth.failure_status
            event_data["sub_status"] = event.auth.failure_substatus
        else:
            event_data["session_type"] = _ecar_non_windows_session_type(event)
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _session_timestamp(
        self,
        event: SecurityEvent,
        host: HostContext | None,
        lifecycle: str,
    ) -> datetime:
        """Return the eCAR render timestamp for a user-session observation."""
        auth = event.auth
        edr = event.edr
        canonical_timestamp = (
            event.source_timing.canonical_timestamp
            if event.source_timing is not None
            else event.timestamp
        )
        timestamp = _SOURCE_TIMING.source_time(
            event,
            "source.ecar_session",
            seed_parts=(
                lifecycle,
                self._host_name(host),
                getattr(auth, "username", ""),
                getattr(auth, "source_ip", ""),
                getattr(auth, "source_port", ""),
                getattr(auth, "logon_id", ""),
                getattr(auth, "logon_type", ""),
                getattr(edr, "object_id", ""),
                canonical_timestamp,
            ),
        )
        if event.event_type == "ssh_session" and lifecycle == "login":
            return self._remote_session_timestamp_after_flow(event, host, timestamp, dst_port=22)
        if (
            event.event_type == "logon"
            and lifecycle == "login"
            and getattr(auth, "logon_type", None) == 10
        ):
            return self._remote_session_timestamp_after_flow(event, host, timestamp, dst_port=3389)
        return timestamp

    def _remote_session_timestamp_after_flow(
        self,
        event: SecurityEvent,
        host: HostContext | None,
        timestamp: datetime,
        *,
        dst_port: int,
    ) -> datetime:
        """Keep eCAR remote session login after the matching inbound FLOW row."""
        auth = event.auth
        if auth is None or host is None or not auth.source_ip or not auth.source_port:
            return timestamp
        flow_time = getattr(self, "_remote_inbound_flow_times", {}).get(
            (
                host.hostname,
                auth.source_ip,
                int(auth.source_port),
                host.ip,
                dst_port,
            )
        )
        if flow_time is None or timestamp > flow_time:
            return timestamp
        seed = _stable_seed(
            "ecar_remote_login_after_flow:"
            f"{host.hostname}:{auth.source_ip}:{auth.source_port}:"
            f"{dst_port}:{getattr(auth, 'logon_id', '')}:{timestamp.isoformat()}"
        )
        return flow_time + timedelta(milliseconds=12 + (seed % 83))

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/CREATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_ts = self._process_create_timestamp(event, proc)
        event_data = {
            "timestamp": event_ts,
            "_canonical_ms": int((proc.start_time or event.timestamp).timestamp() * 1000),
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
            self._stable_tid(
                self._host_name(host),
                proc.pid,
                event_ts,
                "process_create",
                getattr(host, "os_category", ""),
            ),
        )
        self.emit_event(event_data)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/TERMINATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        event_data = {
            "timestamp": self._process_terminate_timestamp(event, proc),
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
            self._stable_tid(
                self._host_name(host),
                proc.pid,
                event.timestamp,
                "process_terminate",
                getattr(host, "os_category", ""),
            ),
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
            self._stable_tid(
                self._host_name(host),
                event_data["pid"],
                event.timestamp,
                "file",
                getattr(host, "os_category", ""),
            ),
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
            self._stable_tid(
                self._host_name(host),
                event_data["pid"],
                event.timestamp,
                "registry",
                getattr(host, "os_category", ""),
            ),
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
            self._stable_tid(
                self._host_name(host),
                event_data["pid"],
                event.timestamp,
                "module",
                getattr(host, "os_category", ""),
            ),
        )
        self.emit_event(event_data)

    def _render_connection(self, event: SecurityEvent) -> None:
        """Render eCAR FLOW/CONNECT events -- OUTBOUND on src_host, INBOUND on dst_host.

        For internal-to-internal connections, emits TWO records (one per host).
        For external-to-internal, emits only the INBOUND on dst_host.
        For internal-to-external, emits only the OUTBOUND on src_host.
        """
        net = event.network
        source_proc = event.process
        if (
            (source_proc is None or source_proc.start_time is None)
            and event.src_host is not None
            and net.initiating_pid > 0
        ):
            source_proc = self._lookup_running_process(event.src_host, net.initiating_pid)

        # OUTBOUND FLOW on source host (if source is internal/known)
        if event.src_host:
            not_before = (
                self._process_identity_not_before_timestamp(event, source_proc)
                if source_proc is not None
                else None
            )
            outbound_seed = (
                "outbound",
                event.src_host.hostname,
                net.initiating_pid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            )
            event_ts, process_identity_safe = self._flow_source_time(
                event,
                seed_parts=outbound_seed,
                not_before=not_before,
                drop_late_process_identity=(net.protocol == "tcp" and net.dst_port in {22, 3389}),
            )
            rendered_source_proc = source_proc if process_identity_safe else None
            rendered_pid = net.initiating_pid if process_identity_safe else -1
            event_data = {
                "timestamp": event_ts,
                "hostname": event.src_host.hostname,
                "object": "FLOW",
                "action": "CONNECT",
                "direction": "OUTBOUND",
                "pid": rendered_pid,
                "src_ip": net.src_ip,
                "src_port": net.src_port,
                "dst_ip": net.dst_ip,
                "dst_port": net.dst_port,
                "protocol": net.protocol,
                "_host_fqdn": self._host_fqdn(event.src_host),
            }
            principal = self._flow_principal_for_process(
                event,
                event.src_host,
                rendered_source_proc,
                "OUTBOUND",
            )
            if principal:
                event_data["principal"] = principal
            self._apply_flow_edr_context(event_data, event, include_actor=process_identity_safe)
            event_data.setdefault(
                "tid",
                self._stable_tid(
                    event.src_host.hostname,
                    rendered_pid,
                    event_ts,
                    "flow_outbound",
                    getattr(event.src_host, "os_category", ""),
                ),
            )
            self.emit_event(event_data)

        # INBOUND FLOW on destination host (if destination is internal/known)
        if event.dst_host:
            listener_observed = self._inbound_listener_observed(event)
            inbound_pid = self._resolve_inbound_service_pid(event) if listener_observed else -1
            inbound_seed = (
                "inbound",
                event.dst_host.hostname,
                net.initiating_pid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            )
            event_ts, _ = self._flow_source_time(
                event,
                seed_parts=inbound_seed,
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
            else:
                inbound_proc = self._lookup_running_process(event.dst_host, inbound_pid)
                if inbound_proc is not None:
                    event_ts, process_identity_safe = self._flow_source_time(
                        event,
                        seed_parts=inbound_seed,
                        not_before=self._process_identity_not_before_timestamp(
                            event,
                            inbound_proc,
                        ),
                        drop_late_process_identity=(
                            net.protocol == "tcp" and net.dst_port in {22, 3389}
                        ),
                    )
                    if not process_identity_safe:
                        inbound_proc = None
                        inbound_pid = -1
                        event_data["pid"] = inbound_pid
                    event_data["timestamp"] = event_ts
                principal = self._flow_principal_for_process(
                    event,
                    event.dst_host,
                    inbound_proc,
                    "INBOUND",
                )
                if principal:
                    event_data["principal"] = principal
                event_data.setdefault(
                    "tid",
                    self._stable_tid(
                        event.dst_host.hostname,
                        inbound_pid,
                        event_ts,
                        "flow_inbound",
                        getattr(event.dst_host, "os_category", ""),
                    ),
                )
                if net.protocol == "tcp" and net.dst_port in {22, 3389}:
                    self._remote_inbound_flow_times[
                        (
                            event.dst_host.hostname,
                            net.src_ip,
                            int(net.src_port or 0),
                            event.dst_host.ip,
                            int(net.dst_port or 0),
                        )
                    ] = event_ts
            # INBOUND flow gets its own objectID (separate telemetry observation)
            self.emit_event(event_data)

    def _flow_source_time(
        self,
        event: SecurityEvent,
        *,
        seed_parts: tuple[Any, ...],
        not_before: datetime | None = None,
        drop_late_process_identity: bool = False,
    ) -> tuple[datetime, bool]:
        """Return a FLOW timestamp bounded by the canonical connection interval.

        If a very short connection cannot also satisfy source-visible process-create
        ordering, omit the process identity from that FLOW row instead of moving the
        endpoint observation after the network close.
        """

        not_after = self._flow_not_after(event, seed_parts)
        if drop_late_process_identity and not_before is not None:
            flow_time = _SOURCE_TIMING.source_time(
                event,
                "source.ecar_flow",
                seed_parts=seed_parts,
                not_after=not_after,
            )
            if not_before > flow_time:
                return flow_time, False
            return flow_time, True

        process_identity_safe = not_before is None or not_after is None or not_before <= not_after
        return (
            _SOURCE_TIMING.source_time(
                event,
                "source.ecar_flow",
                seed_parts=seed_parts,
                not_before=not_before if process_identity_safe else None,
                not_after=not_after,
            ),
            process_identity_safe,
        )

    @staticmethod
    def _flow_identity_deadline(event: SecurityEvent) -> datetime:
        """Return the latest normal FLOW source time before process identity should be omitted."""

        window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )
        return event.timestamp + timedelta(milliseconds=window.max_ms + 1)

    @staticmethod
    def _flow_not_after(event: SecurityEvent, seed_parts: tuple[Any, ...]) -> datetime | None:
        """Return the latest source-native FLOW observation inside a connection interval."""

        net = event.network
        if net is None:
            return None
        if net.duration is None:
            if net.conn_state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR"}:
                return event.timestamp
            return None
        close_time = event.timestamp + timedelta(seconds=max(0.0, net.duration))
        if close_time <= event.timestamp:
            return close_time
        duration_us = int((close_time - event.timestamp).total_seconds() * 1_000_000)
        seed = _stable_seed("ecar_flow_not_after:" + ":".join(str(part) for part in seed_parts))
        margin_us = 1000 + (seed % 4000)
        if duration_us <= margin_us:
            margin_us = max(0, duration_us // 2)
        return close_time - timedelta(microseconds=margin_us)

    @staticmethod
    def _apply_flow_edr_context(
        event_data: dict[str, Any],
        event: SecurityEvent,
        *,
        include_actor: bool,
    ) -> None:
        """Copy eCAR FLOW identity fields, omitting actors when process timing conflicts."""

        if event.edr is None:
            return
        if event.edr.object_id:
            event_data["objectID"] = event.edr.object_id
        if include_actor and event.edr.actor_id:
            event_data["actorID"] = event.edr.actor_id
        if event.edr.tid != -1:
            event_data["tid"] = event.edr.tid

    def _flow_principal_for_process(
        self,
        event: SecurityEvent,
        host: HostContext | None,
        process: Any | None,
        direction: str,
    ) -> str:
        """Return a source-native mixed FLOW principal attribution value."""
        if host is None or process is None:
            return ""
        username = str(getattr(process, "username", "") or "").strip()
        if not username or username == "-":
            return ""
        pid = int(getattr(process, "pid", -1) or -1)
        net = event.network
        probability = _flow_principal_probability(username, direction)
        key = (
            f"ecar_flow_principal:{direction}:{host.hostname}:{pid}:"
            f"{net.src_ip}:{net.src_port}:{net.dst_ip}:{net.dst_port}:"
            f"{int(event.timestamp.timestamp() * 1000)}"
        )
        return username if _ecar_probability_enabled(key, probability) else ""

    def _lookup_running_process(self, host: HostContext, pid: int) -> Any | None:
        """Read a process from attached state when a connection only carries a PID."""
        state_manager = getattr(self, "_state_manager", None)
        if state_manager is None:
            return None
        return state_manager.get_process(host.hostname, pid)

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
        if net.dst_port in {22, 3389}:
            return self._resolve_system_listener_pid(host, net.dst_port)
        if net.responding_pid > 0:
            return net.responding_pid

        listener_pid = self._resolve_system_listener_pid(host, net.dst_port)
        if listener_pid > 0:
            return listener_pid
        return -1

    def _resolve_system_listener_pid(self, host: HostContext, dst_port: int) -> int:
        """Resolve a stable service listener PID for endpoint transport ownership."""
        system_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
        for candidate in _INBOUND_SERVICE_PID_CANDIDATES.get(dst_port, ()):
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
        event_ts = _SOURCE_TIMING.source_time(
            event,
            "source.ecar_remote_thread",
            seed_parts=(
                self._host_name(host),
                proc.pid if proc is not None else -1,
                target_pid,
                remote_thread.new_thread_id if remote_thread else 0,
                event.timestamp,
            ),
            not_before=self._after_process_create_timestamp(event, proc),
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
            else stable_uuid(
                "ecar-remote-thread-target",
                self._host_name(host),
                proc.pid if proc is not None else -1,
                target_pid,
                event_ts.isoformat(),
            ),
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
            "objectID": event.edr.object_id
            if event.edr
            else stable_uuid(
                "ecar-process-access-object",
                self._host_name(host),
                proc.pid,
                target_pid,
                event.timestamp.isoformat(),
            ),
            "actorID": event.edr.actor_id
            if event.edr
            else stable_uuid(
                "ecar-process-access-actor",
                self._host_name(host),
                proc.pid,
                target_pid,
                event.timestamp.isoformat(),
            ),
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
        not_before = start_time
        if host is not None and host.os_category == "windows":
            return _SOURCE_TIMING.source_time_after_source(
                event,
                "source.ecar_process_create",
                after_source_key="source.sysmon_process_create",
                gap_key="source.ecar_after_sysmon_process_create_gap",
                seed_parts=(hostname, proc.pid, start_time),
                after_not_before=start_time,
                not_before=start_time,
            )
        return _SOURCE_TIMING.source_time(
            event,
            "source.ecar_process_create",
            seed_parts=(hostname, proc.pid, start_time),
            not_before=not_before,
        )

    def _after_process_create_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Clamp dependent eCAR observations after their PROCESS/CREATE record."""
        if proc is None or proc.start_time is None:
            return event.timestamp
        if event.timestamp - proc.start_time >= timedelta(seconds=5):
            return _SOURCE_TIMING.source_time(
                event,
                "source.ecar_dependent_after_process_create",
                seed_parts=(
                    event.event_type,
                    self._host_name(event.src_host),
                    proc.pid,
                    event.timestamp,
                ),
                not_before=event.timestamp,
            )
        process_create_ts = self._process_create_timestamp(event, proc)
        return _SOURCE_TIMING.source_time(
            event,
            "source.ecar_dependent_after_process_create",
            seed_parts=(
                event.event_type,
                self._host_name(event.src_host),
                proc.pid,
                event.timestamp,
            ),
            not_before=process_create_ts + timedelta(milliseconds=1),
        )

    def _process_identity_not_before_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Return the earliest eCAR time that can safely claim a process identity."""
        if proc is None or proc.start_time is None:
            return event.timestamp
        if event.timestamp - proc.start_time >= timedelta(seconds=5):
            return proc.start_time
        return self._after_process_create_timestamp(event, proc)

    def _process_terminate_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Return an eCAR terminate timestamp preserving rendered process lifetime."""
        if proc is None or proc.start_time is None:
            return event.timestamp
        canonical_lifetime = max(timedelta(milliseconds=100), event.timestamp - proc.start_time)
        create_anchor_event = SecurityEvent(
            timestamp=proc.start_time,
            event_type="process_create",
            src_host=event.src_host,
            process=proc,
        )
        process_create_ts = self._process_create_timestamp(create_anchor_event, proc)
        return _SOURCE_TIMING.source_time(
            event,
            "source.ecar_process_terminate",
            seed_parts=(
                self._host_name(event.src_host),
                proc.pid,
                proc.start_time,
                event.timestamp,
            ),
            not_before=max(event.timestamp, process_create_ts + canonical_lifetime),
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

    @staticmethod
    def _looks_like_linux_process(record: dict[str, Any]) -> bool:
        """Return whether a PROCESS row is rendering a POSIX process image."""
        props = record.get("properties") or {}
        image_path = str(props.get("image_path") or "")
        return image_path.startswith("/")

    @classmethod
    def _normalize_linux_pid_morphology(cls, lines: list[str]) -> list[str]:
        """Keep Linux eCAR process PIDs increasing in source timestamp order."""
        records: list[dict[str, Any] | None] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

        create_indexes = [
            index
            for index, record in enumerate(records)
            if record is not None
            and record.get("object") == "PROCESS"
            and record.get("action") == "CREATE"
            and cls._looks_like_linux_process(record)
            and cls._ecar_int(record.get("pid")) > 0
        ]
        create_indexes.sort(
            key=lambda index: (
                cls._ecar_int(records[index].get("timestamp_ms"), 0)
                if records[index] is not None
                else 0,
                cls._ecar_int(records[index].get("pid")),
            )
        )

        new_pid_by_object_id: dict[str, int] = {}
        old_to_new_candidates: dict[int, set[int]] = {}
        latest_pid = 0
        for index in create_indexes:
            record = records[index]
            if record is None:
                continue
            old_pid = cls._ecar_int(record.get("pid"))
            new_pid = old_pid
            if latest_pid and new_pid <= latest_pid:
                seed_text = ":".join(
                    [
                        str(record.get("objectID", "")),
                        str(record.get("timestamp_ms", "")),
                        str(old_pid),
                    ]
                )
                new_pid = latest_pid + 1 + (sum(ord(ch) for ch in seed_text) % 17)
            latest_pid = new_pid
            object_id = str(record.get("objectID") or "")
            if object_id:
                new_pid_by_object_id[object_id] = new_pid
            old_to_new_candidates.setdefault(old_pid, set()).add(new_pid)

        old_pid_map = {
            old_pid: next(iter(new_pids))
            for old_pid, new_pids in old_to_new_candidates.items()
            if len(new_pids) == 1
        }

        def rewrite_pid_field(record: dict[str, Any]) -> None:
            object_id = str(record.get("objectID") or "")
            actor_id = str(record.get("actorID") or "")
            if record.get("object") == "PROCESS" and record.get("action") == "OPEN":
                new_pid = new_pid_by_object_id.get(actor_id) or new_pid_by_object_id.get(object_id)
            else:
                new_pid = new_pid_by_object_id.get(object_id) or new_pid_by_object_id.get(actor_id)
            if new_pid is None:
                old_pid = cls._ecar_int(record.get("pid"))
                new_pid = old_pid_map.get(old_pid)
            if new_pid is None:
                return
            old_pid = cls._ecar_int(record.get("pid"))
            record["pid"] = new_pid
            if cls._ecar_int(record.get("tid")) == old_pid:
                record["tid"] = new_pid

        def rewrite_parent_field(record: dict[str, Any]) -> None:
            parent_id = str(record.get("actorID") or "")
            parent_pid = cls._ecar_int(record.get("ppid"))
            new_parent_pid = new_pid_by_object_id.get(parent_id) or old_pid_map.get(parent_pid)
            if new_parent_pid is not None:
                record["ppid"] = new_parent_pid

        def rewrite_property_pid(record: dict[str, Any], pid_key: str, object_key: str) -> None:
            props = record.get("properties")
            if not isinstance(props, dict):
                return
            object_id = str(props.get(object_key) or "")
            old_pid = cls._ecar_int(props.get(pid_key))
            new_pid = new_pid_by_object_id.get(object_id) or old_pid_map.get(old_pid)
            if new_pid is not None:
                props[pid_key] = new_pid

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            rewrite_pid_field(record)
            if record.get("object") == "PROCESS":
                rewrite_parent_field(record)
            rewrite_property_pid(record, "target_pid", "target_process_uuid")
            rewrite_property_pid(record, "target_pid", "target_process_object_id")
            rewrite_property_pid(record, "source_pid", "source_process_object_id")
            normalized.append(json.dumps(record, separators=(",", ":")))
        return normalized

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
    def _filter_stale_process_references_after_termination(cls, lines: list[str]) -> list[str]:
        """Drop or de-attrib stale process-owned rows after PROCESS/TERMINATE."""
        records: list[dict[str, Any] | None] = []
        terminate_ms_by_process_id: dict[str, int] = {}
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                records.append(None)
                continue
            records.append(record)
            if record.get("object") != "PROCESS" or record.get("action") != "TERMINATE":
                continue
            process_id = str(record.get("objectID") or "")
            if not process_id:
                continue
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            current = terminate_ms_by_process_id.get(process_id)
            if current is None or timestamp_ms < current:
                terminate_ms_by_process_id[process_id] = timestamp_ms

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            if record.get("object") == "PROCESS":
                normalized.append(line)
                continue
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            stale_threshold_ms = (
                cls._stale_process_reference_grace_ms
                if record.get("object") == "FLOW"
                else cls._post_termination_dependent_grace_ms
            )
            stale_refs = [
                process_id
                for process_id in cls._referenced_process_ids(record)
                if (
                    process_id in terminate_ms_by_process_id
                    and timestamp_ms > terminate_ms_by_process_id[process_id] + stale_threshold_ms
                )
            ]
            if not stale_refs:
                normalized.append(line)
                continue
            if record.get("object") == "FLOW":
                cls._drop_flow_process_identity(record)
                normalized.append(json.dumps(record, separators=(",", ":")))
                continue
            continue
        return normalized

    @classmethod
    def _normalize_parent_termination_after_children(cls, lines: list[str]) -> list[str]:
        """Keep visible parents alive through visible child process lifecycles."""
        records: list[dict[str, Any] | None] = []
        object_by_pid: dict[int, str] = {}
        child_parent: dict[str, tuple[str | None, int, int]] = {}
        child_last_ms: dict[str, int] = {}

        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                records.append(None)
                continue
            records.append(record)
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            if record.get("object") != "PROCESS":
                continue
            action = record.get("action")
            object_id = str(record.get("objectID", ""))
            pid = cls._ecar_int(record.get("pid"))
            if action == "CREATE":
                if object_id and pid > 0:
                    object_by_pid[pid] = object_id
                parent_id = str(record.get("actorID") or "") or None
                parent_pid = cls._ecar_int(record.get("ppid"))
                child_parent[object_id] = (parent_id, parent_pid, timestamp_ms)
                child_last_ms[object_id] = max(child_last_ms.get(object_id, 0), timestamp_ms)
            elif action == "TERMINATE" and object_id:
                child_last_ms[object_id] = max(child_last_ms.get(object_id, 0), timestamp_ms)

        latest_child_ms_by_parent_id: dict[str, int] = {}
        latest_child_ms_by_parent_pid: dict[int, int] = {}
        for child_id, (parent_id, parent_pid, create_ms) in child_parent.items():
            latest_child_ms = max(create_ms, child_last_ms.get(child_id, create_ms))
            if parent_id:
                latest_child_ms_by_parent_id[parent_id] = max(
                    latest_child_ms_by_parent_id.get(parent_id, 0),
                    latest_child_ms,
                )
            elif parent_pid > 0:
                resolved_parent_id = object_by_pid.get(parent_pid)
                if resolved_parent_id:
                    latest_child_ms_by_parent_id[resolved_parent_id] = max(
                        latest_child_ms_by_parent_id.get(resolved_parent_id, 0),
                        latest_child_ms,
                    )
            if parent_pid > 0:
                latest_child_ms_by_parent_pid[parent_pid] = max(
                    latest_child_ms_by_parent_pid.get(parent_pid, 0),
                    latest_child_ms,
                )

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            if record.get("object") == "PROCESS" and record.get("action") == "TERMINATE":
                object_id = str(record.get("objectID", ""))
                pid = cls._ecar_int(record.get("pid"))
                timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
                latest_child_ms = max(
                    latest_child_ms_by_parent_id.get(object_id, 0),
                    latest_child_ms_by_parent_pid.get(pid, 0),
                )
                if (
                    latest_child_ms >= timestamp_ms
                    and latest_child_ms - timestamp_ms <= cls._stale_process_reference_grace_ms
                ):
                    stable_delay_ms = 20 + (sum(ord(ch) for ch in object_id) % 480)
                    record["timestamp_ms"] = latest_child_ms + stable_delay_ms
                    line = json.dumps(record, separators=(",", ":"))
            normalized.append(line)
        return normalized

    @staticmethod
    def _ecar_int(value: Any, default: int = -1) -> int:
        """Return an integer eCAR field value or a deterministic fallback."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def _normalize_process_create_canonical_order(cls, lines: list[str]) -> list[str]:
        """Keep PROCESS/CREATE rows ordered by canonical process start time."""
        records: list[dict[str, Any] | None] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

        create_indexes = [
            index
            for index, record in enumerate(records)
            if record is not None
            and record.get("object") == "PROCESS"
            and record.get("action") == "CREATE"
            and "_canonical_ms" in record
            and not cls._looks_like_linux_process(record)
        ]
        create_indexes.sort(
            key=lambda index: (
                cls._ecar_int(records[index].get("_canonical_ms"), 0)
                if records[index] is not None
                else 0,
                cls._ecar_int(records[index].get("pid"), 0) if records[index] is not None else 0,
            )
        )

        latest_render_ms = 0
        for index in create_indexes:
            record = records[index]
            if record is None:
                continue
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            if latest_render_ms and timestamp_ms <= latest_render_ms:
                timestamp_ms = latest_render_ms + 1
                record["timestamp_ms"] = timestamp_ms
            latest_render_ms = timestamp_ms

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            record.pop("_canonical_ms", None)
            normalized.append(json.dumps(record, separators=(",", ":")))
        return normalized

    _LINUX_SHELL_FOREGROUND_EXES = {
        "cargo",
        "cat",
        "curl",
        "date",
        "df",
        "docker",
        "du",
        "emacs",
        "env",
        "find",
        "free",
        "gcc",
        "grep",
        "gzip",
        "head",
        "hostname",
        "id",
        "ip",
        "journalctl",
        "kubectl",
        "ldapsearch",
        "ls",
        "make",
        "mysql",
        "mysqldump",
        "nano",
        "npm",
        "pg_isready",
        "printenv",
        "ps",
        "psql",
        "pwd",
        "python",
        "python3",
        "redis-cli",
        "scp",
        "sleep",
        "ss",
        "sqlite3",
        "systemctl",
        "tar",
        "test",
        "tail",
        "true",
        "uname",
        "vi",
        "vim",
        "wc",
        "wget",
        "whoami",
        "zip",
    }
    _LINUX_SHELL_PIPELINE_CREATE_WINDOW_MS = 1000

    @classmethod
    def _is_linux_shell_foreground_create(cls, record: dict[str, Any]) -> bool:
        """Return whether an eCAR row is a foreground Linux child of a shell."""
        if record.get("object") != "PROCESS" or record.get("action") != "CREATE":
            return False
        props = record.get("properties") or {}
        image = str(props.get("image_path") or "")
        parent_image = str(props.get("parent_image_path") or "")
        command_line = str(props.get("command_line") or "")
        if "|" in command_line or cls._is_backgrounded_shell_command(command_line):
            return False
        exe = image.rsplit("/", 1)[-1].lower()
        parent_exe = parent_image.rsplit("/", 1)[-1].lower()
        return exe in cls._LINUX_SHELL_FOREGROUND_EXES and parent_exe in {"bash", "sh", "zsh"}

    @staticmethod
    def _is_backgrounded_shell_command(command_line: str) -> bool:
        """Return whether a shell command should not block later foreground children."""
        normalized = command_line.strip().lower()
        if not normalized:
            return False
        return (
            normalized.endswith("&")
            or " nohup " in f" {normalized} "
            or "tail -f" in normalized
            or "watch " in normalized
            or "--follow" in normalized
        )

    @classmethod
    def _normalize_linux_shell_foreground_order(cls, lines: list[str]) -> list[str]:
        """Serialize foreground shell commands while preserving pipeline concurrency."""
        records: list[dict[str, Any] | None] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

        terminate_ms_by_object_id: dict[str, int] = {}
        for record in records:
            if (
                record is not None
                and record.get("object") == "PROCESS"
                and record.get("action") == "TERMINATE"
            ):
                object_id = str(record.get("objectID") or "")
                if object_id:
                    terminate_ms_by_object_id[object_id] = max(
                        terminate_ms_by_object_id.get(object_id, 0),
                        cls._ecar_int(record.get("timestamp_ms"), 0),
                    )

        create_indexes_by_shell: dict[tuple[str, str, int, str], list[int]] = {}
        for index, record in enumerate(records):
            if record is None or not cls._is_linux_shell_foreground_create(record):
                continue
            shell_key = (
                str(record.get("hostname") or ""),
                str(record.get("principal") or ""),
                cls._ecar_int(record.get("ppid")),
                str(record.get("actorID") or ""),
            )
            create_indexes_by_shell.setdefault(shell_key, []).append(index)

        shift_by_object_id: dict[str, int] = {}
        for indexes in create_indexes_by_shell.values():
            indexes.sort(
                key=lambda index: (
                    cls._ecar_int(records[index].get("timestamp_ms"), 0)
                    if records[index] is not None
                    else 0,
                    cls._ecar_int(records[index].get("pid"), 0)
                    if records[index] is not None
                    else 0,
                )
            )
            next_available_ms = 0
            groups: list[list[int]] = []
            for index in indexes:
                record = records[index]
                if record is None:
                    continue
                timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
                if groups:
                    first_record = records[groups[-1][0]]
                    first_ms = (
                        cls._ecar_int(first_record.get("timestamp_ms"), 0)
                        if first_record is not None
                        else 0
                    )
                    if timestamp_ms <= first_ms + cls._LINUX_SHELL_PIPELINE_CREATE_WINDOW_MS:
                        groups[-1].append(index)
                        continue
                groups.append([index])

            for group in groups:
                group_records = [records[index] for index in group if records[index] is not None]
                if not group_records:
                    continue
                group_start_ms = min(
                    cls._ecar_int(record.get("timestamp_ms"), 0) for record in group_records
                )
                shift_ms = 0
                if next_available_ms and group_start_ms <= next_available_ms:
                    seed_text = ":".join(
                        ":".join(
                            [
                                str(record.get("objectID") or ""),
                                str(record.get("pid", "")),
                                str(record.get("id", "")),
                            ]
                        )
                        for record in group_records
                    )
                    shifted_ms = next_available_ms + 50 + (sum(ord(ch) for ch in seed_text) % 950)
                    shift_ms = shifted_ms - group_start_ms

                group_latest_ms = next_available_ms
                for record in group_records:
                    timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
                    object_id = str(record.get("objectID") or "")
                    if shift_ms:
                        timestamp_ms += shift_ms
                        record["timestamp_ms"] = timestamp_ms
                        if object_id:
                            shift_by_object_id[object_id] = shift_ms
                    if object_id and object_id in terminate_ms_by_object_id:
                        group_latest_ms = max(
                            group_latest_ms,
                            terminate_ms_by_object_id[object_id] + shift_ms,
                        )
                    else:
                        group_latest_ms = max(group_latest_ms, timestamp_ms)
                next_available_ms = max(next_available_ms, group_latest_ms)

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            object_id = str(record.get("objectID") or "")
            shift_ms = shift_by_object_id.get(object_id, 0)
            if (
                shift_ms
                and record.get("object") == "PROCESS"
                and record.get("action") == "TERMINATE"
            ):
                record["timestamp_ms"] = cls._ecar_int(record.get("timestamp_ms"), 0) + shift_ms
            normalized.append(json.dumps(record, separators=(",", ":")))
        return normalized

    @classmethod
    def _normalize_process_parent_order(cls, lines: list[str]) -> list[str]:
        """Move PROCESS/CREATE rows after visible parent PROCESS/CREATE rows."""
        records: list[dict[str, Any] | None] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

        create_indexes = [
            index
            for index, record in enumerate(records)
            if record is not None
            and record.get("object") == "PROCESS"
            and record.get("action") == "CREATE"
        ]
        index_by_object_id: dict[str, int] = {}
        index_by_pid: dict[int, int] = {}
        for index in create_indexes:
            record = records[index]
            if record is None:
                continue
            object_id = record.get("objectID")
            if object_id:
                index_by_object_id[str(object_id)] = index
            pid = cls._ecar_int(record.get("pid"))
            if pid > 0:
                current_index = index_by_pid.get(pid)
                if current_index is None:
                    index_by_pid[pid] = index
                    continue
                current_record = records[current_index]
                current_ms = (
                    cls._ecar_int(current_record.get("timestamp_ms"), 0)
                    if current_record is not None
                    else 0
                )
                if cls._ecar_int(record.get("timestamp_ms"), 0) >= current_ms:
                    index_by_pid[pid] = index

        parent_by_index: dict[int, int] = {}
        for index in create_indexes:
            record = records[index]
            if record is None:
                continue
            parent_index: int | None = None
            parent_id = record.get("actorID")
            if parent_id:
                parent_index = index_by_object_id.get(str(parent_id))
            if parent_index is None:
                pid = cls._ecar_int(record.get("pid"))
                parent_pid = cls._ecar_int(record.get("ppid"))
                if parent_pid > 0 and parent_pid != pid:
                    parent_index = index_by_pid.get(parent_pid)
            if parent_index is not None and parent_index != index:
                parent_by_index[index] = parent_index

        cyclic_indexes: set[int] = set()
        for index in parent_by_index:
            seen: set[int] = set()
            current = index
            while current in parent_by_index:
                if current in seen:
                    cyclic_indexes.update(seen)
                    break
                seen.add(current)
                current = parent_by_index[current]
        parent_by_index = {
            index: parent_index
            for index, parent_index in parent_by_index.items()
            if index not in cyclic_indexes and parent_index not in cyclic_indexes
        }

        for _ in range(len(parent_by_index)):
            changed = False
            for index, parent_index in parent_by_index.items():
                record = records[index]
                parent = records[parent_index]
                if record is None or parent is None:
                    continue
                parent_ms = cls._ecar_int(parent.get("timestamp_ms"), 0)
                timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
                if timestamp_ms <= parent_ms:
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

    @classmethod
    def _normalize_process_reference_order(cls, lines: list[str]) -> list[str]:
        """Move process-owned telemetry after visible PROCESS/CREATE rows."""
        records: list[dict[str, Any] | None] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(None)

        create_ms_by_object_id: dict[str, int] = {}
        create_ms_by_pid: dict[int, int] = {}
        for record in records:
            if (
                record is None
                or record.get("object") != "PROCESS"
                or record.get("action") != "CREATE"
            ):
                continue
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            object_id = record.get("objectID")
            if object_id:
                create_ms_by_object_id[str(object_id)] = max(
                    create_ms_by_object_id.get(str(object_id), 0),
                    timestamp_ms,
                )
            pid = cls._ecar_int(record.get("pid"))
            if pid > 0:
                create_ms_by_pid[pid] = max(create_ms_by_pid.get(pid, 0), timestamp_ms)

        def referenced_process_ids(record: dict[str, Any]) -> set[str]:
            refs: set[str] = set()
            actor_id = record.get("actorID")
            if actor_id:
                refs.add(str(actor_id))
            if record.get("object") == "PROCESS" and record.get("action") == "OPEN":
                object_id = record.get("objectID")
                if object_id:
                    refs.add(str(object_id))
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

        normalized: list[str] = []
        for line, record in zip(lines, records, strict=True):
            if record is None:
                normalized.append(line)
                continue
            if record.get("object") == "PROCESS" and record.get("action") == "CREATE":
                normalized.append(line)
                continue

            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            referenced_create_ms = [
                create_ms_by_object_id[process_id]
                for process_id in referenced_process_ids(record)
                if process_id in create_ms_by_object_id
            ]
            pid = cls._ecar_int(record.get("pid"))
            if pid > 0 and pid in create_ms_by_pid:
                referenced_create_ms.append(create_ms_by_pid[pid])
            if referenced_create_ms:
                minimum_ms = max(referenced_create_ms)
                if timestamp_ms <= minimum_ms:
                    if record.get("object") == "FLOW":
                        if record.get("action") == "CONNECT":
                            cls._drop_flow_process_identity(record)
                            normalized.append(json.dumps(record, separators=(",", ":")))
                            continue
                        if (
                            minimum_ms - timestamp_ms
                            > cls._pre_process_flow_identity_repair_grace_ms
                        ):
                            cls._drop_flow_process_identity(record)
                            normalized.append(json.dumps(record, separators=(",", ":")))
                            continue
                    seed_text = ":".join(
                        [
                            str(record.get("id", "")),
                            str(record.get("object", "")),
                            str(record.get("action", "")),
                            str(record.get("objectID", "")),
                            str(record.get("actorID", "")),
                        ]
                    )
                    stable_delay_ms = 1 + (sum(ord(ch) for ch in seed_text) % 37)
                    record["timestamp_ms"] = minimum_ms + stable_delay_ms
                    line = json.dumps(record, separators=(",", ":"))
            normalized.append(line)
        return normalized

    @staticmethod
    def _drop_flow_process_identity(record: dict[str, Any]) -> None:
        """Remove process attribution from a FLOW that cannot safely claim it."""
        record.pop("actorID", None)
        record.pop("pid", None)
        record.pop("principal", None)
        props = record.get("properties")
        if isinstance(props, dict):
            for key in ("image_path", "command_line", "parent_image_path"):
                props.pop(key, None)

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

    @classmethod
    def _filter_after_output_window(
        cls,
        lines: list[str],
        output_end_time: datetime | None,
    ) -> list[str]:
        """Drop renderer-shifted rows that land outside the scenario collection window."""
        if output_end_time is None:
            return lines
        output_end_ms = int(output_end_time.timestamp() * 1000)
        filtered: list[str] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                filtered.append(line)
                continue
            timestamp_ms = cls._ecar_int(record.get("timestamp_ms"), 0)
            if timestamp_ms <= 0 or timestamp_ms < output_end_ms:
                filtered.append(line)
        return filtered

    def flush(self, force: bool = False) -> None:
        """Flush per-host eCAR records after final lifecycle normalization."""
        if force:
            with self._writers_lock:
                writers = list(self._writers.values())
            for writer in writers:
                with writer._lock:
                    writer.buffer = self._normalize_process_parent_order(writer.buffer)
                    writer.buffer = self._normalize_process_create_canonical_order(writer.buffer)
                    writer.buffer = self._normalize_linux_pid_morphology(writer.buffer)
                    writer.buffer = self._normalize_process_parent_order(writer.buffer)
                    writer.buffer = self._normalize_process_create_canonical_order(writer.buffer)
                    writer.buffer = self._normalize_linux_pid_morphology(writer.buffer)
                    writer.buffer = self._normalize_linux_shell_foreground_order(writer.buffer)
                    writer.buffer = self._normalize_linux_pid_morphology(writer.buffer)
                    writer.buffer = self._normalize_process_reference_order(writer.buffer)
                    writer.buffer = self._filter_stale_process_references_after_termination(
                        writer.buffer
                    )
                    writer.buffer = self._normalize_process_termination_order(writer.buffer)
                    writer.buffer = self._normalize_parent_termination_after_children(writer.buffer)
                    writer.buffer = self._deduplicate_semantic_events(writer.buffer)
                    writer.buffer = self._filter_after_output_window(
                        writer.buffer,
                        self._output_end_time,
                    )
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
        "logon_type",
        "session_type",
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
        comma-handling logic in the old template and enforces source-native
        optionality: pid/tid/ppid are emitted only when known, and all property
        values are strings.
        """
        # Convert timestamp to milliseconds since epoch
        ts = event_data["timestamp"]
        timestamp_ms = int(ts.timestamp() * 1000) if isinstance(ts, datetime) else int(ts * 1000)
        object_id = event_data.get("objectID") or self._stable_record_uuid(
            "object",
            event_data,
            timestamp_ms,
        )
        record_id = event_data.get("id") or self._stable_record_uuid(
            "event",
            event_data,
            timestamp_ms,
            object_id,
            event_data.get("actorID", ""),
        )

        record: dict[str, Any] = {
            "timestamp_ms": timestamp_ms,
            "id": record_id,
            "hostname": event_data.get("hostname", ""),
            "object": event_data["object"],
            "action": event_data["action"],
            "objectID": object_id,
        }
        if "_canonical_ms" in event_data:
            record["_canonical_ms"] = event_data["_canonical_ms"]

        if event_data.get("actorID"):
            record["actorID"] = event_data["actorID"]

        # pid/tid are optional in the format definition.  Emit them only when
        # a source-native value is known; avoiding synthetic negative sentinels
        # keeps session and failed-flow rows from looking like concrete IDs.
        for key in ("pid", "tid", "ppid"):
            if key not in event_data:
                continue
            value = event_data[key]
            if value is None:
                continue
            try:
                int_value = int(value)
            except (TypeError, ValueError):
                continue
            if int_value < 0:
                continue
            record[key] = int_value

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
