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
from evidenceforge.events.contexts import HostContext, NetworkContext
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    ecar_flow_identity_key,
    ecar_flow_render_key,
    ecar_session_render_key,
)
from evidenceforge.utils.rng import stable_uuid

_ECAR_SORT_PRIORITY = {
    ("USER_SESSION", "LOGIN"): 0,
    ("PROCESS", "CREATE"): 1,
    ("MODULE", "LOAD"): 2,
    ("REGISTRY", "MODIFY"): 3,
    ("FILE", "CREATE"): 4,
    ("FILE", "READ"): 5,
    ("FILE", "WRITE"): 6,
    ("FLOW", "CONNECT"): 7,
    ("PROCESS", "OPEN"): 8,
    ("THREAD", "REMOTE_CREATE"): 9,
    ("PROCESS", "TERMINATE"): 10,
    ("USER_SESSION", "LOGOUT"): 11,
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

_PORT_BEARING_PROTOCOLS = {"tcp", "udp", "sctp"}


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


def _ecar_flow_endpoint_properties(
    net: NetworkContext,
    *,
    dst_ip: str | None = None,
    direction: str,
) -> dict[str, Any]:
    """Return source-native FLOW endpoint properties for eCAR rendering."""
    protocol = (net.protocol or "").lower()
    properties: dict[str, Any] = {
        "src_ip": net.src_ip,
        "dst_ip": dst_ip or net.dst_ip,
        "protocol": net.protocol,
        "direction": direction,
    }
    if protocol in _PORT_BEARING_PROTOCOLS:
        properties["src_port"] = net.src_port
        properties["dst_port"] = net.dst_port
    elif protocol == "icmp":
        properties["icmp_type"] = 8
        properties["icmp_code"] = 0
    return properties


def _ecar_remote_auth_transport_properties(event: SecurityEvent) -> dict[str, Any]:
    """Return the exact primary transport view for a remote authentication."""

    remote_auth = event.remote_auth
    transport = remote_auth.primary_transport if remote_auth is not None else None
    if transport is None:
        return {}
    tuple_view = transport.tuple
    return {
        "src_ip": tuple_view.src_ip,
        "src_port": tuple_view.src_port,
        "dst_ip": tuple_view.dst_ip,
        "dst_port": tuple_view.dst_port,
        "protocol": tuple_view.protocol,
    }


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
        "machine_logon",
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
            "machine_logon": self._render_logon,
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
        """Project canonical identity roles into eCAR and retained compatibility fields."""
        plan = event.identity_plan
        if plan is not None:
            if plan.object_id:
                event_data["objectID"] = plan.object_id
            if plan.actor_id:
                event_data["actorID"] = plan.actor_id
            if (
                isinstance(plan.subject, ThreadIdentity)
                and event.event_type != "create_remote_thread"
            ):
                event_data["tid"] = plan.subject.tid
            elif (
                isinstance(plan.subject, ProcessIdentity)
                and event.event_type
                in {"process_create", "system_process_create", "process_terminate"}
                and plan.subject.primary_thread is not None
            ):
                event_data["tid"] = plan.subject.primary_thread.tid
            EcarEmitter._apply_explicit_identity_roles(event_data, event)
            return
        if event.edr is not None:
            if event.edr.object_id:
                event_data["objectID"] = event.edr.object_id
            if event.edr.actor_id:
                event_data["actorID"] = event.edr.actor_id
            if event.edr.tid >= 0:
                event_data["tid"] = event.edr.tid

    @staticmethod
    def _apply_explicit_identity_roles(
        event_data: dict[str, Any],
        event: SecurityEvent,
    ) -> None:
        """Render optional symmetric source/target process identity fields."""

        plan = event.identity_plan
        if plan is None:
            return
        source = plan.actor if isinstance(plan.actor, ProcessIdentity) else None
        target = plan.target if isinstance(plan.target, ProcessIdentity) else None
        if source is not None:
            event_data.update(
                {
                    "source_process_uuid": source.object_id,
                    "source_pid": str(source.pid),
                    "source_image_path": source.image,
                    "source_principal": source.principal,
                    "src_pid": str(source.pid),
                }
            )
            source_tid = -1
            if event.process_access is not None:
                source_tid = event.process_access.source_thread_id
            elif event.remote_thread is not None:
                source_tid = event.remote_thread.source_thread_id
            if source_tid >= 0:
                event_data["source_tid"] = str(source_tid)
                event_data["src_tid"] = str(source_tid)
        if target is not None:
            event_data.update(
                {
                    "target_process_uuid": target.object_id,
                    "target_pid": str(target.pid),
                    "target_image_path": target.image,
                    "target_principal": target.principal,
                }
            )
        if isinstance(plan.subject, ThreadIdentity):
            if source is not None and plan.subject.process_object_id == source.object_id:
                event_data["source_tid"] = str(plan.subject.tid)
                event_data["src_tid"] = str(plan.subject.tid)
            if target is not None and plan.subject.process_object_id == target.object_id:
                event_data["target_tid"] = str(plan.subject.tid)
                event_data["tgt_tid"] = str(plan.subject.tid)

    @staticmethod
    def _apply_flow_actor(
        event_data: dict[str, Any],
        process: ProcessIdentity,
    ) -> None:
        """Project only the host-local actor onto a source-native FLOW row."""

        event_data["actorID"] = process.object_id

    @staticmethod
    def _apply_session_properties(event_data: dict[str, Any], event: SecurityEvent) -> None:
        """Copy durable source-native session identifiers onto session-owned rows."""
        auth = event.auth
        process = event.process
        logon_id = ""
        if auth is not None:
            logon_id = auth.logon_id
        if not logon_id and process is not None:
            logon_id = getattr(process, "logon_id", "") or ""
        if logon_id:
            event_data["logon_id"] = logon_id
        if auth is not None and auth.session_id:
            event_data["session_id"] = auth.session_id
        if auth is not None and auth.logon_guid:
            event_data["logon_guid"] = auth.logon_guid

    @staticmethod
    def _apply_process_provenance(event_data: dict[str, Any], process: Any | None) -> None:
        """Copy known process provenance onto dependent source-native eCAR rows."""
        if process is None:
            return
        image = str(getattr(process, "image", "") or "")
        if image and not event_data.get("image_path"):
            event_data["image_path"] = image
        command_line = str(getattr(process, "command_line", "") or "")
        if command_line and not event_data.get("command_line"):
            event_data["command_line"] = command_line

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

    def _emit_canonical_event(
        self,
        event_data: dict[str, Any],
        event: SecurityEvent,
    ) -> None:
        """Render one eCAR observation from its canonical occurrence identity."""

        if event.event_id:
            event_data["_event_id"] = event.event_id
        self.emit_event(event_data)

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
        if event_data["src_ip"] != "-" and event.auth.source_port:
            event_data["src_port"] = event.auth.source_port
        event_data.update(_ecar_remote_auth_transport_properties(event))
        if getattr(host, "os_category", "") == "windows":
            event_data["logon_type"] = event.auth.logon_type
        else:
            event_data["session_type"] = _ecar_non_windows_session_type(event)
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

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
        if getattr(host, "os_category", "") == "windows":
            event_data["logon_type"] = event.auth.logon_type
        else:
            event_data["session_type"] = _ecar_non_windows_session_type(event)
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

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
        event_data.update(_ecar_remote_auth_transport_properties(event))
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _session_timestamp(
        self,
        event: SecurityEvent,
        host: HostContext | None,
        lifecycle: str,
    ) -> datetime:
        """Return the eCAR render timestamp for a user-session observation."""
        plan = event.source_timing
        if plan is None:
            return event.timestamp
        return plan.finalized_times.get(
            ecar_session_render_key(lifecycle),
            event.timestamp,
        )

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/CREATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        plan = event.identity_plan
        process_identity = (
            plan.subject if plan is not None and isinstance(plan.subject, ProcessIdentity) else proc
        )
        event_ts = self._process_create_timestamp(event, process_identity)
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
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/TERMINATE event (logged on src_host)."""
        host = event.src_host
        proc = event.process
        plan = event.identity_plan
        process_identity = (
            plan.subject if plan is not None and isinstance(plan.subject, ProcessIdentity) else proc
        )
        event_data = {
            "timestamp": self._process_terminate_timestamp(event, process_identity),
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "TERMINATE",
            "pid": proc.pid,
            "principal": proc.username,
            "image_path": proc.image,
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _render_file_event(self, event: SecurityEvent) -> None:
        """Render eCAR FILE event from canonical FileContext (logged on src_host)."""
        host = event.src_host
        proc = event.process
        plan = event.identity_plan
        process_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else proc
        )
        action_map = {
            "file_read": "READ",
            "file_create": "CREATE",
            "file_modify": "WRITE",
            "file_delete": "DELETE",
        }
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, process_identity),
            "hostname": self._host_name(host),
            "object": "FILE",
            "action": action_map.get(event.event_type, "CREATE"),
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_process_provenance(event_data, proc)
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _render_registry_event(self, event: SecurityEvent) -> None:
        """Render eCAR REGISTRY event from canonical RegistryContext (logged on src_host)."""
        host = event.src_host
        proc = event.process
        plan = event.identity_plan
        process_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else proc
        )
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, process_identity),
            "hostname": self._host_name(host),
            "object": "REGISTRY",
            "action": "MODIFY",
            "pid": event.registry.pid if event.registry else -1,
            "principal": event.auth.username if event.auth else "",
            "registry_key": event.registry.key if event.registry else "",
            "registry_value": event.registry.value if event.registry else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_process_provenance(event_data, proc)
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _render_module_event(self, event: SecurityEvent) -> None:
        """Render eCAR MODULE/LOAD event from canonical ImageLoadContext."""
        host = event.src_host
        proc = event.process
        plan = event.identity_plan
        process_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else proc
        )
        module_path = ""
        if event.image_load is not None:
            module_path = event.image_load.image_loaded
        elif event.file is not None:
            module_path = event.file.path
        event_data = {
            "timestamp": self._after_process_create_timestamp(event, process_identity),
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
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _render_connection(self, event: SecurityEvent) -> None:
        """Render eCAR FLOW/CONNECT events -- OUTBOUND on src_host, INBOUND on dst_host.

        For internal-to-internal connections, emits TWO records (one per host).
        For external-to-internal, emits only the INBOUND on dst_host.
        For internal-to-external, emits only the OUTBOUND on src_host.
        """
        net = event.network
        plan = event.identity_plan
        source_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else None
        )
        target_identity = (
            plan.target if plan is not None and isinstance(plan.target, ProcessIdentity) else None
        )
        source_proc = source_identity

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
                paired_endpoint=event.dst_host is not None,
            )
            rendered_source_proc = source_proc if process_identity_safe else None
            rendered_pid = (
                int(getattr(rendered_source_proc, "pid", -1))
                if rendered_source_proc is not None
                else -1
            )
            event_data = {
                "timestamp": event_ts,
                "hostname": event.src_host.hostname,
                "object": "FLOW",
                "action": "CONNECT",
                "pid": rendered_pid,
                "_host_fqdn": self._host_fqdn(event.src_host),
                **_ecar_flow_endpoint_properties(net, direction="OUTBOUND"),
            }
            if self._flow_connection_failed(net):
                event_data["outcome"] = "failure"
                event_data["connection_state"] = net.conn_state
            principal = str(
                getattr(rendered_source_proc, "principal", "")
                or getattr(rendered_source_proc, "username", "")
            )
            if principal:
                event_data["principal"] = principal
            if process_identity_safe and rendered_source_proc is not None:
                self._apply_process_provenance(event_data, rendered_source_proc)
            if process_identity_safe and rendered_source_proc is not None:
                self._apply_flow_actor(event_data, rendered_source_proc)
            self._emit_canonical_event(event_data, event)

        # INBOUND FLOW on destination host (if destination is internal/known)
        if event.dst_host:
            listener_observed = self._inbound_listener_observed(event)
            inbound_proc = target_identity if listener_observed else None
            inbound_pid = target_identity.pid if inbound_proc is not None else -1
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
                paired_endpoint=event.src_host is not None,
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
                "pid": inbound_pid,
                "_host_fqdn": self._host_fqdn(event.dst_host),
                **_ecar_flow_endpoint_properties(net, dst_ip=dst_ip, direction="INBOUND"),
            }
            if self._flow_connection_failed(net):
                event_data["outcome"] = "failure"
                event_data["connection_state"] = net.conn_state
            if listener_observed and inbound_proc is not None:
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
                    paired_endpoint=event.src_host is not None,
                )
                if not process_identity_safe:
                    inbound_proc = None
                    inbound_pid = -1
                    event_data["pid"] = inbound_pid
                event_data["timestamp"] = event_ts
            if inbound_proc is not None:
                principal = str(
                    getattr(inbound_proc, "principal", "") or getattr(inbound_proc, "username", "")
                )
                if principal:
                    event_data["principal"] = principal
                self._apply_process_provenance(event_data, inbound_proc)
                self._apply_flow_actor(event_data, inbound_proc)
            # INBOUND flow gets its own objectID (separate telemetry observation)
            self._emit_canonical_event(event_data, event)

    def _flow_source_time(
        self,
        event: SecurityEvent,
        *,
        seed_parts: tuple[Any, ...],
        not_before: datetime | None = None,
        drop_late_process_identity: bool = False,
        paired_endpoint: bool = False,
    ) -> tuple[datetime, bool]:
        """Return the dispatcher-finalized FLOW time and identity decision."""

        del drop_late_process_identity, paired_endpoint
        direction = str(seed_parts[0]) if seed_parts else ""
        hostname = str(seed_parts[1]) if len(seed_parts) > 1 else ""
        plan = event.source_timing
        if plan is None:
            timestamp = event.network.source_visible_start_time or event.timestamp
            return timestamp, not_before is None or not_before <= timestamp
        timestamp = plan.finalized_times.get(
            ecar_flow_render_key(direction, hostname),
            event.network.source_visible_start_time or event.timestamp,
        )
        identity_safe = plan.finalized_flags.get(
            ecar_flow_identity_key(direction, hostname),
            not_before is None or not_before <= timestamp,
        )
        return timestamp, identity_safe

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
    def _flow_connection_failed(net: NetworkContext | None) -> bool:
        """Return whether source-native FLOW should expose a failed connection outcome."""
        if net is None:
            return False
        if net.protocol.lower() != "tcp":
            return False
        return net.conn_state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR", "OTH"}

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
        plan = event.identity_plan
        source_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else None
        )
        target_identity = (
            plan.target if plan is not None and isinstance(plan.target, ProcessIdentity) else None
        )
        created_thread = (
            plan.subject if plan is not None and isinstance(plan.subject, ThreadIdentity) else None
        )
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
            not_before=self._after_process_create_timestamp(
                event,
                source_identity if source_identity is not None else proc,
            ),
        )
        event_data = {
            "timestamp": event_ts,
            "hostname": self._host_name(host),
            "object": "THREAD",
            "action": "REMOTE_CREATE",
            "pid": source_identity.pid if source_identity is not None else proc.pid,
            "ppid": source_identity.parent_pid if source_identity is not None else proc.parent_pid,
            "principal": source_identity.principal
            if source_identity is not None
            else proc.username or "NT AUTHORITY\\SYSTEM",
            "image_path": source_identity.image if source_identity is not None else proc.image,
            "target_pid": str(target_identity.pid if target_identity is not None else target_pid),
            "target_process_uuid": target_identity.object_id
            if target_identity is not None
            else remote_thread.target_process_object_id
            if remote_thread
            else "",
            "start_address": f"{remote_thread.start_address:016x}" if remote_thread else "",
            "stack_base": f"{remote_thread.stack_base:016x}" if remote_thread else "",
            "stack_limit": f"{remote_thread.stack_limit:016x}" if remote_thread else "",
            "user_stack_base": f"{remote_thread.user_stack_base:016x}" if remote_thread else "",
            "user_stack_limit": f"{remote_thread.user_stack_limit:016x}" if remote_thread else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        if created_thread is not None:
            event_data["target_tid"] = str(created_thread.tid)
            event_data["tgt_tid"] = str(created_thread.tid)
        elif remote_thread is not None:
            event_data["target_tid"] = str(remote_thread.target_thread_id)
            event_data["tgt_tid"] = str(remote_thread.target_thread_id)
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

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
        plan = event.identity_plan
        source_identity = (
            plan.actor if plan is not None and isinstance(plan.actor, ProcessIdentity) else None
        )
        target_identity = (
            plan.target if plan is not None and isinstance(plan.target, ProcessIdentity) else None
        )
        event_data = {
            "timestamp": self._after_process_create_timestamp(
                event,
                source_identity if source_identity is not None else proc,
            ),
            "hostname": self._host_name(host),
            "object": "PROCESS",
            "action": "OPEN",
            "pid": source_identity.pid if source_identity is not None else proc.pid,
            "ppid": source_identity.parent_pid if source_identity is not None else proc.parent_pid,
            "principal": source_identity.principal
            if source_identity is not None
            else proc.username or "NT AUTHORITY\\SYSTEM",
            "image_path": source_identity.image if source_identity is not None else proc.image,
            "command_line": source_identity.command_line
            if source_identity is not None
            else proc.command_line,
            "parent_image_path": proc.parent_image or "",
            "target_pid": str(target_identity.pid if target_identity is not None else target_pid),
            "target_image_path": target_identity.image
            if target_identity is not None
            else target_image,
            "target_process_uuid": target_identity.object_id
            if target_identity is not None
            else access.target_process_object_id
            if access
            else "",
            "granted_access": granted_access,
            "call_trace": access.call_trace if access else "",
            "_host_fqdn": self._host_fqdn(host),
        }
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

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
        start_time = (
            getattr(proc, "started_at", None)
            or getattr(proc, "start_time", None)
            or event.timestamp
        )
        not_before = start_time
        identity_hostname = str(getattr(proc, "hostname", "") or "")
        identity_pid = int(getattr(proc, "pid", -1))
        return _SOURCE_TIMING.source_time(
            event,
            "source.ecar_process_create",
            seed_parts=(identity_hostname or hostname, identity_pid, start_time),
            not_before=not_before,
        )

    def _after_process_create_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Clamp dependent eCAR observations after their PROCESS/CREATE record."""
        start_time = getattr(proc, "started_at", None) or getattr(proc, "start_time", None)
        if proc is None or start_time is None:
            return event.timestamp
        if event.timestamp - start_time >= timedelta(seconds=5):
            return _SOURCE_TIMING.source_time(
                event,
                "source.ecar_dependent_after_process_create",
                seed_parts=(
                    event.event_type,
                    self._host_name(event.src_host),
                    getattr(proc, "pid", -1),
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
                getattr(proc, "pid", -1),
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
        start_time = getattr(proc, "started_at", None) or getattr(proc, "start_time", None)
        if proc is None or start_time is None:
            return event.timestamp
        if event.timestamp - start_time >= timedelta(seconds=5):
            return start_time
        return self._process_create_timestamp(event, proc) + timedelta(milliseconds=1)

    def _process_terminate_timestamp(
        self,
        event: SecurityEvent,
        proc: Any,
    ) -> datetime:
        """Return an eCAR terminate timestamp preserving rendered process lifetime."""
        start_time = getattr(proc, "started_at", None) or getattr(proc, "start_time", None)
        if proc is None or start_time is None:
            return event.timestamp
        canonical_lifetime = max(timedelta(milliseconds=100), event.timestamp - start_time)
        process_create_ts = (
            self._process_create_timestamp(event, proc)
            if isinstance(proc, ProcessIdentity)
            else start_time
        )
        return _SOURCE_TIMING.source_time(
            event,
            "source.ecar_process_terminate",
            seed_parts=(
                self._host_name(event.src_host),
                getattr(proc, "pid", -1),
                start_time,
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
        self._apply_session_properties(event_data, event)
        self._apply_edr_context(event_data, event)
        self._emit_canonical_event(event_data, event)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route event to per-host writer."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def flush(self, force: bool = False) -> None:
        """Serialize buffered records in source-timestamp order without semantic mutation."""

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
        "icmp_type",
        "icmp_code",
        "direction",
        "md5",
        "sha256",
        "registry_key",
        "registry_value",
        "failure_reason",
        "outcome",
        "logon_id",
        "logon_type",
        "session_id",
        "logon_guid",
        "session_type",
        "session_lifecycle",
        "status_code",
        "sub_status",
        "src_pid",
        "src_tid",
        "source_process_uuid",
        "source_pid",
        "source_tid",
        "source_image_path",
        "source_principal",
        "tgt_tid",
        "target_tid",
        "start_address",
        "stack_base",
        "stack_limit",
        "user_stack_base",
        "user_stack_limit",
        "granted_access",
        "call_trace",
        "target_pid",
        "target_image_path",
        "target_process_uuid",
        "target_principal",
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
