"""Emitter for EDR/XDR host telemetry in eCAR format."""

import json
import uuid
from datetime import datetime
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class EcarEmitter(HostMultiplexEmitter):
    """Emitter for eCAR (extended Cyber Analytics Repository) format.

    Per-host FQDN directory routing: each host gets its own ecar.json.
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
    }

    def can_handle(self, event: SecurityEvent) -> bool:
        """eCAR handles events regardless of OS (cross-platform EDR)."""
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
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(f"EcarEmitter: no render method for {event.event_type}")
        renderer(event)

    def _get_host_fqdn(self, event: SecurityEvent) -> str:
        """Extract host FQDN for per-host routing."""
        if event.host:
            return event.host.fqdn or event.host.hostname
        return ""

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
        """Render eCAR USER_SESSION/LOGIN event."""
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": event.auth.source_ip,
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGOUT event."""
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "USER_SESSION",
            "action": "LOGOUT",
            "principal": event.auth.username,
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render eCAR USER_SESSION/LOGIN with failure_reason."""
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "USER_SESSION",
            "action": "LOGIN",
            "principal": event.auth.username,
            "src_ip": event.auth.source_ip,
            "failure_reason": "bad_password",
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/CREATE event."""
        proc = event.process
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "PROCESS",
            "action": "CREATE",
            "pid": proc.pid,
            "ppid": proc.parent_pid,
            "principal": proc.username,
            "image_path": proc.image,
            "command_line": proc.command_line,
            "_host_fqdn": self._get_host_fqdn(event),
        }
        if proc.parent_image:
            event_data["parent_image_path"] = proc.parent_image
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render eCAR PROCESS/TERMINATE event."""
        proc = event.process
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "PROCESS",
            "action": "TERMINATE",
            "pid": proc.pid,
            "principal": proc.username,
            "image_path": proc.image,
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_file_event(self, event: SecurityEvent) -> None:
        """Render eCAR FILE event from canonical FileContext."""
        action_map = {"file_create": "CREATE", "file_modify": "MODIFY", "file_delete": "DELETE"}
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "FILE",
            "action": action_map.get(event.event_type, "CREATE"),
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_registry_event(self, event: SecurityEvent) -> None:
        """Render eCAR REGISTRY event from canonical RegistryContext."""
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "REGISTRY",
            "action": "MODIFY",
            "pid": event.registry.pid if event.registry else -1,
            "principal": event.auth.username if event.auth else "",
            "registry_key": event.registry.key if event.registry else "",
            "registry_value": event.registry.value if event.registry else "",
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_module_event(self, event: SecurityEvent) -> None:
        """Render eCAR MODULE/LOAD event from canonical FileContext."""
        event_data = {
            "timestamp": event.timestamp,
            "hostname": event.host.hostname if event.host else "",
            "object": "MODULE",
            "action": "LOAD",
            "pid": event.file.pid if event.file else -1,
            "principal": event.auth.username if event.auth else "",
            "file_path": event.file.path if event.file else "",
            "_host_fqdn": self._get_host_fqdn(event),
        }
        self._apply_edr_context(event_data, event)
        self.emit_event(event_data)

    def _render_connection(self, event: SecurityEvent) -> None:
        """Render eCAR FLOW/CONNECT event from canonical NetworkContext."""
        net = event.network
        hostname = event.host.hostname if event.host else net.src_ip
        event_data = {
            "timestamp": event.timestamp,
            "hostname": hostname,
            "object": "FLOW",
            "action": "CONNECT",
            "pid": net.initiating_pid,
            "src_ip": net.src_ip,
            "src_port": net.src_port,
            "dst_ip": net.dst_ip,
            "dst_port": net.dst_port,
            "protocol": net.protocol,
            "_host_fqdn": self._get_host_fqdn(event),
        }
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
        "md5",
        "sha256",
        "registry_key",
        "registry_value",
        "failure_reason",
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
