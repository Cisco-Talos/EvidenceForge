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
        self.emit_event(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route event to per-host writer."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render eCAR event to JSON format (NDJSON - one event per line).

        Converts timestamp to milliseconds, ensures UUIDs, handles properties.
        """
        # Convert timestamp to milliseconds
        if "timestamp" in event_data:
            ts = event_data["timestamp"]
            if isinstance(ts, datetime):
                timestamp_ms = int(ts.timestamp() * 1000)
            else:
                timestamp_ms = int(ts * 1000)
            event_data["timestamp_ms"] = timestamp_ms

        # Ensure event has an ID
        if "id" not in event_data:
            event_data["id"] = str(uuid.uuid4())

        # Ensure objectID and actorID are UUIDs
        if "objectID" not in event_data:
            event_data["objectID"] = str(uuid.uuid4())

        # Handle -1 for unavailable PID/TID/PPID
        for field in ["pid", "tid", "ppid"]:
            if field in event_data and event_data[field] is None:
                event_data[field] = -1

        # Build template context - fill all optional fields
        context = {
            "timestamp_ms": event_data.get("timestamp_ms"),
            "id": event_data.get("id"),
            "hostname": event_data.get("hostname"),
            "object": event_data.get("object"),
            "action": event_data.get("action"),
            "objectID": event_data.get("objectID"),
            "actorID": event_data.get("actorID"),
            "pid": event_data.get("pid"),
            "tid": event_data.get("tid"),
            "ppid": event_data.get("ppid"),
            "principal": event_data.get("principal"),
            # Properties
            "command_line": event_data.get("command_line"),
            "image_path": event_data.get("image_path"),
            "file_path": event_data.get("file_path"),
            "src_ip": event_data.get("src_ip"),
            "src_port": event_data.get("src_port"),
            "dst_ip": event_data.get("dst_ip"),
            "dst_port": event_data.get("dst_port"),
            "protocol": event_data.get("protocol"),
            "md5": event_data.get("md5"),
            "sha256": event_data.get("sha256"),
            "registry_key": event_data.get("registry_key"),
            "registry_value": event_data.get("registry_value"),
        }

        # Render template
        rendered = self._template.render(**context)

        # Compact JSON to single line (NDJSON format)
        try:
            parsed = json.loads(rendered)
            compact = json.dumps(parsed, separators=(",", ":"))
            return compact
        except json.JSONDecodeError:
            # If template rendering failed, return as-is
            return rendered
