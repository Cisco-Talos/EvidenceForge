# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused machine-readable authored-scenario schema contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, get_args

from pydantic import BaseModel, TypeAdapter

from evidenceforge.models import scenario as scenario_models


@dataclass(frozen=True)
class SchemaContract:
    """One focused public authored-schema contract."""

    selector: str
    adapter: TypeAdapter[Any]
    example: Any


_MODEL_SELECTORS: dict[str, tuple[type[BaseModel], Any]] = {
    "environment": (
        scenario_models.Environment,
        {
            "description": "Small corporate environment",
            "users": [
                {
                    "username": "analyst",
                    "full_name": "Alex Analyst",
                    "email": "analyst@corp.invalid",
                    "primary_system": "WS-01",
                }
            ],
            "systems": [
                {
                    "hostname": "WS-01",
                    "ip": "10.0.1.10",
                    "os": "Windows 11",
                    "type": "workstation",
                }
            ],
        },
    ),
    "environment.users": (
        scenario_models.User,
        {
            "username": "analyst",
            "full_name": "Alex Analyst",
            "email": "analyst@corp.invalid",
            "primary_system": "WS-01",
        },
    ),
    "environment.systems": (
        scenario_models.System,
        {
            "hostname": "WS-01",
            "ip": "10.0.1.10",
            "os": "Windows 11",
            "type": "workstation",
        },
    ),
    "environment.network_identities": (
        scenario_models.NetworkIdentity,
        {
            "id": "partner_portal",
            "hosts": ["partner.example.com"],
            "ips": ["203.0.113.60"],
            "tags": ["web", "partner"],
            "dns": True,
        },
    ),
    "environment.network": (
        scenario_models.NetworkConfig,
        {
            "segments": [
                {
                    "name": "workstations",
                    "cidr": "10.0.1.0/24",
                    "systems": ["WS-01"],
                    "exposure": "internal",
                }
            ]
        },
    ),
    "environment.network.segments": (
        scenario_models.NetworkSegment,
        {
            "name": "workstations",
            "cidr": "10.0.1.0/24",
            "systems": ["WS-01"],
            "exposure": "internal",
        },
    ),
    "environment.network.sensors": (
        scenario_models.NetworkSensor,
        {
            "type": "network",
            "name": "core-span",
            "monitoring_segments": ["workstations"],
            "log_formats": ["zeek"],
        },
    ),
    "environment.storage": (scenario_models.StorageConfig, {}),
    "environment.email": (
        scenario_models.EmailConfig,
        {
            "accepted_domains": ["corp.invalid"],
            "mail_servers": [
                {
                    "name": "primary",
                    "hostname": "mail.corp.invalid",
                    "system": "MAIL-01",
                }
            ],
            "default_mailbox_servers": ["primary"],
        },
    ),
    "environment.proxy": (scenario_models.ProxyConfig, {}),
    "time_window": (
        scenario_models.TimeWindow,
        {"start": "2026-08-26T13:00:00Z", "duration": "8h"},
    ),
    "baseline_activity": (
        scenario_models.BaselineActivity,
        {
            "description": "Normal office activity",
            "intensity": "medium",
            "variation": "medium",
        },
    ),
    "output": (
        scenario_models.OutputSpec,
        {"logs": [{"format": "windows"}], "destination": "./output"},
    ),
}

_SCALAR_SELECTORS: dict[str, tuple[Any, Any]] = {
    "environment.service_accounts": (list[str], ["svc-backup", "svc-monitoring"]),
}

_EVENT_EXAMPLES: dict[str, dict[str, Any]] = {
    "process": {"type": "process", "process_name": "whoami.exe"},
    "logon": {"type": "logon"},
    "failed_logon": {"type": "failed_logon"},
    "logoff": {"type": "logoff"},
    "connection": {"type": "connection", "dst_ip": "203.0.113.60", "dst_port": 443},
    "smb_activity": {
        "type": "smb_activity",
        "operation": "browse",
        "target": {"type": "share", "share": "FS-01.finance"},
    },
    "ssh_session": {"type": "ssh_session", "source_ip": "10.0.1.10"},
    "rdp_session": {"type": "rdp_session", "source_ip": "10.0.1.10"},
    "account_created": {"type": "account_created", "target_username": "temp.user"},
    "account_deleted": {"type": "account_deleted", "target_username": "temp.user"},
    "group_member_added": {
        "type": "group_member_added",
        "group_name": "Administrators",
        "member_name": "temp.user",
    },
    "service_installed": {
        "type": "service_installed",
        "service_name": "Updater",
        "service_file_name": "C:\\Program Files\\Updater\\updater.exe",
    },
    "scheduled_task_created": {
        "type": "scheduled_task_created",
        "task_name": "UpdaterCheck",
    },
    "log_cleared": {"type": "log_cleared"},
    "create_remote_thread": {"type": "create_remote_thread", "target_process": "lsass.exe"},
    "process_access": {"type": "process_access", "target_process": "lsass.exe"},
    "dhcp_lease": {"type": "dhcp_lease"},
    "port_scan": {"type": "port_scan", "target_ips": ["10.0.2.20"]},
    "beacon": {
        "type": "beacon",
        "dst_ip": "203.0.113.60",
        "interval": "1m",
        "count": 5,
    },
    "dns_query": {
        "type": "dns_query",
        "query": "partner.example.com",
        "answer": "203.0.113.60",
    },
    "web_scan": {
        "type": "web_scan",
        "dst_ip": "203.0.113.60",
        "preset": "nikto",
        "rate": 1.0,
        "count": 5,
    },
    "credential_spray": {
        "type": "credential_spray",
        "target_accounts": ["analyst"],
        "interval": "5s",
        "count": 5,
    },
    "dga_queries": {"type": "dga_queries", "interval": "1m", "count": 5},
    "dns_tunnel": {
        "type": "dns_tunnel",
        "base_domain": "tunnel.example.com",
        "interval": "5s",
        "count": 5,
    },
    "explicit_credentials": {
        "type": "explicit_credentials",
        "target_username": "administrator",
    },
    "workstation_lock": {"type": "workstation_lock"},
    "workstation_unlock": {"type": "workstation_unlock"},
    "spillage": {
        "type": "spillage",
        "surface": "shell_history",
        "family": "aws_access_key",
    },
    "adversarial_payload": {
        "type": "adversarial_payload",
        "surface": "syslog_message",
        "family": "ansi_escape",
    },
    "email_message": {
        "type": "email_message",
        "to": ["analyst@corp.invalid"],
        "subject": "Quarterly update",
    },
    "email_read": {"type": "email_read", "protocol": "owa", "duration": 45.0},
    "raw": {"type": "raw", "target_format": "syslog"},
}


def _event_models() -> dict[str, type[BaseModel]]:
    """Return event models keyed by their discriminator value."""

    event_union = get_args(scenario_models.EventSpec)[0]
    return {str(model.model_fields["type"].default): model for model in get_args(event_union)}


def schema_selectors() -> tuple[str, ...]:
    """Return every supported focused selector."""

    event_selectors = (f"event.{event_type}" for event_type in _event_models())
    return tuple(sorted((*_MODEL_SELECTORS, *_SCALAR_SELECTORS, *event_selectors)))


def resolve_schema_contract(selector: str) -> SchemaContract | None:
    """Resolve one case-insensitive selector to its model adapter and example."""

    normalized = selector.casefold()
    if normalized in _MODEL_SELECTORS:
        model, example = _MODEL_SELECTORS[normalized]
        return SchemaContract(normalized, TypeAdapter(model), example)
    if normalized in _SCALAR_SELECTORS:
        annotation, example = _SCALAR_SELECTORS[normalized]
        return SchemaContract(normalized, TypeAdapter(annotation), example)
    if normalized.startswith("event."):
        event_type = normalized.removeprefix("event.")
        model = _event_models().get(event_type)
        example = _EVENT_EXAMPLES.get(event_type)
        if model is not None and example is not None:
            return SchemaContract(normalized, TypeAdapter(model), example)
    return None


def _field_summary(field_schema: dict[str, Any], *, required: bool) -> dict[str, Any]:
    """Extract the high-value authoring constraints from one JSON Schema property."""

    summary: dict[str, Any] = {"required": required}
    for key in (
        "type",
        "const",
        "enum",
        "default",
        "description",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
    ):
        if key in field_schema:
            summary[key] = field_schema[key]
    if "$ref" in field_schema:
        summary["schema_ref"] = field_schema["$ref"]
    if "anyOf" in field_schema:
        summary["variants"] = field_schema["anyOf"]
    if "items" in field_schema:
        summary["items"] = field_schema["items"]
    return summary


def schema_contract_payload(contract: SchemaContract) -> dict[str, Any]:
    """Serialize a focused contract with a validated minimal example."""

    validated = contract.adapter.validate_python(contract.example)
    schema = contract.adapter.json_schema(mode="validation")
    required = set(schema.get("required", []))
    properties = schema.get("properties", {})
    fields = {
        name: _field_summary(field_schema, required=name in required)
        for name, field_schema in properties.items()
    }
    return {
        "schema_version": "1.0",
        "selector": contract.selector,
        "fields": fields,
        "example": contract.adapter.dump_python(validated, mode="json", exclude_defaults=True),
        "json_schema": schema,
    }
