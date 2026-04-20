# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pydantic schemas for EvidenceForge config YAML files.

These models define the expected structure of each config file type.
Used by validate_config.py to validate merged data — not used by loaders
(loaders stay fast, validation is opt-in via eforge validate-config).

All models use extra="forbid" so misspelled fields are caught as errors.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, field_validator

# --- DNS Registry ---


class DnsEntry(BaseModel, extra="forbid"):
    """A single domain entry in dns_registry.yaml."""

    domain: str
    ips: list[str]
    tags: list[str]

    @field_validator("ips")
    @classmethod
    def ips_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("ips must not be empty")
        return v

    @field_validator("tags")
    @classmethod
    def tags_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("tags must not be empty")
        return v


# --- Application Catalog ---


class LoadedModuleEntry(BaseModel, extra="forbid"):
    """A DLL/module entry in a loaded_modules list."""

    path: str
    signed: bool = True
    signature: str = "Microsoft Windows"
    signature_status: str = "Valid"


class PlatformConfig(BaseModel, extra="forbid"):
    """Per-OS platform config within an application entry."""

    image_path: str
    pe_metadata: dict[str, str] | None = None
    command_templates: list[str] | None = None
    children: list[str] | None = None
    loaded_modules: list[LoadedModuleEntry] | None = None


class ApplicationEntry(BaseModel, extra="forbid"):
    """A single application entry in application_catalog.yaml."""

    id: str
    display_name: str
    platforms: dict[str, PlatformConfig]
    categories: list[str]
    personas: list[str]
    system_types: list[str] | None = None


# --- Persona ---


class PersonaEntry(BaseModel, extra="forbid"):
    """A single persona definition."""

    name: str
    description: str
    typical_activities: list[str]
    work_hours: str
    application_usage: list[str]
    risk_profile: Literal["low", "medium", "high"]
    browsing_intensity: Literal["light", "normal", "heavy"]


# --- Systemd Schedules ---


class SystemdScheduleEntry(BaseModel, extra="forbid"):
    """A single schedule entry in systemd_schedules.yaml."""

    service: str
    type: Literal["systemd_timer", "cron"]
    frequency: Literal["daily", "weekly", "30min"]
    typical_hour: int
    jitter_minutes: int
    distro: str
    # Optional fields for systemd_timer type
    process_path: str | None = None
    start_message: str | None = None
    finish_message: str | None = None
    timer_message: str | None = None
    detail_messages: dict[str, list[str]] | None = None
    # Optional fields for weekly frequency
    typical_day: str | None = None
    # Optional role filter
    role: str | None = None
    # Optional fields for cron type
    cron_user: str | None = None
    cron_commands: dict[str, str] | None = None


# --- Extra Syslog Messages ---


class SyslogProgramEntry(BaseModel, extra="forbid"):
    """A single program entry in extra_syslog_messages.yaml."""

    app: str
    messages: list[str]
    distro: str | None = None
    roles: list[str] | None = None
    transient: bool | None = None


# --- TLS Issuers ---


class TlsKeyType(BaseModel, extra="forbid"):
    """A key type within a TLS issuer."""

    type: str
    length: int
    weight: int


class TlsIssuerEntry(BaseModel, extra="forbid"):
    """A single issuer entry in tls_issuers.yaml."""

    name: str
    weight: int
    validity_days_min: int
    validity_days_max: int
    not_before_max_days: int
    key_types: list[TlsKeyType]


# --- Network Params ---


class OuiEntry(BaseModel, extra="forbid"):
    """A single OUI prefix entry in network_params.yaml."""

    prefix: str
    vendor: str
    weight: int


# --- Process Network Map ---


class ProcessNetworkEntry(BaseModel, extra="forbid"):
    """A single mapping entry in process_network_map.yaml."""

    exe: list[str]
    service: str
    port: int
    external: bool


# --- Traffic Profile Connection ---


class ConnectionEntry(BaseModel, extra="forbid"):
    """A single connection entry within traffic_profiles.yaml."""

    role: str
    port: int
    weight: int
    proto: str = "tcp"
    service: str | None = None
    os: str | None = None
    emit_dns: bool | None = None
    dns_tags: list[str] | None = None
    description: str | None = None


# --- Spawn Rules ---


class SpawnRuleEntry(BaseModel, extra="forbid"):
    """A single parent process entry within spawn_rules.yaml."""

    command_templates: list[str]
    lifetime: Literal["long", "short"]
    children: list[str]
    spawn_delay: list[float] | None = None
    max_children: int | None = None


# --- System Processes ---


class ScheduledTaskEntry(BaseModel, extra="forbid"):
    """A scheduled task entry in system_processes.yaml."""

    image: str
    command_templates: list[str]
    parent: str
    params: dict[str, list[str]] | None = None


class SystemServiceEntry(BaseModel, extra="forbid"):
    """A system service entry in system_processes.yaml."""

    image: str
    command_templates: list[str]
    parent: str
    params: dict[str, list[str]] | None = None
    loaded_modules: list[LoadedModuleEntry] | None = None


class SystemBinaryEntry(BaseModel, extra="forbid"):
    """A single system binary entry in system_processes.yaml."""

    exe: str
    path: str


# --- Validation helper ---


def validate_entry(entry: dict[str, Any], schema: type[BaseModel], file_name: str) -> str | None:
    """Validate a single entry against a Pydantic schema.

    Returns an error message string, or None if valid.
    """
    try:
        schema(**entry)
        return None
    except Exception as e:
        # Extract the most useful part of the Pydantic error
        errors = []
        if hasattr(e, "errors"):
            for err in e.errors():
                loc = " → ".join(str(x) for x in err["loc"])
                errors.append(f"{loc}: {err['msg']}")
        else:
            errors.append(str(e))
        return "; ".join(errors)
