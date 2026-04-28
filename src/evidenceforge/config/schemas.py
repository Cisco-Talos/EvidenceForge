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

from pydantic import BaseModel, Field, field_validator

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


class TlsSanConfig(BaseModel, extra="forbid"):
    """SAN generation settings in tls_realism.yaml."""

    multi_label_public_suffixes: list[str]


class TlsOcspResponder(BaseModel, extra="forbid"):
    """Issuer-pattern to OCSP responder mapping in tls_realism.yaml."""

    issuer_patterns: list[str]
    domains: list[str]


class TlsOcspConfig(BaseModel, extra="forbid"):
    """OCSP behavior settings in tls_realism.yaml."""

    cache_bucket_seconds: int
    this_update_max_skew_seconds: int
    next_update_min_seconds: int
    next_update_max_seconds: int
    responders: list[TlsOcspResponder] = Field(default_factory=list)
    status_weights: dict[Literal["good", "unknown", "revoked"], int]
    suppress_revoked_suffixes: list[str] = Field(default_factory=list)

    @field_validator(
        "cache_bucket_seconds",
        "this_update_max_skew_seconds",
        "next_update_min_seconds",
        "next_update_max_seconds",
    )
    @classmethod
    def seconds_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("seconds values must be non-negative")
        return v

    @field_validator("status_weights")
    @classmethod
    def status_weights_valid(cls, v: dict[str, int]) -> dict[str, int]:
        if set(v) != {"good", "unknown", "revoked"}:
            raise ValueError("status_weights must contain good, unknown, and revoked")
        if any(weight < 0 for weight in v.values()):
            raise ValueError("status_weights must be non-negative")
        if sum(v.values()) <= 0:
            raise ValueError("status_weights must have a positive total")
        return v


class TlsChainTemplate(BaseModel, extra="forbid"):
    """A certificate-chain template in tls_realism.yaml."""

    name: str
    issuer_patterns: list[str]
    intermediates: list[str]

    @field_validator("issuer_patterns", "intermediates")
    @classmethod
    def non_empty_list(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("list must not be empty")
        return v


class TlsCertificateChainConfig(BaseModel, extra="forbid"):
    """Certificate-chain behavior settings in tls_realism.yaml."""

    include_intermediate_probability: float
    include_second_intermediate_probability: float
    intermediate_validity_days_min: int
    intermediate_validity_days_max: int
    intermediate_not_before_max_days: int
    key_types: list[TlsKeyType]
    templates: list[TlsChainTemplate]

    @field_validator(
        "include_intermediate_probability",
        "include_second_intermediate_probability",
    )
    @classmethod
    def probability_range(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("probability must be between 0 and 1")
        return v

    @field_validator(
        "intermediate_validity_days_min",
        "intermediate_validity_days_max",
        "intermediate_not_before_max_days",
    )
    @classmethod
    def days_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("day values must be positive")
        return v


class TlsDestinationOsOverride(BaseModel, extra="forbid"):
    """OS-specific TLS destination pool override."""

    domains: list[str] = Field(default_factory=list)
    dns_tags: list[str] = Field(default_factory=list)


class TlsDestinationProfile(BaseModel, extra="forbid"):
    """A weighted TLS destination profile in tls_realism.yaml."""

    name: str
    weight: int
    domains: list[str] = Field(default_factory=list)
    dns_tags: list[str] = Field(default_factory=list)
    os: list[str] = Field(default_factory=list)
    personas: list[str] = Field(default_factory=list)
    system_types: list[str] = Field(default_factory=list)
    purpose_tags: list[str] = Field(default_factory=list)
    os_overrides: dict[str, TlsDestinationOsOverride] = Field(default_factory=dict)

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v

    @field_validator("domains", "dns_tags")
    @classmethod
    def has_destination_source(cls, v: list[str], info) -> list[str]:
        if any(not item for item in v):
            raise ValueError(f"{info.field_name} entries must be non-empty")
        return v


class TlsDestinationsConfig(BaseModel, extra="forbid"):
    """TLS destination profile settings in tls_realism.yaml."""

    enabled: bool = True
    host_preferred_domain_count: int = 6
    host_preferred_probability: float = 0.68
    profiles: list[TlsDestinationProfile]

    @field_validator("host_preferred_domain_count")
    @classmethod
    def preferred_count_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("host_preferred_domain_count must be positive")
        return v

    @field_validator("host_preferred_probability")
    @classmethod
    def probability_range(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("host_preferred_probability must be between 0 and 1")
        return v

    @field_validator("profiles")
    @classmethod
    def profiles_non_empty(cls, v: list[TlsDestinationProfile]) -> list[TlsDestinationProfile]:
        if not v:
            raise ValueError("profiles must not be empty")
        return v


class TlsRealismConfig(BaseModel, extra="forbid"):
    """Root schema for tls_realism.yaml."""

    san: TlsSanConfig
    ocsp: TlsOcspConfig
    certificate_chains: TlsCertificateChainConfig
    destinations: TlsDestinationsConfig


# --- SMB File Transfers ---


class SmbMimeTypeEntry(BaseModel, extra="forbid"):
    """A weighted MIME type in smb_file_transfers.yaml."""

    mime_type: str
    weight: int

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class SmbAnalyzerSetEntry(BaseModel, extra="forbid"):
    """A weighted Zeek file analyzer set in smb_file_transfers.yaml."""

    analyzers: list[str]
    weight: int

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class SmbFilenameTemplateEntry(BaseModel, extra="forbid"):
    """A weighted SMB filename template set in smb_file_transfers.yaml."""

    mime_types: list[str] = Field(default_factory=list)
    templates: list[str]
    weight: int

    @field_validator("templates")
    @classmethod
    def templates_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("templates must not be empty")
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class SmbFileTransferConfig(BaseModel, extra="forbid"):
    """Root schema for smb_file_transfers.yaml."""

    min_transfer_bytes: int
    missing_bytes_probability: float
    timeout_probability: float
    mime_types: list[SmbMimeTypeEntry]
    analyzer_sets: list[SmbAnalyzerSetEntry]
    filename_templates: list[SmbFilenameTemplateEntry] = Field(default_factory=list)

    @field_validator("min_transfer_bytes")
    @classmethod
    def min_transfer_bytes_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("min_transfer_bytes must be positive")
        return v

    @field_validator("missing_bytes_probability", "timeout_probability")
    @classmethod
    def probability_range(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("probability must be between 0 and 1")
        return v

    @field_validator("mime_types", "analyzer_sets")
    @classmethod
    def non_empty_weighted_lists(cls, v: list[Any]) -> list[Any]:
        if not v:
            raise ValueError("weighted lists must not be empty")
        return v


# --- Network Params ---


class OuiEntry(BaseModel, extra="forbid"):
    """A single OUI prefix entry in network_params.yaml."""

    prefix: str
    vendor: str
    weight: int


class PublicNtpServerEntry(BaseModel, extra="forbid"):
    """A public NTP server profile in network_params.yaml."""

    name: str
    ip: str
    operator: str
    stratum: int = Field(ge=1, le=4)
    ref_id: str
    weight: int = Field(gt=0)


class ProxyUserAgentOverrideEntry(BaseModel, extra="forbid"):
    """A domain-specific proxy User-Agent profile."""

    os_keywords: list[str]
    hosts: list[str]
    user_agents: list[str]

    @field_validator("os_keywords", "hosts", "user_agents")
    @classmethod
    def non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("list must not be empty")
        return v


# --- Process Network Map ---


class ProcessNetworkEntry(BaseModel, extra="forbid"):
    """A single mapping entry in process_network_map.yaml."""

    exe: list[str]
    service: str
    port: int
    external: bool
    dns_tags: list[str] | None = None


# --- ProcessAccess Patterns ---


class ProcessAccessMaskEntry(BaseModel, extra="forbid"):
    """A weighted GrantedAccess mask in process_access_patterns.yaml."""

    mask: str
    weight: int

    @field_validator("mask")
    @classmethod
    def mask_is_hex(cls, v: str) -> str:
        if not v.startswith("0x"):
            raise ValueError("mask must be a hex string such as 0x1010")
        int(v, 16)
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class ProcessAccessPatternEntry(BaseModel, extra="forbid"):
    """A baseline ProcessAccess source/target pair in process_access_patterns.yaml."""

    source_pid_key: str
    source_image: str
    target_pid_key: str
    target_image: str
    access_masks: list[ProcessAccessMaskEntry]

    @field_validator("access_masks")
    @classmethod
    def access_masks_non_empty(
        cls, v: list[ProcessAccessMaskEntry]
    ) -> list[ProcessAccessMaskEntry]:
        if not v:
            raise ValueError("access_masks must not be empty")
        return v


# --- CreateRemoteThread Patterns ---


class CreateRemoteThreadPatternEntry(BaseModel, extra="forbid"):
    """A benign CreateRemoteThread source/target pair."""

    source_pid_key: str
    source_image: str
    target_pid_key: str
    target_image: str
    weight: int = 1

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


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


# --- Traffic Rates ---


class TrafficRateLevel(BaseModel, extra="forbid"):
    """Rate ranges for one intensity level in traffic_rates.yaml."""

    user_activity: list[int]
    web: list[int]
    dns_interval: list[int]
    ntp: list[int]
    smb_interval: list[int]
    kerberos: list[int]
    ldap: list[int]
    persona_connections: list[int]

    @field_validator("*", mode="before")
    @classmethod
    def validate_rate_range(cls, v: Any) -> Any:
        if isinstance(v, list):
            if len(v) != 2:
                raise ValueError("must be a [lo, hi] pair")
            if not all(isinstance(x, int) and x > 0 for x in v):
                raise ValueError("values must be positive integers")
            if v[0] > v[1]:
                raise ValueError(f"lo ({v[0]}) must be <= hi ({v[1]})")
        return v


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
