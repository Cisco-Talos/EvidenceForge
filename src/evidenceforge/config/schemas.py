# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pydantic schemas for EvidenceForge config YAML files.

These models define the expected structure of each config file type.
Used by validate_config.py to validate merged data — not used by loaders
(loaders stay fast, validation is opt-in via eforge validate-config).

All models use extra="forbid" so misspelled fields are caught as errors.
"""

from __future__ import annotations

import ipaddress
import math
import re
from string import Formatter
from typing import Any, ClassVar, Literal, Self
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    Field,
    IPvAnyAddress,
    ValidationInfo,
    field_validator,
    model_validator,
)

from evidenceforge.config.public_dns_templates import validate_public_dns_answer_template
from evidenceforge.models.http import HttpMultipartEntitySpec

TLS_SERIAL_LENGTH_MAX_WEIGHT = 1_000_000
KERBEROS_TRANSPORT_MAX_WEIGHT = 1_000_000
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_REALISM_RESERVED_DOMAINS = (
    "example",
    "example.com",
    "example.net",
    "example.org",
    "test",
    "invalid",
    "localhost",
)


class IdsSignaturePredicateSpec(BaseModel, extra="forbid", frozen=True):
    """Validated semantic preconditions for one configured IDS signature."""

    destination_port: int | None = Field(default=None, ge=0, le=65535)
    phase: Literal["attempt", "established", "application", "response"] = "attempt"
    payload_direction: Literal["none", "orig", "resp", "either"] = "none"
    minimum_payload_bytes: int = Field(default=0, ge=0)
    requires_response: bool = False
    application_protocol: (
        Literal["http", "dns", "tls", "ssh", "smb", "kerberos", "ldap", "ntp", "stun"] | None
    ) = None
    inspection: Literal["metadata", "payload_cleartext", "payload_decrypted"] = "metadata"
    http_methods: list[str] = Field(default_factory=list)
    http_statuses: list[int] = Field(default_factory=list)
    requires_http_body: bool = False
    tls_server_names: list[str] = Field(default_factory=list)
    file_mime_types: list[str] = Field(default_factory=list)
    semantic_claim: Literal[
        "flow_metadata",
        "scan",
        "handshake",
        "request_content",
        "response_content",
        "upload_request",
        "dns_query",
        "dns_response",
        "file_content",
    ] = "flow_metadata"

    @field_validator("http_methods")
    @classmethod
    def normalize_http_methods(cls, values: list[str]) -> list[str]:
        """Normalize and deduplicate configured HTTP methods."""

        normalized = [value.strip().upper() for value in values]
        if any(not value or not re.fullmatch(r"[A-Z]+", value) for value in normalized):
            raise ValueError("http_methods must contain non-empty alphabetic method names")
        if len(normalized) != len(set(normalized)):
            raise ValueError("http_methods must not contain duplicates")
        return normalized

    @field_validator("http_statuses")
    @classmethod
    def validate_http_statuses(cls, values: list[int]) -> list[int]:
        """Reject non-native or duplicate HTTP response codes."""

        if any(isinstance(value, bool) or value < 100 or value > 599 for value in values):
            raise ValueError("http_statuses must contain integers between 100 and 599")
        if len(values) != len(set(values)):
            raise ValueError("http_statuses must not contain duplicates")
        return values

    @field_validator("file_mime_types")
    @classmethod
    def normalize_file_mime_types(cls, values: list[str]) -> list[str]:
        """Normalize and deduplicate MIME requirements for file-content rules."""

        normalized = [value.strip().lower() for value in values]
        if any(not value or "/" not in value for value in normalized):
            raise ValueError("file_mime_types must contain non-empty MIME types")
        if len(normalized) != len(set(normalized)):
            raise ValueError("file_mime_types must not contain duplicates")
        return normalized

    @field_validator("tls_server_names")
    @classmethod
    def normalize_tls_server_names(cls, values: list[str]) -> list[str]:
        """Normalize exact or suffix-wildcard TLS server-name requirements."""
        normalized = [value.strip().lower().rstrip(".") for value in values]
        if any(
            not value or (value.startswith("*.") and value.count("*") > 1) for value in normalized
        ):
            raise ValueError("tls_server_names must contain non-empty exact or *.suffix names")
        if len(normalized) != len(set(normalized)):
            raise ValueError("tls_server_names must not contain duplicates")
        return normalized

    @model_validator(mode="after")
    def validate_semantic_combination(self) -> Self:
        """Reject predicates that cannot be evaluated coherently."""

        if self.minimum_payload_bytes and self.payload_direction == "none":
            raise ValueError("minimum_payload_bytes requires a payload_direction")
        if (self.http_methods or self.http_statuses or self.requires_http_body) and (
            self.application_protocol != "http"
        ):
            raise ValueError("HTTP-specific fields require application_protocol='http'")
        if self.requires_http_body and self.payload_direction not in {"orig", "either"}:
            raise ValueError("requires_http_body needs orig/either payload_direction")
        if self.tls_server_names and self.application_protocol != "tls":
            raise ValueError("tls_server_names requires application_protocol='tls'")
        if self.file_mime_types and self.semantic_claim != "file_content":
            raise ValueError("file_mime_types requires semantic_claim='file_content'")
        if self.phase == "response" and not self.requires_response:
            raise ValueError("response-phase predicates must set requires_response=true")
        return self


def _normalized_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"{value!r} is not a valid DNS domain")
    if domain in _REALISM_RESERVED_DOMAINS or any(
        domain.endswith(f".{suffix}") for suffix in _REALISM_RESERVED_DOMAINS
    ):
        raise ValueError(f"{value!r} uses a reserved documentation domain")
    return domain


def _normalized_hostname(value: str, *, allow_single_label: bool = False) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        raise ValueError("hostname must not be empty")
    if not allow_single_label and "." not in host:
        raise ValueError(f"{value!r} must be a fully-qualified hostname")
    if not _HOST_RE.fullmatch(host):
        raise ValueError(f"{value!r} is not a valid hostname")
    return host


def _unique_values(items: list[Any], attr: str, label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for item in items:
        value = str(getattr(item, attr, "")).lower()
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise ValueError(f"{label} contains duplicate values: {', '.join(sorted(duplicates))}")


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


class PublicDnsAnswerProfile(BaseModel, extra="forbid"):
    """A public DNS provider-style answer profile."""

    name: str
    weight: int
    match_suffixes: list[str] = Field(default_factory=list)
    answer_sets: list[list[str]]
    soa_rnames: list[str] = Field(default_factory=list)

    @field_validator("weight")
    @classmethod
    def weight_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("weight must be non-negative")
        return v

    @field_validator("match_suffixes", "soa_rnames")
    @classmethod
    def optional_strings_non_empty(cls, v: list[str], info) -> list[str]:
        if any(not item for item in v):
            raise ValueError(f"{info.field_name} entries must be non-empty")
        if info.field_name == "soa_rnames":
            for item in v:
                validate_public_dns_answer_template(item)
        return v

    @field_validator("answer_sets")
    @classmethod
    def answer_sets_non_empty(cls, v: list[list[str]]) -> list[list[str]]:
        if not v:
            raise ValueError("answer_sets must not be empty")
        for answer_set in v:
            if not answer_set:
                raise ValueError("answer_sets entries must not be empty")
            if any(not answer for answer in answer_set):
                raise ValueError("answer strings must be non-empty")
            for answer in answer_set:
                validate_public_dns_answer_template(answer)
        return v


class PublicDnsProfilesConfig(BaseModel, extra="forbid"):
    """Root schema for public_dns_profiles.yaml."""

    nameserver_profiles: list[PublicDnsAnswerProfile]
    mail_profiles: list[PublicDnsAnswerProfile]
    aaaa_profiles: list[PublicDnsAnswerProfile]
    generic_aaaa_probability: float = Field(default=0.62, ge=0.0, le=1.0)

    @field_validator("nameserver_profiles", "mail_profiles")
    @classmethod
    def profiles_non_empty(
        cls,
        v: list[PublicDnsAnswerProfile],
        info,
    ) -> list[PublicDnsAnswerProfile]:
        if not v:
            raise ValueError(f"{info.field_name} must not be empty")
        if sum(profile.weight for profile in v) <= 0:
            raise ValueError(f"{info.field_name} must include at least one positive weight")
        return v

    @field_validator("aaaa_profiles")
    @classmethod
    def aaaa_profiles_non_empty(
        cls,
        v: list[PublicDnsAnswerProfile],
    ) -> list[PublicDnsAnswerProfile]:
        if not v:
            raise ValueError("aaaa_profiles must not be empty")
        return v


# --- Data-driven identity pools ---


class WeightedDomainEntry(BaseModel, extra="forbid"):
    """Weighted external DNS domain entry for generated identities."""

    domain: str
    weight: int = Field(default=1, gt=0)

    @field_validator("domain")
    @classmethod
    def domain_realistic(cls, v: str) -> str:
        return _normalized_domain(v)


class WeightedLocalPartEntry(BaseModel, extra="forbid"):
    """Weighted email local-part entry."""

    local_part: str
    weight: int = Field(default=1, gt=0)

    @field_validator("local_part")
    @classmethod
    def local_part_non_empty(cls, v: str) -> str:
        local_part = v.strip()
        if not local_part:
            raise ValueError("local_part must not be empty")
        if "@" in local_part or any(ch.isspace() for ch in local_part):
            raise ValueError("local_part must not contain @ or whitespace")
        return local_part


class EmailBackgroundConfig(BaseModel, extra="forbid"):
    """Root schema for email_background.yaml."""

    external_domains: list[WeightedDomainEntry]
    inbound_local_parts: list[WeightedLocalPartEntry]
    outbound_local_parts: list[WeightedLocalPartEntry]

    @model_validator(mode="after")
    def pools_non_empty_and_unique(self) -> Self:
        for field_name in ("external_domains", "inbound_local_parts", "outbound_local_parts"):
            values = getattr(self, field_name)
            if not values:
                raise ValueError(f"{field_name} must not be empty")
        _unique_values(self.external_domains, "domain", "external_domains")
        _unique_values(self.inbound_local_parts, "local_part", "inbound_local_parts")
        _unique_values(self.outbound_local_parts, "local_part", "outbound_local_parts")
        return self


class MailPublicIdentitiesConfig(BaseModel, extra="forbid"):
    """Root schema for mail_public_identities.yaml."""

    reserved_replacement_domains: list[str]
    providers: list[dict[str, Any]]

    @field_validator("reserved_replacement_domains")
    @classmethod
    def replacement_domains_valid(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("reserved_replacement_domains must not be empty")
        normalized = [_normalized_domain(domain) for domain in v]
        if len(set(normalized)) != len(normalized):
            raise ValueError("reserved_replacement_domains contains duplicate domains")
        return normalized


class ExternalActorIpEntry(BaseModel, extra="forbid"):
    """Weighted public IPv4/IPv6 entry for omitted storyline external addresses."""

    ip: str
    weight: int = Field(default=1, gt=0)

    @field_validator("ip")
    @classmethod
    def ip_valid(cls, v: str) -> str:
        try:
            parsed = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"{v!r} is not a valid IP address") from exc
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
            raise ValueError(f"{v!r} must be a routable public IP address")
        return v


class ExternalActorProfilesConfig(BaseModel, extra="forbid"):
    """Root schema for external_actor_profiles.yaml."""

    logon_source_ips: list[ExternalActorIpEntry]
    failed_logon_source_ips: list[ExternalActorIpEntry]
    connection_c2_ips: list[ExternalActorIpEntry]

    @model_validator(mode="after")
    def pools_non_empty_and_unique(self) -> Self:
        for field_name in ("logon_source_ips", "failed_logon_source_ips", "connection_c2_ips"):
            values = getattr(self, field_name)
            if not values:
                raise ValueError(f"{field_name} must not be empty")
            _unique_values(values, "ip", field_name)
        return self


class SuspiciousBenignDnsHostEntry(BaseModel, extra="forbid"):
    """Weighted suspicious-looking benign DNS hostname entry."""

    hostname: str
    weight: int = Field(default=1, gt=0)

    @field_validator("hostname")
    @classmethod
    def hostname_valid(cls, v: str) -> str:
        return _normalized_hostname(v)


class SuspiciousBenignConnectionEntry(BaseModel, extra="forbid"):
    """Suspicious-looking benign outbound connection target entry."""

    dst_ip: str
    dst_port: int = Field(gt=0, le=65535)
    service: str
    hostname: str
    desc: str
    weight: int = Field(default=1, gt=0)

    @field_validator("dst_ip")
    @classmethod
    def dst_ip_valid(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"{v!r} is not a valid IP address") from exc
        return v

    @field_validator("hostname")
    @classmethod
    def hostname_valid(cls, v: str) -> str:
        return _normalized_hostname(v)

    @field_validator("service", "desc")
    @classmethod
    def strings_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("value must not be empty")
        return v


class SuspiciousBenignConfig(BaseModel, extra="forbid"):
    """Root schema for suspicious_benign.yaml."""

    dns_hosts: list[SuspiciousBenignDnsHostEntry]
    unusual_connections: list[SuspiciousBenignConnectionEntry]

    @model_validator(mode="after")
    def pools_non_empty_and_unique(self) -> Self:
        if not self.dns_hosts:
            raise ValueError("dns_hosts must not be empty")
        if not self.unusual_connections:
            raise ValueError("unusual_connections must not be empty")
        _unique_values(self.dns_hosts, "hostname", "dns_hosts")
        _unique_values(self.unusual_connections, "hostname", "unusual_connections")
        pairs = {(entry.hostname.lower(), entry.dst_ip) for entry in self.unusual_connections}
        if len(pairs) != len(self.unusual_connections):
            raise ValueError("unusual_connections contains duplicate hostname/dst_ip pairs")
        return self


class CommandParameterPoolsConfig(BaseModel, extra="forbid"):
    """Root schema for command_parameter_pools.yaml."""

    general: dict[str, list[str]]
    query: dict[str, list[str]]
    linux_query: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def pools_are_non_empty_strings_and_urls_have_hosts(self) -> Self:
        for section_name in ("general", "query", "linux_query"):
            section = getattr(self, section_name)
            for key, values in section.items():
                if not values:
                    raise ValueError(f"{section_name}.{key} must not be empty")
                for value in values:
                    if not str(value).strip():
                        raise ValueError(f"{section_name}.{key} contains an empty value")
                    if key.endswith("url") or key == "url":
                        parsed = urlparse(value)
                        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                            raise ValueError(
                                f"{section_name}.{key} value {value!r} must be an HTTP(S) URL with a host"
                            )
        return self


# --- Application Catalog ---


class LoadedModuleEntry(BaseModel, extra="forbid"):
    """A DLL/module entry in a loaded_modules list."""

    path: str
    signed: bool = True
    signature: str = "Microsoft Windows"
    signature_status: str = "Valid"
    pe_metadata: dict[str, str] | None = None
    load_phase: Literal["startup", "runtime"] | None = None
    startup_probability: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("startup_probability", mode="before")
    @classmethod
    def startup_probability_is_numeric(cls, value: Any) -> Any:
        """Reject booleans masquerading as numeric probabilities."""
        if isinstance(value, bool):
            raise ValueError("startup_probability must be a number between 0 and 1")
        return value

    @model_validator(mode="after")
    def known_vendor_modules_have_native_identity(self) -> Self:
        """Require explicit source-native identity for known third-party DLL families."""
        known_vendors = {
            "google\\chrome": ("Google LLC",),
            "mozilla firefox": ("Mozilla Corporation",),
            "7-zip": ("Igor Pavlov", "-"),
            "vmware": ("VMware, Inc.",),
            "dell": ("Dell Inc.",),
            "cisco": ("Cisco Systems, Inc.",),
        }
        path_lower = self.path.replace("/", "\\").lower()
        for path_fragment, allowed_signatures in known_vendors.items():
            if path_fragment not in path_lower:
                continue
            if self.signature not in allowed_signatures:
                raise ValueError(f"known third-party module {self.path!r} must use a native signer")
            if not self.pe_metadata:
                raise ValueError(f"known third-party module {self.path!r} must define pe_metadata")
            required_fields = {
                "file_version",
                "description",
                "product",
                "company",
                "original_filename",
            }
            missing = sorted(field for field in required_fields if not self.pe_metadata.get(field))
            if missing:
                raise ValueError(
                    f"known third-party module {self.path!r} missing pe_metadata fields: "
                    f"{', '.join(missing)}"
                )
        return self


class PlatformConfig(BaseModel, extra="forbid"):
    """Per-OS platform config within an application entry."""

    image_path: str
    pe_metadata: dict[str, str] | None = None
    command_templates: list[str] | None = None
    command_parameter_pools: dict[str, list[str]] | None = None
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
    selection_weight: int = Field(default=10, gt=0)
    compatibility_group: str | None = None
    compatibility_option: str | None = None
    singleton_per_session: bool = False


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
    roles: list[str] | None = None
    exclude_roles: list[str] | None = None
    services_any: list[str] | None = None
    host_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    slot_skip_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    slot_jitter_seconds: int | None = Field(default=None, ge=0, le=1800)
    # Optional fields for cron type
    cron_user: str | None = None
    cron_commands: dict[str, str] | None = None


# --- Extra Syslog Messages ---


class SyslogProgramEntry(BaseModel, extra="forbid"):
    """A single program entry in extra_syslog_messages.yaml."""

    app: str
    messages: list[str]
    params: dict[str, list[str]] | None = None
    parameter_profiles: list[dict[str, str]] | None = None
    distro: str | None = None
    roles: list[str] | None = None
    exclude_roles: list[str] | None = None
    system_types: list[str] | None = None
    transient: bool | None = None
    weight: int = Field(default=10, gt=0)
    max_per_host_window: int | None = Field(default=None, gt=0)


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

    @model_validator(mode="after")
    def rsa_named_ca_uses_rsa_keys(self) -> Self:
        """Reject RSA-named issuer profiles that can emit ECDSA metadata."""
        if " rsa " in f" {self.name.lower()} ":
            ecdsa_types = [key for key in self.key_types if key.type.lower() == "ecdsa"]
            if ecdsa_types:
                raise ValueError("RSA-named issuers must not include ecdsa key_types")
        return self


class TlsSanConfig(BaseModel, extra="forbid"):
    """SAN generation settings in tls_realism.yaml."""

    multi_label_public_suffixes: list[str]
    profile_weights: dict[str, int] = Field(default_factory=dict)
    _VALID_PROFILE_KEYS: ClassVar[set[str]] = {
        "apex_exact",
        "apex_www",
        "apex_wildcard",
        "subdomain_exact",
        "subdomain_parent",
        "subdomain_wildcard",
        "subdomain_sibling",
    }

    @field_validator("profile_weights")
    @classmethod
    def profile_weights_valid(cls, v: dict[str, int]) -> dict[str, int]:
        unknown = set(v) - cls._VALID_PROFILE_KEYS
        if unknown:
            raise ValueError(f"unknown SAN profile weights: {sorted(unknown)}")
        if any(weight < 0 for weight in v.values()):
            raise ValueError("SAN profile weights must be non-negative")
        if v and sum(v.values()) <= 0:
            raise ValueError("SAN profile weights must have a positive total")
        return v


class TlsSerialLength(BaseModel, extra="forbid"):
    """Weighted serial-number byte length in tls_realism.yaml."""

    bytes: int
    weight: int

    @field_validator("bytes")
    @classmethod
    def bytes_within_rfc_limit(cls, v: int) -> int:
        if not 1 <= v <= 20:
            raise ValueError("serial byte length must be between 1 and 20")
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        if v > TLS_SERIAL_LENGTH_MAX_WEIGHT:
            raise ValueError(f"weight must be <= {TLS_SERIAL_LENGTH_MAX_WEIGHT}")
        return v


class TlsSerialNumberConfig(BaseModel, extra="forbid"):
    """Certificate serial-number behavior settings in tls_realism.yaml."""

    byte_lengths: list[TlsSerialLength]

    @field_validator("byte_lengths")
    @classmethod
    def byte_lengths_non_empty(cls, v: list[TlsSerialLength]) -> list[TlsSerialLength]:
        if not v:
            raise ValueError("byte_lengths must not be empty")
        return v


class TlsOcspResponder(BaseModel, extra="forbid"):
    """Issuer-pattern to OCSP responder mapping in tls_realism.yaml."""

    issuer_patterns: list[str]
    domains: list[str]


class TlsOcspRequestPathConfig(BaseModel, extra="forbid"):
    """OCSP GET request-path shape settings in tls_realism.yaml."""

    min_encoded_chars: int = 72
    max_encoded_chars: int = 150
    include_padding_probability: float = 0.35
    der_prefixes: list[str] = Field(default_factory=list)

    @field_validator("min_encoded_chars", "max_encoded_chars")
    @classmethod
    def encoded_length_valid(cls, v: int) -> int:
        if v < 32 or v > 512:
            raise ValueError("encoded length must be between 32 and 512")
        return v

    @field_validator("include_padding_probability")
    @classmethod
    def padding_probability_valid(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("include_padding_probability must be between 0 and 1")
        return v

    @field_validator("der_prefixes")
    @classmethod
    def der_prefixes_valid(cls, v: list[str]) -> list[str]:
        if any(not prefix for prefix in v):
            raise ValueError("der_prefixes entries must be non-empty")
        return v

    @model_validator(mode="after")
    def encoded_range_valid(self) -> TlsOcspRequestPathConfig:
        if self.max_encoded_chars < self.min_encoded_chars:
            raise ValueError("max_encoded_chars must be >= min_encoded_chars")
        return self


class TlsOcspStatusProfile(BaseModel, extra="forbid"):
    """Explicit certificate-pattern status policy for generated OCSP responses."""

    name: str
    certificate_patterns: list[str]
    status_weights: dict[Literal["good", "unknown", "revoked"], int]
    revocation_reasons: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def name_non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("OCSP status profile names must not be empty")
        return v

    @field_validator("certificate_patterns")
    @classmethod
    def certificate_patterns_non_empty(cls, v: list[str]) -> list[str]:
        if not v or any(not pattern for pattern in v):
            raise ValueError("OCSP status profiles require certificate_patterns")
        return v

    @field_validator("status_weights")
    @classmethod
    def status_weights_valid(cls, v: dict[str, int]) -> dict[str, int]:
        if set(v) != {"good", "unknown", "revoked"}:
            raise ValueError("status_weights must contain good, unknown, and revoked")
        if any(weight < 0 for weight in v.values()) or sum(v.values()) <= 0:
            raise ValueError("status_weights must be non-negative with a positive total")
        return v

    @model_validator(mode="after")
    def revoked_profiles_have_reasons(self) -> Self:
        if self.status_weights.get("revoked", 0) > 0 and not self.revocation_reasons:
            raise ValueError("OCSP profiles that permit revoked status require reasons")
        return self


class TlsOcspResponseConfig(BaseModel, extra="forbid"):
    """OCSP response size and responder-scoped transfer timing bounds."""

    size_bytes_min: int = Field(gt=0)
    size_bytes_max: int = Field(gt=0)
    latency_ms_min: float = Field(gt=0)
    latency_ms_max: float = Field(gt=0)
    throughput_bytes_per_second_min: float = Field(gt=0)
    throughput_bytes_per_second_max: float = Field(gt=0)
    file_duration_floor_ms: float = Field(gt=0)

    @model_validator(mode="after")
    def ranges_are_ordered(self) -> Self:
        """Reject inverted response timing and size ranges."""

        if self.size_bytes_max < self.size_bytes_min:
            raise ValueError("size_bytes_max must be >= size_bytes_min")
        if self.latency_ms_max < self.latency_ms_min:
            raise ValueError("latency_ms_max must be >= latency_ms_min")
        if self.throughput_bytes_per_second_max < self.throughput_bytes_per_second_min:
            raise ValueError(
                "throughput_bytes_per_second_max must be >= throughput_bytes_per_second_min"
            )
        return self


class TlsOcspConfig(BaseModel, extra="forbid"):
    """OCSP behavior settings in tls_realism.yaml."""

    query_probability: float = 0.18
    request_hash_algorithm: Literal["sha1", "sha256"] = "sha1"
    cache_bucket_seconds: int
    this_update_max_skew_seconds: int
    next_update_min_seconds: int
    next_update_max_seconds: int
    response: TlsOcspResponseConfig
    request_path: TlsOcspRequestPathConfig = Field(default_factory=TlsOcspRequestPathConfig)
    responders: list[TlsOcspResponder] = Field(default_factory=list)
    status_weights: dict[Literal["good", "unknown", "revoked"], int]
    suppress_revoked_suffixes: list[str] = Field(default_factory=list)
    certificate_status_profiles: list[TlsOcspStatusProfile] = Field(default_factory=list)

    @field_validator("query_probability")
    @classmethod
    def query_probability_valid(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("query_probability must be between 0 and 1")
        return v

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


class TlsSubjectKeyProfile(BaseModel, extra="forbid"):
    """A CA subject-name to public-key profile mapping in tls_realism.yaml."""

    subject_patterns: list[str]
    issuer_family: str
    key_type: Literal["rsa", "ecdsa"]
    key_length: int
    child_signature_algorithms: list[
        Literal[
            "sha256WithRSAEncryption",
            "sha384WithRSAEncryption",
            "ecdsa-with-SHA256",
            "ecdsa-with-SHA384",
        ]
    ]

    @field_validator("subject_patterns")
    @classmethod
    def patterns_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("subject_patterns must not be empty")
        if any(not pattern for pattern in v):
            raise ValueError("subject_patterns entries must be non-empty")
        return v

    @field_validator("key_length")
    @classmethod
    def key_length_valid(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("key_length must be positive")
        return v

    @field_validator("child_signature_algorithms")
    @classmethod
    def child_signature_algorithms_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("child_signature_algorithms must not be empty")
        return v

    @model_validator(mode="after")
    def child_algorithms_match_key_type(self) -> Self:
        """Reject child signature algorithms incompatible with the issuer key."""
        has_ecdsa_alg = any(
            algorithm.startswith("ecdsa-") for algorithm in self.child_signature_algorithms
        )
        has_rsa_alg = any(
            algorithm.endswith("RSAEncryption") for algorithm in self.child_signature_algorithms
        )
        if self.key_type == "rsa" and has_ecdsa_alg:
            raise ValueError("rsa issuer profiles cannot use ecdsa child signature algorithms")
        if self.key_type == "ecdsa" and has_rsa_alg:
            raise ValueError("ecdsa issuer profiles cannot use RSA child signature algorithms")
        return self


class TlsAuthorityProfile(BaseModel, extra="forbid"):
    """Stable metadata for a known public or enterprise certificate authority."""

    subject: str
    issuer: str
    not_valid_before: int
    not_valid_after: int
    key_type: Literal["rsa", "ecdsa"]
    key_length: int

    @field_validator("subject", "issuer")
    @classmethod
    def distinguished_name_non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("authority profile distinguished names must be non-empty")
        return v

    @field_validator("not_valid_before", "not_valid_after")
    @classmethod
    def validity_epoch_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("authority profile validity epochs must be positive")
        return v

    @field_validator("key_length")
    @classmethod
    def key_length_valid(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("authority profile key_length must be positive")
        return v

    @model_validator(mode="after")
    def validity_window_ordered(self) -> Self:
        """Reject public CA profiles with inverted validity windows."""
        if self.not_valid_after <= self.not_valid_before:
            raise ValueError("authority profile not_valid_after must be after not_valid_before")
        return self


class TlsCertificateChainConfig(BaseModel, extra="forbid"):
    """Certificate-chain behavior settings in tls_realism.yaml."""

    include_intermediate_probability: float
    include_second_intermediate_probability: float
    present_trust_anchor: bool = False
    intermediate_validity_days_min: int
    intermediate_validity_days_max: int
    intermediate_not_before_max_days: int
    key_types: list[TlsKeyType]
    subject_key_profiles: list[TlsSubjectKeyProfile] = Field(default_factory=list)
    authority_profiles: list[TlsAuthorityProfile] = Field(default_factory=list)
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

    @model_validator(mode="after")
    def authority_profiles_fit_parent_validity(self) -> Self:
        """Reject configured CA chains where a child outlives its parent issuer."""
        profiles_by_subject = {profile.subject: profile for profile in self.authority_profiles}
        for profile in self.authority_profiles:
            if profile.subject == profile.issuer:
                continue
            issuer = profiles_by_subject.get(profile.issuer)
            if issuer is None:
                continue
            if (
                profile.not_valid_before < issuer.not_valid_before
                or profile.not_valid_after > issuer.not_valid_after
            ):
                raise ValueError(
                    "authority profile validity must fit within issuer validity window: "
                    f"{profile.subject}"
                )
        return self


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
    serial_numbers: TlsSerialNumberConfig
    ocsp: TlsOcspConfig
    certificate_chains: TlsCertificateChainConfig
    destinations: TlsDestinationsConfig


# --- Kerberos Realism ---


class KerberosWeightedHexValue(BaseModel, extra="forbid"):
    """Weighted hex value used by kerberos_realism.yaml."""

    value: str
    weight: int

    @field_validator("value")
    @classmethod
    def value_hex(cls, v: str) -> str:
        if not v.startswith("0x"):
            raise ValueError("value must be a hex string beginning with 0x")
        int(v, 16)
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class KerberosPreAuthTypeEntry(BaseModel, extra="forbid"):
    """Weighted Kerberos pre-auth type profile."""

    value: int
    weight: int
    certificate_required: bool
    certificate_profile: str | None = None
    description: str = ""

    @field_validator("value")
    @classmethod
    def allowed_pre_auth_type(cls, v: int) -> int:
        if v not in {0, 2, 15}:
            raise ValueError("pre-auth value must be one of 0, 2, or 15")
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v

    @model_validator(mode="after")
    def coherent_certificate_flags(self) -> KerberosPreAuthTypeEntry:
        if self.value == 15 and not self.certificate_required:
            raise ValueError("PreAuthType 15 must set certificate_required=true")
        if self.certificate_required and self.value != 15:
            raise ValueError("certificate_required=true is only valid for PreAuthType 15")
        if self.value == 15 and not self.certificate_profile:
            raise ValueError("PreAuthType 15 must reference a certificate_profile")
        if self.value != 15 and self.certificate_profile:
            raise ValueError("certificate_profile is only valid for PreAuthType 15")
        return self


class KerberosTgtSuccessConfig(BaseModel, extra="forbid"):
    """Successful 4768 field distributions."""

    pre_auth_types: dict[str, KerberosPreAuthTypeEntry]
    ticket_options: dict[str, KerberosWeightedHexValue]
    encryption_types: dict[str, KerberosWeightedHexValue]

    @field_validator("pre_auth_types", "ticket_options", "encryption_types")
    @classmethod
    def weighted_profiles_non_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("weighted profile dict must not be empty")
        if sum(entry.weight for entry in v.values()) <= 0:
            raise ValueError("weighted profile dict must have a positive total weight")
        return v

    @field_validator("ticket_options")
    @classmethod
    def allowed_ticket_options(
        cls, v: dict[str, KerberosWeightedHexValue]
    ) -> dict[str, KerberosWeightedHexValue]:
        allowed = {"0x40810010", "0x40810000", "0x40000010", "0x50800000", "0x10"}
        invalid = sorted({entry.value for entry in v.values()} - allowed)
        if invalid:
            raise ValueError(f"ticket_options contains unsupported values: {invalid}")
        return v

    @field_validator("encryption_types")
    @classmethod
    def allowed_encryption_types(
        cls, v: dict[str, KerberosWeightedHexValue]
    ) -> dict[str, KerberosWeightedHexValue]:
        allowed = {"0x12", "0x11", "0x17"}
        invalid = sorted({entry.value for entry in v.values()} - allowed)
        if invalid:
            raise ValueError(f"encryption_types contains unsupported values: {invalid}")
        return v

    @model_validator(mode="after")
    def realistic_weights(self) -> KerberosTgtSuccessConfig:
        pre_auth_weight_by_value: dict[int, int] = {}
        for entry in self.pre_auth_types.values():
            pre_auth_weight_by_value[entry.value] = (
                pre_auth_weight_by_value.get(entry.value, 0) + entry.weight
            )
        total_pre_auth = sum(pre_auth_weight_by_value.values())
        if pre_auth_weight_by_value.get(2, 0) == 0:
            raise ValueError("PreAuthType 2 must be present for normal encrypted timestamp TGTs")
        if pre_auth_weight_by_value.get(15, 0) / total_pre_auth > 0.20:
            raise ValueError("PreAuthType 15 PKINIT weight must not exceed 20% by default")
        if pre_auth_weight_by_value.get(0, 0) / total_pre_auth > 0.05:
            raise ValueError("PreAuthType 0/no-preauth weight must not exceed 5%")

        encryption_weight_by_value: dict[str, int] = {}
        for entry in self.encryption_types.values():
            encryption_weight_by_value[entry.value] = (
                encryption_weight_by_value.get(entry.value, 0) + entry.weight
            )
        total_encryption = sum(encryption_weight_by_value.values())
        if encryption_weight_by_value.get("0x17", 0) / total_encryption > 0.30:
            raise ValueError("RC4 encryption type 0x17 weight must not exceed 30%")
        return self


class KerberosFailurePreAuthTypeEntry(BaseModel, extra="forbid"):
    """Weighted 4771 failure pre-auth profile."""

    value: int
    weight: int
    description: str = ""

    @field_validator("value")
    @classmethod
    def allowed_pre_auth_type(cls, v: int) -> int:
        if v not in {0, 2}:
            raise ValueError("failure pre-auth value must be one of 0 or 2")
        return v

    @field_validator("weight")
    @classmethod
    def weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class KerberosTgtFailureConfig(BaseModel, extra="forbid"):
    """Failed 4771 field distributions."""

    pre_auth_types: dict[str, KerberosFailurePreAuthTypeEntry]
    ticket_options: dict[str, KerberosWeightedHexValue]

    @field_validator("pre_auth_types", "ticket_options")
    @classmethod
    def weighted_profiles_non_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("weighted profile dict must not be empty")
        if sum(entry.weight for entry in v.values()) <= 0:
            raise ValueError("weighted profile dict must have a positive total weight")
        return v

    @model_validator(mode="after")
    def realistic_failure_weights(self) -> KerberosTgtFailureConfig:
        weights: dict[int, int] = {}
        for entry in self.pre_auth_types.values():
            weights[entry.value] = weights.get(entry.value, 0) + entry.weight
        total = sum(weights.values())
        if weights.get(2, 0) == 0:
            raise ValueError("4771 failure PreAuthType 2 must be present")
        if weights.get(0, 0) / total > 0.10:
            raise ValueError("4771 failure PreAuthType 0/no-preauth weight must not exceed 10%")
        return self


class KerberosCertificateProfile(BaseModel, extra="forbid"):
    """Certificate field generation profile for Kerberos PKINIT events."""

    issuer_names: list[str]
    serial_hex_bytes: int = 16
    thumbprint_hex_chars: int = 40

    @field_validator("issuer_names")
    @classmethod
    def issuer_names_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("issuer_names must not be empty")
        if any(not issuer for issuer in v):
            raise ValueError("issuer_names entries must be non-empty")
        return v

    @field_validator("serial_hex_bytes")
    @classmethod
    def serial_bytes_range(cls, v: int) -> int:
        if not 8 <= v <= 20:
            raise ValueError("serial_hex_bytes must be between 8 and 20")
        return v

    @field_validator("thumbprint_hex_chars")
    @classmethod
    def thumbprint_length_valid(cls, v: int) -> int:
        if v not in {40, 64}:
            raise ValueError("thumbprint_hex_chars must be 40 (SHA-1) or 64 (SHA-256)")
        return v


class KerberosTransportProfile(BaseModel, extra="forbid"):
    """TCP/UDP transport weights for Kerberos network exchanges."""

    _MAX_TRANSPORT_WEIGHT: ClassVar[int] = KERBEROS_TRANSPORT_MAX_WEIGHT
    udp: int = 0
    tcp: int = 0

    @field_validator("udp", "tcp")
    @classmethod
    def weight_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("transport weights must be non-negative")
        if v > cls._MAX_TRANSPORT_WEIGHT:
            raise ValueError(
                f"transport weights must be less than or equal to {cls._MAX_TRANSPORT_WEIGHT}"
            )
        return v

    @model_validator(mode="after")
    def has_positive_weight(self) -> KerberosTransportProfile:
        if self.udp + self.tcp <= 0:
            raise ValueError("transport profile must have a positive total weight")
        return self


class KerberosRealismConfig(BaseModel, extra="forbid"):
    """Root schema for kerberos_realism.yaml."""

    tgt_success: KerberosTgtSuccessConfig
    tgt_failure: KerberosTgtFailureConfig
    certificate_profiles: dict[str, KerberosCertificateProfile] = Field(default_factory=dict)
    transport_profiles: dict[str, KerberosTransportProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def referenced_certificate_profiles_exist(self) -> KerberosRealismConfig:
        profile_names = set(self.certificate_profiles)
        missing = sorted(
            {
                entry.certificate_profile
                for entry in self.tgt_success.pre_auth_types.values()
                if entry.certificate_profile and entry.certificate_profile not in profile_names
            }
        )
        if missing:
            raise ValueError(f"unknown certificate_profile references: {missing}")
        if self.transport_profiles and "default" not in self.transport_profiles:
            raise ValueError("transport_profiles must include a default profile")
        return self


class HttpRequestProfilesConfig(BaseModel, extra="forbid"):
    """Request-entity classification values in http_file_profiles.yaml."""

    browser_form: str
    json_api: str
    binary: str
    json_uri_tokens: list[str] = Field(min_length=1)

    @field_validator("browser_form", "json_api", "binary")
    @classmethod
    def mime_type_is_valid(cls, value: str) -> str:
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", value):
            raise ValueError("must be a MIME type such as application/json")
        return value

    @field_validator("json_uri_tokens")
    @classmethod
    def uri_tokens_are_non_empty(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("json_uri_tokens must contain non-empty strings")
        return values


class HttpFileProfilesConfig(BaseModel, extra="forbid"):
    """Root schema for bidirectional HTTP file-analysis profiles."""

    extension_mime_types: dict[str, str]
    request_profiles: HttpRequestProfilesConfig
    multipart: HttpMultipartProfilesConfig

    @field_validator("extension_mime_types")
    @classmethod
    def extensions_and_mime_types_are_valid(cls, values: dict[str, str]) -> dict[str, str]:
        if not values:
            raise ValueError("extension_mime_types must not be empty")
        for extension, mime_type in values.items():
            if not re.fullmatch(r"\.[a-z0-9]+", extension):
                raise ValueError(f"invalid lowercase file extension {extension!r}")
            if not re.fullmatch(r"[^/\s]+/[^/\s]+", mime_type):
                raise ValueError(f"invalid MIME type {mime_type!r} for {extension}")
        return values


class HttpMultipartBoundaryProfile(BaseModel, extra="forbid"):
    """Deterministic multipart boundary morphology for one client family."""

    prefix: str = Field(min_length=1, max_length=50)
    suffix_length: int = Field(ge=4, le=40)


class HttpMultipartProfilesConfig(BaseModel, extra="forbid"):
    """Multipart serializer and Zeek projection limits."""

    boundaries: dict[str, HttpMultipartBoundaryProfile]
    header_order: list[
        Literal["content_disposition", "content_type", "content_length", "transfer_encoding"]
    ]
    max_parts: int = Field(ge=1, le=1000)
    max_depth: int = Field(ge=1, le=100)
    max_files_orig: int = Field(ge=1, le=1000)
    max_files_resp: int = Field(ge=1, le=1000)
    quoted_printable_escape_percent: int = Field(ge=0, le=100)

    @field_validator("boundaries")
    @classmethod
    def required_boundary_families_exist(
        cls, values: dict[str, HttpMultipartBoundaryProfile]
    ) -> dict[str, HttpMultipartBoundaryProfile]:
        required = {"browser", "curl", "generic"}
        missing = required - set(values)
        if missing:
            raise ValueError(f"multipart boundaries missing families: {sorted(missing)}")
        return values

    @field_validator("header_order")
    @classmethod
    def header_order_is_complete(cls, values: list[str]) -> list[str]:
        required = {
            "content_disposition",
            "content_type",
            "content_length",
            "transfer_encoding",
        }
        if set(values) != required or len(values) != len(required):
            raise ValueError("multipart header_order must list every supported header exactly once")
        return values


# --- Auth Noise ---

_AUTH_NOISE_ACCOUNT_NAME_RE = re.compile(r"^[a-zA-Z0-9._$-]+$")


class AuthNoiseIntervalRange(BaseModel, extra="forbid"):
    """A weighted interval range for auth-noise recurrence."""

    min_minutes: int = Field(ge=1, le=1440)
    max_minutes: int = Field(ge=1, le=1440)
    weight: int = Field(gt=0)

    @model_validator(mode="after")
    def valid_range(self) -> Self:
        if self.max_minutes < self.min_minutes:
            raise ValueError("max_minutes must be greater than or equal to min_minutes")
        return self


class ScheduledStaleCredentialsConfig(BaseModel, extra="forbid"):
    """Stale scheduled-task failed-logon noise profile."""

    account_base_names: list[str] = Field(min_length=1)
    host_count_min: int = Field(ge=1)
    host_count_max: int = Field(ge=1)
    interval_ranges: list[AuthNoiseIntervalRange] = Field(min_length=1)
    first_occurrence_seconds_min: int = Field(ge=0, le=86_400)
    first_occurrence_seconds_max: int = Field(ge=0, le=86_400)
    jitter_seconds_min: int = Field(ge=-86_400, le=86_400)
    jitter_seconds_max: int = Field(ge=-86_400, le=86_400)
    skip_probability: float = Field(ge=0.0, le=0.95)
    backoff_probability: float = Field(ge=0.0, le=0.95)
    backoff_seconds_min: int = Field(ge=0, le=86_400)
    backoff_seconds_max: int = Field(ge=0, le=86_400)

    @field_validator("account_base_names")
    @classmethod
    def account_base_names_match_usernames(cls, v: list[str]) -> list[str]:
        for name in v:
            stripped_name = name.strip() if isinstance(name, str) else ""
            if not stripped_name:
                raise ValueError("account_base_names entries must be non-empty")
            if _AUTH_NOISE_ACCOUNT_NAME_RE.fullmatch(stripped_name) is None:
                raise ValueError(
                    "account_base_names entries must match scenario username syntax "
                    "^[a-zA-Z0-9._$-]+$"
                )
        return v

    @model_validator(mode="after")
    def valid_ranges(self) -> Self:
        if self.host_count_max < self.host_count_min:
            raise ValueError("host_count_max must be greater than or equal to host_count_min")
        if self.first_occurrence_seconds_max < self.first_occurrence_seconds_min:
            raise ValueError(
                "first_occurrence_seconds_max must be greater than or equal to "
                "first_occurrence_seconds_min"
            )
        if self.jitter_seconds_max < self.jitter_seconds_min:
            raise ValueError(
                "jitter_seconds_max must be greater than or equal to jitter_seconds_min"
            )
        if self.backoff_seconds_max < self.backoff_seconds_min:
            raise ValueError(
                "backoff_seconds_max must be greater than or equal to backoff_seconds_min"
            )
        return self


class ServiceAccountDelegationProcessConfig(BaseModel, extra="forbid"):
    """One caller-process choice for service-account explicit-credential noise."""

    image: str = Field(min_length=1)
    command_line: str = Field(min_length=1)
    parent_key: str = Field(default="services", min_length=1)
    weight: int = Field(gt=0)
    system_types: list[str] | None = None
    compatibility_group: str | None = None
    compatibility_option: str | None = None


class ServiceAccountDelegationProfileConfig(BaseModel, extra="forbid"):
    """Role-specific service-account delegation caller profile."""

    name: str = Field(min_length=1)
    account_terms: list[str] = Field(min_length=1)
    weight: int = Field(gt=0)
    processes: list[ServiceAccountDelegationProcessConfig] = Field(min_length=1)

    @field_validator("account_terms")
    @classmethod
    def account_terms_are_non_empty(cls, v: list[str]) -> list[str]:
        for term in v:
            if not term.strip():
                raise ValueError("account_terms entries must be non-empty")
        return v


class ServiceAccountDelegationConfig(BaseModel, extra="forbid"):
    """Service-account explicit-credential baseline profile."""

    hourly_probability: float = Field(ge=0.0, le=0.95)
    caller_profiles: list[ServiceAccountDelegationProfileConfig] = Field(min_length=1)


class AuthNoiseConfig(BaseModel, extra="forbid"):
    """Root schema for auth_noise.yaml."""

    scheduled_stale_credentials: ScheduledStaleCredentialsConfig
    service_account_delegation: ServiceAccountDelegationConfig


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


class PublicDnsResolverEntry(BaseModel, extra="forbid"):
    """A public recursive DNS resolver profile in network_params.yaml."""

    name: str
    ip: IPvAnyAddress
    operator: str
    weight: int = Field(gt=0)


class DnsTunnelRttConfig(BaseModel, extra="forbid"):
    """DNS tunnel response timing parameters in network_params.yaml."""

    min_seconds: float = Field(ge=0.001)
    max_seconds: float = Field(ge=0.001)

    @model_validator(mode="after")
    def valid_range(self) -> DnsTunnelRttConfig:
        if self.max_seconds < self.min_seconds:
            raise ValueError("max_seconds must be greater than or equal to min_seconds")
        if self.max_seconds > 10.0:
            raise ValueError("max_seconds should stay within realistic DNS transaction timing")
        return self


class DnsTunnelTtlEntry(BaseModel, extra="forbid"):
    """A weighted DNS tunnel response TTL choice in network_params.yaml."""

    value: int = Field(ge=0, le=3600)
    weight: float = Field(gt=0, allow_inf_nan=False)


class ExternalScannerPortWeight(BaseModel, extra="forbid"):
    """A weighted destination port in an external scanner profile."""

    port: int = Field(ge=1, le=65535)
    weight: float = Field(gt=0, allow_inf_nan=False)


class ExternalScannerPortProfile(BaseModel, extra="forbid"):
    """A source-sticky external scanner port preference profile."""

    name: str
    weight: float = Field(gt=0, allow_inf_nan=False)
    ports: list[ExternalScannerPortWeight]

    @field_validator("ports")
    @classmethod
    def ports_non_empty(cls, v: list[ExternalScannerPortWeight]) -> list[ExternalScannerPortWeight]:
        if not v:
            raise ValueError("ports must not be empty")
        return v


# --- SMB Client and Server Profiles ---


SmbOperationName = Literal["browse", "read", "create", "update", "copy", "move", "delete"]
SmbPurposeName = Literal[
    "interactive",
    "administrative",
    "software",
    "backup",
    "collection",
    "ransomware",
    "auto",
]
SmbProcessOperandMode = Literal[
    "none",
    "remote",
    "download",
    "upload",
    "rename",
    "transfer",
]
SmbAuthOptionName = Literal["auto", "kerberos", "ntlmssp"]
_SMB_OPERATIONS = frozenset({"browse", "read", "create", "update", "copy", "move", "delete"})
_SMB_PURPOSES = frozenset(
    {"interactive", "administrative", "software", "backup", "collection", "ransomware", "auto"}
)
SmbVfsAuditProfileName = Literal["standard", "high"]
SmbAuditEventType = Literal[
    "smb_directory_enumeration",
    "smb_file_open",
    "smb_file_read",
    "smb_file_write",
    "smb_file_rename",
    "smb_file_delete",
    "smb_file_close",
]
_SMB_AUDIT_EVENT_TYPES = frozenset(
    {
        "smb_directory_enumeration",
        "smb_file_open",
        "smb_file_read",
        "smb_file_write",
        "smb_file_rename",
        "smb_file_delete",
        "smb_file_close",
    }
)
_SMB_TEMPLATE_FIELDS = frozenset(
    {
        "server",
        "share",
        "path",
        "client_path",
        "local_path",
        "source_path",
        "destination_path",
        "username",
        "smb_principal",
        "auth_options",
        "operation",
        "client_ip",
    }
)


def _validate_smb_filesystem_label(value: str) -> str:
    """Normalize one safe SMB wire-advertised filesystem label."""

    normalized = value.strip()
    if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._ -]{0,63}", normalized) is None:
        raise ValueError("advertised filesystem labels must be nonempty safe labels")
    return normalized


class SmbAdvertisedFilesystemDefaults(BaseModel, extra="forbid", frozen=True):
    """Provider defaults mapping backing filesystems to SMB wire labels."""

    windows: dict[Literal["ntfs", "refs"], str]
    linux: dict[Literal["ext4", "xfs"], str]

    @field_validator("windows", "linux")
    @classmethod
    def valid_labels(cls, values: dict[str, str]) -> dict[str, str]:
        """Normalize every advertised label before it reaches compiler output."""

        return {
            filesystem: _validate_smb_filesystem_label(label)
            for filesystem, label in values.items()
        }

    @model_validator(mode="after")
    def complete_platform_defaults(self) -> Self:
        """Require one default for every supported platform/backing pair."""

        if set(self.windows) != {"ntfs", "refs"}:
            raise ValueError("advertised filesystem windows defaults require ntfs and refs")
        if set(self.linux) != {"ext4", "xfs"}:
            raise ValueError("advertised filesystem linux defaults require ext4 and xfs")
        return self


class SmbSambaAuditOperation(BaseModel, extra="forbid", frozen=True):
    """Source-native Samba label and audit-tier eligibility for one event."""

    label: str
    audit_profiles: tuple[SmbVfsAuditProfileName, ...]

    @field_validator("label")
    @classmethod
    def valid_label(cls, value: str) -> str:
        """Require a compact vfs_full_audit-style operation token."""

        normalized = value.strip().casefold()
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", normalized) is None:
            raise ValueError("Samba audit operation label must be a safe lowercase token")
        return normalized

    @field_validator("audit_profiles", mode="before")
    @classmethod
    def lifecycle_only_minimal(cls, values: object) -> object:
        """Reject attempts to turn the minimal lifecycle tier into file auditing."""

        if isinstance(values, (list, tuple)) and any(
            str(value).strip().casefold() == "minimal" for value in values
        ):
            raise ValueError(
                "Samba operation audit_profiles cannot include minimal; minimal is lifecycle-only"
            )
        return values

    @field_validator("audit_profiles")
    @classmethod
    def unique_audit_profiles(
        cls,
        values: tuple[SmbVfsAuditProfileName, ...],
    ) -> tuple[SmbVfsAuditProfileName, ...]:
        """Reject duplicate or non-monotonic tier declarations."""

        if len(values) != len(set(values)):
            raise ValueError("Samba operation audit_profiles must not contain duplicates")
        if "standard" in values and "high" not in values:
            raise ValueError(
                "Samba operation audit_profiles containing standard must also contain high"
            )
        return values


class SmbSambaAuditConfig(BaseModel, extra="forbid", frozen=True):
    """Samba VFS audit eligibility and canonical operation labels."""

    failure_audit_profiles: tuple[SmbVfsAuditProfileName, ...]
    operations: dict[SmbAuditEventType, SmbSambaAuditOperation]

    @field_validator("failure_audit_profiles", mode="before")
    @classmethod
    def lifecycle_only_minimal_failures(cls, values: object) -> object:
        """Reject per-file failure audit configuration in the minimal tier."""

        if isinstance(values, (list, tuple)) and any(
            str(value).strip().casefold() == "minimal" for value in values
        ):
            raise ValueError(
                "failure_audit_profiles cannot include minimal; minimal is lifecycle-only"
            )
        return values

    @field_validator("failure_audit_profiles")
    @classmethod
    def unique_failure_profiles(
        cls,
        values: tuple[SmbVfsAuditProfileName, ...],
    ) -> tuple[SmbVfsAuditProfileName, ...]:
        """Require a duplicate-free, monotonic failure-observation tier set."""

        if len(values) != len(set(values)):
            raise ValueError("failure_audit_profiles must not contain duplicates")
        if "standard" in values and "high" not in values:
            raise ValueError("failure_audit_profiles containing standard must also contain high")
        return values

    @model_validator(mode="after")
    def complete_operation_map(self) -> Self:
        """Keep every canonical Samba audit event mapped explicitly."""

        missing = sorted(_SMB_AUDIT_EVENT_TYPES - set(self.operations))
        if missing:
            raise ValueError(f"Samba audit operations are missing canonical events: {missing}")
        return self


def _validate_smb_template(value: str, field_name: str) -> str:
    """Validate one SMB process template without evaluating it."""

    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    try:
        parsed = tuple(Formatter().parse(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} has invalid format syntax: {exc}") from exc
    for _literal, placeholder, format_spec, conversion in parsed:
        if placeholder is None:
            continue
        if placeholder not in _SMB_TEMPLATE_FIELDS:
            raise ValueError(
                f"{field_name} uses unsupported placeholder {placeholder!r}; "
                f"allowed placeholders are {sorted(_SMB_TEMPLATE_FIELDS)}"
            )
        if format_spec or conversion:
            raise ValueError(f"{field_name} placeholders cannot use conversions or format specs")
    return value


class SmbProcessProfile(BaseModel, extra="forbid", frozen=True):
    """Process metadata for one SMB client or server lifecycle owner."""

    key_template: str
    image: str
    command_line_template: str
    username_template: str
    lifecycle: Literal["resident", "operation", "transport", "service"]
    credential_source: Literal["none", "smb_principal"] = "none"
    operand_mode: SmbProcessOperandMode = "none"

    @field_validator("key_template", "command_line_template", "username_template")
    @classmethod
    def valid_template(cls, value: str, info: ValidationInfo) -> str:
        """Reject empty templates, unsafe field traversal, and unknown placeholders."""

        return _validate_smb_template(value, info.field_name)

    @field_validator("image")
    @classmethod
    def image_non_empty(cls, value: str) -> str:
        """Require a literal image path rather than a generated template."""

        if not value.strip():
            raise ValueError("image must not be empty")
        if "{" in value or "}" in value:
            raise ValueError("image must be a literal path without placeholders")
        return value

    @model_validator(mode="after")
    def coherent_identity_and_operands(self) -> Self:
        """Keep local ownership, remote credentials, and command operands distinct."""

        def placeholders(template: str) -> set[str]:
            return {
                placeholder
                for _literal, placeholder, _format_spec, _conversion in Formatter().parse(template)
                if placeholder is not None
            }

        command_fields = placeholders(self.command_line_template)
        owner_fields = placeholders(self.username_template)
        if "smb_principal" in owner_fields:
            raise ValueError("username_template cannot use the remote SMB principal")
        if self.credential_source == "smb_principal":
            if "smb_principal" not in command_fields:
                raise ValueError(
                    "credential_source=smb_principal requires {smb_principal} in the command"
                )
        elif "smb_principal" in command_fields:
            raise ValueError(
                "commands using {smb_principal} must declare credential_source=smb_principal"
            )

        required_fields = {
            "none": set(),
            "remote": {"path"},
            "download": {"path", "local_path"},
            "upload": {"path", "local_path"},
            "rename": {"path", "destination_path"},
            "transfer": {"source_path", "destination_path"},
        }[self.operand_mode]
        missing_fields = sorted(required_fields - command_fields)
        if missing_fields:
            raise ValueError(
                f"operand_mode={self.operand_mode} requires command placeholders {missing_fields}"
            )
        if self.operand_mode in {"download", "upload"} and "client_path" in command_fields:
            raise ValueError(
                f"operand_mode={self.operand_mode} must use {{local_path}}, not {{client_path}}"
            )
        return self


class SmbClientProfile(BaseModel, extra="forbid", frozen=True):
    """Platform-native client presentation and process ownership profile."""

    os_category: Literal["windows", "linux"]
    access_mode: Literal["explorer", "desktop", "direct", "mounted"]
    path_style: Literal["unc", "mapped", "smb_uri", "mounted"]
    transport_attribution: Literal["process", "kernel", "none"]
    service_aliases: tuple[str, ...] = ()
    weight: float = Field(default=1.0, gt=0.0, allow_inf_nan=False)
    system_types: tuple[Literal["workstation", "server", "domain_controller"], ...] = (
        "workstation",
        "server",
        "domain_controller",
    )
    auth_options: dict[SmbAuthOptionName, str] = Field(default_factory=dict)
    process: SmbProcessProfile | None = None
    operation_processes: dict[SmbOperationName, SmbProcessProfile] = Field(default_factory=dict)

    @field_validator("service_aliases")
    @classmethod
    def valid_service_aliases(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize non-empty service aliases and reject duplicates."""

        normalized = tuple(value.strip().casefold() for value in values)
        if any(
            not value or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value) for value in normalized
        ):
            raise ValueError("service_aliases must contain non-empty service identifiers")
        if len(normalized) != len(set(normalized)):
            raise ValueError("service_aliases must not contain duplicates")
        return normalized

    @field_validator("system_types")
    @classmethod
    def valid_system_types(
        cls,
        values: tuple[Literal["workstation", "server", "domain_controller"], ...],
    ) -> tuple[Literal["workstation", "server", "domain_controller"], ...]:
        """Require a non-empty, duplicate-free eligibility set."""

        if not values:
            raise ValueError("system_types must not be empty")
        if len(values) != len(set(values)):
            raise ValueError("system_types must not contain duplicates")
        return values

    @field_validator("auth_options")
    @classmethod
    def valid_auth_options(cls, values: dict[str, str]) -> dict[str, str]:
        """Require source-native smbclient options without shell control syntax."""

        option_pattern = re.compile(
            r"--[a-z0-9][a-z0-9-]*(?:=[a-z0-9][a-z0-9._-]*)?"
            r"(?: --[a-z0-9][a-z0-9-]*(?:=[a-z0-9][a-z0-9._-]*)?)*"
        )
        normalized = {name: option.strip() for name, option in values.items()}
        invalid = sorted(
            name for name, option in normalized.items() if option_pattern.fullmatch(option) is None
        )
        if invalid:
            raise ValueError(f"auth_options contain unsafe or empty values for {invalid}")
        return normalized

    @model_validator(mode="after")
    def coherent_platform_and_ownership(self) -> Self:
        """Keep access mode, presentation, and process ownership coherent."""

        if self.access_mode == "explorer" and self.os_category != "windows":
            raise ValueError("explorer access_mode requires os_category=windows")
        if self.access_mode != "explorer" and self.os_category != "linux":
            raise ValueError(f"{self.access_mode} access_mode requires os_category=linux")
        if self.os_category == "windows" and self.path_style not in {"unc", "mapped"}:
            raise ValueError("Windows SMB clients require unc or mapped path_style")
        if self.access_mode in {"desktop", "direct"} and self.path_style != "smb_uri":
            raise ValueError(f"{self.access_mode} access_mode requires path_style=smb_uri")
        if self.access_mode == "mounted" and self.path_style != "mounted":
            raise ValueError("mounted access_mode requires path_style=mounted")
        if self.access_mode == "direct" and self.transport_attribution != "process":
            raise ValueError("direct access_mode requires transport_attribution=process")
        if self.access_mode == "mounted" and self.transport_attribution != "kernel":
            raise ValueError("mounted access_mode requires transport_attribution=kernel")

        missing_operations = sorted(_SMB_OPERATIONS - set(self.operation_processes))
        if self.access_mode == "mounted" and self.process is not None:
            raise ValueError(
                "mounted access_mode cannot declare a default process; mount lifecycle is "
                "separate from per-operation actors"
            )
        if self.access_mode == "mounted" and missing_operations:
            raise ValueError(
                "mounted access_mode requires operation_processes for every SMB operation; "
                f"missing {missing_operations}"
            )
        if self.process is None and missing_operations:
            raise ValueError(
                "profiles without a default process require operation_processes for every SMB "
                f"operation; missing {missing_operations}"
            )
        if self.access_mode in {"explorer", "desktop"} and (
            self.process is None or self.process.lifecycle != "resident"
        ):
            raise ValueError(f"{self.access_mode} access_mode requires a resident process")
        if (
            self.access_mode == "direct"
            and self.process is not None
            and self.process.lifecycle != "operation"
        ):
            raise ValueError("direct access_mode default process must use lifecycle=operation")
        if self.access_mode in {"direct", "mounted"} and any(
            process.lifecycle != "operation" for process in self.operation_processes.values()
        ):
            raise ValueError(f"{self.access_mode} operation_processes must use lifecycle=operation")
        processes = [
            process
            for process in (self.process, *self.operation_processes.values())
            if process is not None
        ]
        uses_auth_options = any(
            "{auth_options}" in process.command_line_template for process in processes
        )
        if uses_auth_options and set(self.auth_options) != {"auto", "kerberos", "ntlmssp"}:
            raise ValueError(
                "profiles using {auth_options} require auto, kerberos, and ntlmssp mappings"
            )
        if self.auth_options and not uses_auth_options:
            raise ValueError("auth_options require {auth_options} in a process command template")
        return self


class SmbServerProfile(BaseModel, extra="forbid", frozen=True):
    """Platform-native SMB server listener and optional connection worker."""

    os_category: Literal["windows", "linux"]
    service_aliases: tuple[str, ...]
    listener: SmbProcessProfile
    worker: SmbProcessProfile | None = None

    @field_validator("service_aliases")
    @classmethod
    def valid_service_aliases(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize server service aliases and reject duplicates."""

        normalized = tuple(value.strip().casefold() for value in values)
        if not normalized or any(
            not value or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value) for value in normalized
        ):
            raise ValueError("service_aliases must contain non-empty service identifiers")
        if len(normalized) != len(set(normalized)):
            raise ValueError("service_aliases must not contain duplicates")
        return normalized

    @model_validator(mode="after")
    def coherent_process_lifecycles(self) -> Self:
        """Require one durable listener and Linux per-transport workers."""

        if self.listener.lifecycle != "service":
            raise ValueError("SMB server listener must use lifecycle=service")
        if self.worker is not None and self.worker.lifecycle != "transport":
            raise ValueError("SMB server worker must use lifecycle=transport")
        if self.os_category == "linux" and self.worker is None:
            raise ValueError("Linux Samba server profiles require a per-transport worker")
        return self


class SmbTransferTimingConfig(BaseModel, extra="forbid", frozen=True):
    """Bounded wire-rate and operation timing texture for canonical SMB activity."""

    throughput_median_bytes_per_second: float = Field(gt=0.0, allow_inf_nan=False)
    throughput_sigma: float = Field(gt=0.0, le=2.0, allow_inf_nan=False)
    throughput_min_bytes_per_second: float = Field(gt=0.0, allow_inf_nan=False)
    throughput_max_bytes_per_second: float = Field(gt=0.0, allow_inf_nan=False)
    session_setup_seconds: tuple[float, float]
    operation_setup_seconds: tuple[float, float]
    operation_jitter_seconds: tuple[float, float]
    close_delay_seconds: tuple[float, float]
    purpose_dwell_seconds: dict[SmbPurposeName, tuple[float, float]]
    transport_tail_seconds: float = Field(gt=0.0, allow_inf_nan=False)

    @field_validator(
        "session_setup_seconds",
        "operation_setup_seconds",
        "operation_jitter_seconds",
        "close_delay_seconds",
    )
    @classmethod
    def valid_range(cls, values: tuple[float, float], info: ValidationInfo) -> tuple[float, float]:
        """Require finite, nonnegative, increasing timing ranges."""

        if len(values) != 2:
            raise ValueError(f"{info.field_name} must contain exactly [minimum, maximum]")
        minimum, maximum = values
        if not math.isfinite(minimum) or not math.isfinite(maximum):
            raise ValueError(f"{info.field_name} values must be finite")
        if minimum < 0 or maximum <= minimum:
            raise ValueError(f"{info.field_name} must have 0 <= minimum < maximum, got {values!r}")
        return values

    @model_validator(mode="after")
    def coherent_bounds(self) -> Self:
        """Keep throughput and total-duration clamps internally coherent."""

        if self.throughput_max_bytes_per_second <= self.throughput_min_bytes_per_second:
            raise ValueError(
                "throughput_max_bytes_per_second must exceed throughput_min_bytes_per_second"
            )
        if not (
            self.throughput_min_bytes_per_second
            <= self.throughput_median_bytes_per_second
            <= self.throughput_max_bytes_per_second
        ):
            raise ValueError("throughput median must fall within the configured bounds")
        missing = sorted(_SMB_PURPOSES - set(self.purpose_dwell_seconds))
        if missing:
            raise ValueError(f"purpose_dwell_seconds is missing SMB purposes: {missing}")
        for purpose, values in self.purpose_dwell_seconds.items():
            if len(values) != 2:
                raise ValueError(f"purpose_dwell_seconds.{purpose} must contain [minimum, maximum]")
            minimum, maximum = values
            if (
                not math.isfinite(minimum)
                or not math.isfinite(maximum)
                or minimum < 0
                or maximum <= minimum
            ):
                raise ValueError(
                    f"purpose_dwell_seconds.{purpose} must have 0 <= minimum < maximum"
                )
        return self


class SmbProfilesConfig(BaseModel, extra="forbid", frozen=True):
    """Root schema for smb_profiles.yaml."""

    schema_version: Literal[1]
    advertised_filesystem_defaults: SmbAdvertisedFilesystemDefaults
    transfer_timing: SmbTransferTimingConfig
    samba_audit: SmbSambaAuditConfig
    client_defaults: dict[Literal["windows", "linux"], str]
    client_profiles: dict[str, SmbClientProfile]
    server_defaults: dict[Literal["windows", "linux"], str]
    server_profiles: dict[str, SmbServerProfile]

    @model_validator(mode="after")
    def valid_defaults_and_native_images(self) -> Self:
        """Validate default references, profile keys, and native executable paths."""

        for profile_group_name, profiles in (
            ("client_profiles", self.client_profiles),
            ("server_profiles", self.server_profiles),
        ):
            if not profiles:
                raise ValueError(f"{profile_group_name} must not be empty")
            invalid_names = sorted(
                name for name in profiles if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name)
            )
            if invalid_names:
                raise ValueError(f"{profile_group_name} has invalid names: {invalid_names}")

        self._validate_default_references(
            defaults=self.client_defaults,
            profiles=self.client_profiles,
            field_name="client_defaults",
        )
        self._validate_default_references(
            defaults=self.server_defaults,
            profiles=self.server_profiles,
            field_name="server_defaults",
        )
        for profile in self.client_profiles.values():
            processes = [
                process
                for process in (profile.process, *profile.operation_processes.values())
                if process is not None
            ]
            self._validate_native_images(profile.os_category, processes)
        for profile in self.server_profiles.values():
            processes = [process for process in (profile.listener, profile.worker) if process]
            self._validate_native_images(profile.os_category, processes)
        return self

    @staticmethod
    def _validate_default_references(
        *,
        defaults: dict[Literal["windows", "linux"], str],
        profiles: dict[str, SmbClientProfile] | dict[str, SmbServerProfile],
        field_name: str,
    ) -> None:
        missing_platforms = sorted({"windows", "linux"} - set(defaults))
        if missing_platforms:
            raise ValueError(f"{field_name} is missing platforms: {missing_platforms}")
        for os_category, profile_name in defaults.items():
            profile = profiles.get(profile_name)
            if profile is None:
                raise ValueError(f"{field_name}.{os_category} references unknown {profile_name!r}")
            if profile.os_category != os_category:
                raise ValueError(
                    f"{field_name}.{os_category} references {profile_name!r} for "
                    f"os_category={profile.os_category}"
                )

    @staticmethod
    def _validate_native_images(
        os_category: Literal["windows", "linux"],
        processes: list[SmbProcessProfile],
    ) -> None:
        for process in processes:
            if os_category == "linux" and not process.image.startswith("/"):
                raise ValueError(f"Linux SMB process image must be absolute: {process.image!r}")
            if os_category == "windows" and not re.fullmatch(
                r"[A-Za-z]:\\.+|\\\\.+",
                process.image,
            ):
                raise ValueError(f"Windows SMB process image must be absolute: {process.image!r}")


class WindowsFailedLogonLocalProfile(BaseModel, extra="forbid"):
    """Local interactive 4625 profile."""

    logon_process_name: str
    authentication_package_name: str
    process_name: str


class WindowsFailedLogonProcessProfile(BaseModel, extra="forbid"):
    """Network 4625 logon process/auth package profile."""

    logon_process_name: str
    authentication_package_name: str
    lm_package_name: str
    weight: int = Field(gt=0)


class WindowsFailedLogonPortProfile(BaseModel, extra="forbid"):
    """Network 4625 companion connection port profile."""

    port: int = Field(gt=0, le=65535)
    weight: int = Field(gt=0)


class WindowsFailedLogonValidationPathProfile(BaseModel, extra="forbid"):
    """DC-side validation evidence profile for failed network logons."""

    emit_4776: bool
    emit_4771: bool
    weight: int = Field(gt=0)

    @model_validator(mode="after")
    def emits_some_validation(self) -> Self:
        if not self.emit_4776 and not self.emit_4771:
            raise ValueError("validation path must emit at least one DC-side event")
        return self


class WindowsFailedLogonNetworkProfile(BaseModel, extra="forbid"):
    """Network 4625 profile."""

    validation_path_weights: dict[str, WindowsFailedLogonValidationPathProfile]
    logon_process_weights: dict[str, WindowsFailedLogonProcessProfile]
    emit_network_connection_probability: float = Field(ge=0.0, le=1.0)
    network_ports: dict[str, WindowsFailedLogonPortProfile]

    @field_validator("validation_path_weights", "logon_process_weights", "network_ports")
    @classmethod
    def weighted_profiles_non_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("weighted profile dict must not be empty")
        return v


class WindowsFailedLogonConfig(BaseModel, extra="forbid"):
    """Windows failed-logon profile config."""

    local_interactive: WindowsFailedLogonLocalProfile
    batch: WindowsFailedLogonLocalProfile | None = None
    network: WindowsFailedLogonNetworkProfile


class WindowsWorkstationLockConfig(BaseModel, extra="forbid"):
    """Windows workstation lock/unlock realism config."""

    MAX_UNLOCK_GAP_SECONDS: ClassVar[int] = 86_400

    min_unlock_gap_seconds: int

    @field_validator("min_unlock_gap_seconds")
    @classmethod
    def min_gap_realistic(cls, v: int) -> int:
        if v < 60:
            raise ValueError("workstation_lock.min_unlock_gap_seconds must be at least 60")
        if v > cls.MAX_UNLOCK_GAP_SECONDS:
            raise ValueError(
                "workstation_lock.min_unlock_gap_seconds must be at most "
                f"{cls.MAX_UNLOCK_GAP_SECONDS}"
            )
        return v


class WindowsGroupPolicyCommandProfile(BaseModel, extra="forbid"):
    """One weighted gpupdate command morphology."""

    command_line: str = Field(min_length=1)
    weight: int = Field(gt=0)


class WindowsGroupPolicyRefreshConfig(BaseModel, extra="forbid"):
    """Host-scoped Windows Group Policy refresh model."""

    interval_minutes_min: int = Field(ge=30, le=1440)
    interval_minutes_max: int = Field(ge=30, le=1440)
    process_emission_probability: float = Field(ge=0.0, le=1.0)
    command_profiles: list[WindowsGroupPolicyCommandProfile] = Field(min_length=1)

    @model_validator(mode="after")
    def interval_is_ordered(self) -> Self:
        """Reject inverted refresh interval bounds."""

        if self.interval_minutes_max < self.interval_minutes_min:
            raise ValueError("interval_minutes_max must be >= interval_minutes_min")
        return self


class WindowsRemoteAuthDurationProfile(BaseModel, extra="forbid", frozen=True):
    """One bounded right-skew transport-duration profile."""

    distribution: Literal["lognormal"]
    median_seconds: float = Field(gt=0.0, le=3600.0)
    sigma: float = Field(gt=0.0, le=3.0)
    minimum_seconds: float = Field(ge=0.001, le=3600.0)
    maximum_seconds: float = Field(gt=0.0, le=3600.0)

    @model_validator(mode="after")
    def duration_bounds_are_ordered(self) -> Self:
        """Require the median and clamp to describe one coherent distribution."""

        if self.maximum_seconds < self.minimum_seconds:
            raise ValueError("maximum_seconds must be >= minimum_seconds")
        if not self.minimum_seconds <= self.median_seconds <= self.maximum_seconds:
            raise ValueError("median_seconds must fall within the duration bounds")
        return self


class WindowsRemoteAuthOutcomeProfiles(BaseModel, extra="forbid", frozen=True):
    """Profile references for successful and failed remote authentication."""

    success: str = Field(min_length=1)
    failure: str = Field(min_length=1)


class WindowsRemoteAuthTransportConfig(BaseModel, extra="forbid", frozen=True):
    """Source/outcome-aware Windows remote-authentication transport texture."""

    profiles: dict[str, WindowsRemoteAuthDurationProfile]
    defaults: WindowsRemoteAuthOutcomeProfiles
    sources: dict[str, WindowsRemoteAuthOutcomeProfiles]

    @model_validator(mode="after")
    def profile_references_exist(self) -> Self:
        """Reject empty profile maps and dangling source/default references."""

        if not self.profiles:
            raise ValueError("remote_auth_transport.profiles must not be empty")
        references = {
            self.defaults.success,
            self.defaults.failure,
            *(
                profile_name
                for source_profiles in self.sources.values()
                for profile_name in (source_profiles.success, source_profiles.failure)
            ),
        }
        missing = sorted(references - set(self.profiles))
        if missing:
            raise ValueError(
                f"remote_auth_transport references unknown duration profiles: {missing}"
            )
        if any(not source.strip() for source in self.sources):
            raise ValueError("remote_auth_transport source names must not be empty")
        return self


class WindowsAnonymousSmbBaselineConfig(BaseModel, extra="forbid", frozen=True):
    """Sparse host-scoped cadence for anonymous SMB enumeration noise."""

    hourly_probability: float = Field(ge=0.0, le=1.0)
    events_per_active_hour_min: int = Field(ge=1, le=10)
    events_per_active_hour_max: int = Field(ge=1, le=10)

    @model_validator(mode="after")
    def event_bounds_are_ordered(self) -> Self:
        """Reject inverted per-hour count bounds."""

        if self.events_per_active_hour_max < self.events_per_active_hour_min:
            raise ValueError("events_per_active_hour_max must be >= events_per_active_hour_min")
        return self


class WindowsSpecialPrivilegesProfile(BaseModel, extra="forbid"):
    """Source-native 4672 privilege list profile."""

    privileges: list[str] = Field(min_length=1)
    weight: int = Field(gt=0)

    @field_validator("privileges")
    @classmethod
    def privileges_are_windows_names(cls, v: list[str]) -> list[str]:
        for privilege in v:
            if not privilege.startswith("Se") or not privilege.endswith("Privilege"):
                raise ValueError("Windows privileges must use Se*Privilege names")
        return v


class WindowsSpecialPrivilegesConfig(BaseModel, extra="forbid"):
    """Windows 4672 privilege profile config."""

    emission_probabilities: dict[str, float] = Field(default_factory=dict)
    profiles: dict[str, WindowsSpecialPrivilegesProfile]

    @field_validator("emission_probabilities")
    @classmethod
    def probabilities_are_unit_interval(cls, v: dict[str, float]) -> dict[str, float]:
        for profile_name, probability in v.items():
            if probability < 0.0 or probability > 1.0:
                raise ValueError(
                    f"special_privileges.emission_probabilities.{profile_name} "
                    "must be between 0.0 and 1.0"
                )
        return v

    @field_validator("profiles")
    @classmethod
    def required_profiles_present(cls, v: dict) -> dict:
        required = {
            "service_account",
            "domain_admin",
            "workstation_admin",
            "uac_elevated_user",
        }
        missing = required - set(v)
        if missing:
            raise ValueError(f"special_privileges.profiles missing required profiles: {missing}")
        return v


class WindowsAuthRealismConfig(BaseModel, extra="forbid"):
    """Windows authentication realism knobs."""

    workstation_lock: WindowsWorkstationLockConfig
    group_policy_refresh: WindowsGroupPolicyRefreshConfig
    remote_auth_transport: WindowsRemoteAuthTransportConfig
    anonymous_smb_baseline: WindowsAnonymousSmbBaselineConfig
    failed_logon: WindowsFailedLogonConfig
    special_privileges: WindowsSpecialPrivilegesConfig


class ProxyUserAgentOverrideEntry(BaseModel, extra="forbid"):
    """A domain-specific proxy User-Agent profile."""

    os_keywords: list[str]
    stickiness: Literal["request", "source_host"] = "request"
    hosts: list[str]
    user_agents: list[str]

    @field_validator("os_keywords", "hosts", "user_agents")
    @classmethod
    def non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("list must not be empty")
        return v


class BeaconProfileHttpEntry(BaseModel, extra="forbid"):
    """One weighted HTTP request shape in a beacon profile."""

    method: str = "GET"
    uri: str
    status_code: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = None
    referrer: str | None = None
    request_body_len: list[int] | int | None = None
    request_multipart: HttpMultipartEntitySpec | None = None
    response_body_len: list[int] | int | None = None
    response_multipart: HttpMultipartEntitySpec | None = None
    orig_bytes: list[int] | int | None = None
    resp_bytes: list[int] | int | None = None
    weight: float = Field(default=1.0, gt=0.0)

    @field_validator("method")
    @classmethod
    def method_is_token(cls, v: str) -> str:
        method = v.upper()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
            raise ValueError("method must be a valid HTTP token")
        return method

    @field_validator("uri")
    @classmethod
    def uri_is_origin_form(cls, v: str) -> str:
        if not v.startswith("/") or any(char.isspace() for char in v):
            raise ValueError("uri must start with '/' and contain no whitespace")
        return v

    @field_validator("request_body_len", "response_body_len", "orig_bytes", "resp_bytes")
    @classmethod
    def byte_value_or_range(cls, v: list[int] | int | None, info: ValidationInfo):
        if v is None:
            return v
        if isinstance(v, int):
            if v < 0:
                raise ValueError(f"{info.field_name} must be non-negative")
            return v
        if len(v) != 2:
            raise ValueError(f"{info.field_name} range must contain exactly two integers")
        if not all(isinstance(item, int) for item in v):
            raise ValueError(f"{info.field_name} range values must be integers")
        if v[0] < 0 or v[1] < v[0]:
            raise ValueError(f"{info.field_name} range must be non-negative [lo, hi]")
        return v

    @model_validator(mode="after")
    def multipart_body_length_is_exact(self) -> BeaconProfileHttpEntry:
        """Reject ranged outer sizes for deterministically serialized multipart entities."""

        if self.request_multipart is not None and isinstance(self.request_body_len, list):
            raise ValueError("request_multipart requires an exact request_body_len assertion")
        if self.response_multipart is not None and isinstance(self.response_body_len, list):
            raise ValueError("response_multipart requires an exact response_body_len assertion")
        return self


class BeaconProfileEntry(BaseModel, extra="forbid"):
    """Behavior-shaped synthetic beacon profile."""

    description: str | None = None
    user_agents: list[str] = Field(default_factory=list)
    http_sequence: list[BeaconProfileHttpEntry] = Field(default_factory=list)
    dns_resolution: Literal["cached", "each_tick"] | None = None
    jitter: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def has_behavior(self) -> BeaconProfileEntry:
        if not self.user_agents and not self.http_sequence and self.dns_resolution is None:
            raise ValueError(
                "beacon profile must define user_agents, http_sequence, or dns_resolution"
            )
        return self


class BeaconProfilesConfig(BaseModel, extra="forbid"):
    """Top-level config for beacon_profiles.yaml."""

    profiles: dict[str, BeaconProfileEntry]

    @field_validator("profiles")
    @classmethod
    def profile_names_are_simple(
        cls, v: dict[str, BeaconProfileEntry]
    ) -> dict[str, BeaconProfileEntry]:
        if not v:
            raise ValueError("profiles must not be empty")
        invalid = [name for name in v if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", str(name))]
        if invalid:
            raise ValueError(f"invalid beacon profile names: {', '.join(invalid)}")
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


class CallTracePatternEntry(BaseModel, extra="forbid"):
    """A concrete Sysmon Event 10 CallTrace palette in calltrace_patterns.yaml."""

    id: str | None = None
    modules: list[str]
    offset_ranges: dict[str, list[int]]

    @field_validator("modules")
    @classmethod
    def modules_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("modules must not be empty")
        if any(not module for module in v):
            raise ValueError("modules entries must be non-empty")
        return v

    @field_validator("offset_ranges")
    @classmethod
    def offset_ranges_valid(cls, v: dict[str, list[int]]) -> dict[str, list[int]]:
        for module, bounds in v.items():
            if len(bounds) != 2:
                raise ValueError(f"{module} offset range must be [lo, hi]")
            lo, hi = bounds
            if lo <= 0 or hi <= 0:
                raise ValueError(f"{module} offset range values must be positive")
            if lo >= hi:
                raise ValueError(f"{module} offset range lo must be less than hi")
        return v


class CallTraceSourceFamilyEntry(BaseModel, extra="forbid"):
    """Source process selector for CallTrace palettes."""

    match_exes: list[str] | None = None
    pattern_ids: list[str]

    @field_validator("pattern_ids")
    @classmethod
    def pattern_ids_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("pattern_ids must not be empty")
        if any(not pattern_id for pattern_id in v):
            raise ValueError("pattern_ids entries must be non-empty")
        return v


# --- EDR Pools ---


class EdrFileSideEffectProfile(BaseModel, extra="forbid"):
    """A process-aware ambient FILE telemetry profile in edr_pools.yaml."""

    name: str
    executables: list[str] = Field(default_factory=list)
    executable_contains: list[str] = Field(default_factory=list)
    command_contains: list[str] = Field(default_factory=list)
    actions: list[Literal["create", "modify", "delete", "read"]]
    paths_windows: list[str] = Field(default_factory=list)
    paths_linux: list[str] = Field(default_factory=list)
    probability: float = 1.0

    @model_validator(mode="after")
    def has_matchers_and_paths(self) -> Self:
        """Ensure profiles are actionable and cannot emit impossible empty paths."""
        if not (self.executables or self.executable_contains or self.command_contains):
            raise ValueError(
                "profile must define executables, executable_contains, or command_contains"
            )
        if not self.paths_windows and not self.paths_linux:
            raise ValueError("profile must define paths_windows or paths_linux")
        if not 0 <= self.probability <= 1:
            raise ValueError("probability must be between 0 and 1")
        return self


class EdrInstalledSoftwareProduct(BaseModel, extra="forbid"):
    """A data-driven installed software identity in edr_pools.yaml."""

    name: str
    publisher: str
    version: str

    @field_validator("name", "publisher", "version")
    @classmethod
    def values_non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("installed software fields must be non-empty")
        return v


# --- Endpoint Noise ---


class WindowsScheduledProcessNoiseConfig(BaseModel, extra="forbid"):
    """Windows scheduled/background process timing policy."""

    count_min: int = Field(ge=0)
    count_max: int = Field(ge=0)
    trigger_window_start_seconds: int = Field(ge=0, le=3599)
    trigger_window_end_seconds: int = Field(ge=0, le=3599)
    slot_spacing_seconds: int = Field(gt=0, le=3600)
    host_phase_window_seconds: int = Field(gt=0, le=3600)
    jitter_seconds_min: int
    jitter_seconds_max: int
    skip_probability: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def bounds_are_ordered(self) -> Self:
        """Reject timing windows that would reintroduce boundary clamping."""
        if self.count_min > self.count_max:
            raise ValueError("count_min must be <= count_max")
        if self.trigger_window_start_seconds >= self.trigger_window_end_seconds:
            raise ValueError("trigger_window_start_seconds must be < trigger_window_end_seconds")
        if self.jitter_seconds_min > self.jitter_seconds_max:
            raise ValueError("jitter_seconds_min must be <= jitter_seconds_max")
        return self


class DhcpInterfaceRegistryNoiseConfig(BaseModel, extra="forbid"):
    """Policy for DHCP-related interface registry values."""

    value_names: list[str]
    require_dhcp_state: bool = True
    emit_on_lease_events: bool = True
    suppress_system_types: list[str] = Field(default_factory=list)
    suppress_roles: list[str] = Field(default_factory=list)

    @field_validator("value_names")
    @classmethod
    def value_names_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("value_names must not be empty")
        if any(not name for name in v):
            raise ValueError("value_names entries must be non-empty")
        return v


class StaticInventoryRegistryNoiseConfig(BaseModel, extra="forbid"):
    """Policy for static software-inventory registry values."""

    suppress_in_ambient_noise: bool = True
    key_substrings: list[str]
    value_names: list[str]

    @field_validator("key_substrings", "value_names")
    @classmethod
    def entries_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("entries must not be empty")
        if any(not entry for entry in v):
            raise ValueError("entries must be non-empty")
        return v


class RegistryNoiseConfig(BaseModel, extra="forbid"):
    """Ambient endpoint registry-noise policy."""

    static_inventory_values: StaticInventoryRegistryNoiseConfig
    dhcp_interface_values: DhcpInterfaceRegistryNoiseConfig


class EcarFlowIdentityConfig(BaseModel, extra="forbid"):
    """eCAR FLOW principal-attribution probability policy."""

    user_process_probability: float = Field(ge=0.0, le=1.0)
    service_process_probability: float = Field(ge=0.0, le=1.0)
    root_process_probability: float = Field(ge=0.0, le=1.0)
    inbound_listener_probability: float = Field(ge=0.0, le=1.0)


MAX_ECAR_FILE_CHURN_EVENTS_PER_HOST_HOUR = 100


class EcarFileChurnOsConfig(BaseModel, extra="forbid"):
    """Per-OS ambient eCAR FILE event count and action policy."""

    count_min: int = Field(ge=0, le=MAX_ECAR_FILE_CHURN_EVENTS_PER_HOST_HOUR)
    count_max: int = Field(ge=0, le=MAX_ECAR_FILE_CHURN_EVENTS_PER_HOST_HOUR)
    action_weights: dict[Literal["read", "modify", "create"], int]

    @model_validator(mode="after")
    def bounds_and_weights_are_valid(self) -> Self:
        """Reject inverted count bounds and unusable action weights."""
        if self.count_min > self.count_max:
            raise ValueError("count_min must be <= count_max")
        if not self.action_weights:
            raise ValueError("action_weights must not be empty")
        if any(weight < 0 for weight in self.action_weights.values()):
            raise ValueError("action_weights must be non-negative")
        if sum(self.action_weights.values()) <= 0:
            raise ValueError("action_weights must include at least one positive weight")
        return self


class EcarFileChurnConfig(BaseModel, extra="forbid"):
    """Ambient eCAR FILE event baseline policy."""

    enabled: bool
    windows: EcarFileChurnOsConfig
    linux: EcarFileChurnOsConfig


class EndpointNoiseConfig(BaseModel, extra="forbid"):
    """Root schema for endpoint_noise.yaml."""

    windows_scheduled_processes: WindowsScheduledProcessNoiseConfig
    registry_noise: RegistryNoiseConfig
    ecar_flow_identity: EcarFlowIdentityConfig
    ecar_file_churn: EcarFileChurnConfig


# --- Observation Profiles ---


class ObservationDelayRange(BaseModel, extra="forbid"):
    """Source-observation delay bounds in milliseconds."""

    min_ms: int = Field(ge=0, le=3_600_000)
    max_ms: int = Field(ge=0, le=3_600_000)

    @model_validator(mode="after")
    def bounds_are_ordered(self) -> Self:
        """Reject inverted delay ranges."""
        if self.min_ms > self.max_ms:
            raise ValueError("min_ms must be <= max_ms")
        return self


class ObservationMultiplierRange(BaseModel, extra="forbid"):
    """Deterministic per-host multiplier bounds for source missingness."""

    min: float = Field(ge=0.0, le=10.0)
    max: float = Field(ge=0.0, le=10.0)

    @model_validator(mode="after")
    def bounds_are_ordered(self) -> Self:
        """Reject inverted multiplier ranges."""
        if self.min > self.max:
            raise ValueError("min must be <= max")
        return self


class ObservationCollectionBatching(BaseModel, extra="forbid"):
    """Optional coherent collection batching delay for a source family."""

    enabled: bool = False
    interval_ms: ObservationDelayRange = Field(
        default_factory=lambda: ObservationDelayRange(min_ms=0, max_ms=0)
    )


class ObservationCollectionWindow(BaseModel, extra="forbid"):
    """Optional collection deployment window for a source family."""

    enabled: bool = False
    start: str | None = None
    end: str | None = None


class ObservationSourceProfile(BaseModel, extra="forbid"):
    """Source-level observation behavior for a profile."""

    missingness: float = Field(default=0.0, ge=0.0, le=1.0)
    format_missingness: dict[str, float] = Field(default_factory=dict)
    delay_ms: ObservationDelayRange = Field(
        default_factory=lambda: ObservationDelayRange(min_ms=0, max_ms=0)
    )
    host_missingness_multiplier: ObservationMultiplierRange = Field(
        default_factory=lambda: ObservationMultiplierRange(min=1.0, max=1.0)
    )
    collection_batching: ObservationCollectionBatching = Field(
        default_factory=ObservationCollectionBatching
    )
    collection_window: ObservationCollectionWindow = Field(
        default_factory=ObservationCollectionWindow
    )

    @field_validator("format_missingness")
    @classmethod
    def format_missingness_probabilities_are_valid(cls, v: dict[str, float]) -> dict[str, float]:
        """Reject invalid per-format missingness probabilities."""
        invalid = sorted(name for name, probability in v.items() if not 0.0 <= probability <= 1.0)
        if invalid:
            raise ValueError(
                "format_missingness probabilities must be between 0 and 1 for: "
                + ", ".join(invalid)
            )
        return v


class ObservationProfileEntry(BaseModel, extra="forbid"):
    """A named source-observation profile."""

    VALID_SOURCE_FAMILIES: ClassVar[set[str]] = {
        "windows_security",
        "sysmon",
        "ecar",
        "syslog",
        "bash_history",
        "zeek",
        "proxy",
        "web",
        "asa",
        "ids",
    }
    FORMAT_SOURCE_FAMILIES: ClassVar[dict[str, str]] = {
        "windows_event_security": "windows_security",
        "windows_event_sysmon": "sysmon",
        "ecar": "ecar",
        "syslog": "syslog",
        "bash_history": "bash_history",
        "zeek_conn": "zeek",
        "zeek_dns": "zeek",
        "zeek_http": "zeek",
        "zeek_smtp": "zeek",
        "zeek_ssl": "zeek",
        "zeek_files": "zeek",
        "zeek_smb_files": "zeek",
        "zeek_smb_mapping": "zeek",
        "zeek_x509": "zeek",
        "zeek_dhcp": "zeek",
        "zeek_ntp": "zeek",
        "zeek_weird": "zeek",
        "zeek_ocsp": "zeek",
        "zeek_pe": "zeek",
        "zeek_packet_filter": "zeek",
        "zeek_reporter": "zeek",
        "proxy_access": "proxy",
        "web_access": "web",
        "cisco_asa": "asa",
        "snort_alert": "ids",
    }

    description: str = ""
    default: ObservationSourceProfile = Field(default_factory=ObservationSourceProfile)
    sources: dict[str, ObservationSourceProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def source_names_are_known(self) -> Self:
        """Reject source-family and format-level typos."""
        unknown = sorted(set(self.sources) - self.VALID_SOURCE_FAMILIES)
        if unknown:
            raise ValueError(f"unknown observation source families: {', '.join(unknown)}")
        for source, profile in self.sources.items():
            unknown_formats = sorted(
                set(profile.format_missingness) - set(self.FORMAT_SOURCE_FAMILIES)
            )
            if unknown_formats:
                raise ValueError(
                    f"unknown observation formats for {source}: {', '.join(unknown_formats)}"
                )
            wrong_source = sorted(
                format_name
                for format_name in profile.format_missingness
                if self.FORMAT_SOURCE_FAMILIES[format_name] != source
            )
            if wrong_source:
                raise ValueError(
                    f"format_missingness entries do not belong to {source}: "
                    + ", ".join(wrong_source)
                )
        return self


class ObservationProfilesConfig(BaseModel, extra="forbid"):
    """Root schema for observation_profiles.yaml."""

    profiles: dict[str, ObservationProfileEntry]

    @field_validator("profiles")
    @classmethod
    def profile_names_are_simple(
        cls, v: dict[str, ObservationProfileEntry]
    ) -> dict[str, ObservationProfileEntry]:
        if not v:
            raise ValueError("profiles must not be empty")
        invalid = sorted(
            name for name in v if not name or not name.replace("_", "").replace("-", "").isalnum()
        )
        if invalid:
            raise ValueError(f"invalid observation profile names: {', '.join(invalid)}")
        return v

    @model_validator(mode="after")
    def complete_profile_exists(self) -> Self:
        """The complete profile is the stable training-friendly default."""
        if "complete" not in self.profiles:
            raise ValueError('profiles must include "complete"')
        return self


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


class RemoteThreadStartLocationEntry(BaseModel, extra="forbid"):
    """A remote thread start module/function entry."""

    module: str
    function: str
    weight: int = 1

    @field_validator("module")
    @classmethod
    def module_windows_path(cls, v: str) -> str:
        if "\\" not in v:
            raise ValueError("module must look like a Windows path")
        return v

    @field_validator("weight")
    @classmethod
    def start_weight_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("weight must be positive")
        return v


class CreateRemoteThreadNoiseConfig(BaseModel, extra="forbid"):
    """Rate controls for benign Sysmon Event 8 baseline noise."""

    probability_per_host_hour: float = Field(ge=0.0, le=1.0)
    max_events_per_hour: int = Field(ge=0, le=5)


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

    id: str | None = None
    image: str
    command_templates: list[str]
    parent: str
    params: dict[str, list[str]] | None = None
    system_types: list[str] | None = None
    weight: int = Field(default=1, gt=0)
    max_per_host_window: int | None = Field(default=None, gt=0)
    cooldown_seconds: float | None = Field(default=None, gt=0)
    cooldown_hours: float | None = Field(default=None, gt=0)
    compatibility_group: str | None = None
    compatibility_option: str | None = None
    compatibility_scope: Literal["host"] | None = None


class SystemServiceEntry(BaseModel, extra="forbid"):
    """A system service entry in system_processes.yaml."""

    image: str
    command_templates: list[str]
    parent: str
    params: dict[str, list[str]] | None = None
    loaded_modules: list[LoadedModuleEntry] | None = None
    singleton: bool = False
    compatibility_group: str | None = None
    compatibility_option: str | None = None
    compatibility_scope: Literal["host"] | None = None


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


# --- Host Activity Profiles ---


_HOST_ACTIVITY_RATE_FAMILIES = frozenset(
    {
        "user_activity",
        "web",
        "dns_interval",
        "ntp",
        "smb_interval",
        "kerberos",
        "ldap",
        "persona_connections",
        "role_network",
        "inbound_network",
        "windows_service_process",
        "windows_registry",
        "windows_scheduled_task",
        "windows_remote_thread",
        "windows_process_access",
        "windows_module_load",
        "windows_remote_admin",
        "windows_service_logon",
        "windows_machine_auth",
        "dc_kerberos",
        "linux_syslog",
        "linux_remote_admin",
        "linux_shell",
        "firewall_deny",
        "ids_alert",
        "icmp_monitoring",
    }
)


class HostActivityRateFamiliesConfig(BaseModel, extra="forbid"):
    """Rate-family bounds for host_activity_profiles.yaml."""

    default_bounds: list[float]
    bounds: dict[str, list[float]] = Field(default_factory=dict)

    @field_validator("default_bounds")
    @classmethod
    def default_bounds_valid(cls, v: list[float]) -> list[float]:
        return _validate_positive_pair(v, "default_bounds")

    @field_validator("bounds")
    @classmethod
    def bounds_valid(cls, v: dict[str, list[float]]) -> dict[str, list[float]]:
        unknown = sorted(set(v) - _HOST_ACTIVITY_RATE_FAMILIES)
        if unknown:
            raise ValueError(f"unknown rate family bounds: {unknown}")
        for family, bounds in v.items():
            _validate_positive_pair(bounds, f"bounds.{family}")
        return v


def _validate_positive_pair(v: list[float], field_name: str) -> list[float]:
    """Validate a two-value positive numeric range."""
    if len(v) != 2:
        raise ValueError(f"{field_name} must be a two-value [min, max] list")
    if not all(isinstance(item, int | float) and item > 0 for item in v):
        raise ValueError(f"{field_name} values must be positive numbers")
    if v[0] > v[1]:
        raise ValueError(f"{field_name} min must be <= max")
    return v


class HostActivityProfileEntry(BaseModel, extra="forbid"):
    """Host type, role, or persona multiplier profile."""

    base_multiplier: float = Field(default=1.0, gt=0)
    variance: list[float] | None = None
    families: dict[str, float] = Field(default_factory=dict)

    @field_validator("variance")
    @classmethod
    def variance_valid(cls, v: list[float] | None) -> list[float] | None:
        if v is None:
            return v
        return _validate_positive_pair(v, "variance")

    @field_validator("families")
    @classmethod
    def families_valid(cls, v: dict[str, float]) -> dict[str, float]:
        unknown = sorted(set(v) - _HOST_ACTIVITY_RATE_FAMILIES)
        if unknown:
            raise ValueError(f"unknown activity families: {unknown}")
        for family, multiplier in v.items():
            if not isinstance(multiplier, int | float) or multiplier <= 0:
                raise ValueError(f"family multiplier {family!r} must be positive")
        return v


class PowerShellEncodedVariantsConfig(BaseModel, extra="forbid"):
    """Data-driven encoded PowerShell command variants."""

    host_preferred_template_count: int = Field(default=3, gt=0)
    templates: list[str]
    params: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("templates")
    @classmethod
    def templates_non_empty(cls, v: list[str]) -> list[str]:
        if not v or any(not template for template in v):
            raise ValueError("templates must contain non-empty strings")
        return v

    @field_validator("params")
    @classmethod
    def params_non_empty(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        for key, values in v.items():
            if not key or not values or any(not value for value in values):
                raise ValueError("params keys and values must be non-empty")
        return v


class HostActivityArtifactVariantsConfig(BaseModel, extra="forbid"):
    """Artifact variation config for host_activity_profiles.yaml."""

    powershell_encoded: PowerShellEncodedVariantsConfig


class HostActivityFirewallDenyConfig(BaseModel, extra="forbid"):
    """Firewall deny burst and metadata knobs."""

    burst_window_count: list[int]
    burst_width_seconds: list[int]
    quiet_probability: float = Field(ge=0.0, le=1.0)
    metadata_hash_nonzero_probability: float = Field(ge=0.0, le=1.0)

    @field_validator("burst_window_count", "burst_width_seconds")
    @classmethod
    def integer_range_valid(cls, v: list[int]) -> list[int]:
        if len(v) != 2:
            raise ValueError("must be a two-value [min, max] list")
        if not all(isinstance(item, int) and item > 0 for item in v):
            raise ValueError("values must be positive integers")
        if v[0] > v[1]:
            raise ValueError("min must be <= max")
        return v


class HostActivityProfilesConfig(BaseModel, extra="forbid"):
    """Root schema for host_activity_profiles.yaml."""

    rate_families: HostActivityRateFamiliesConfig
    host_types: dict[str, HostActivityProfileEntry]
    role_profiles: dict[str, HostActivityProfileEntry] = Field(default_factory=dict)
    persona_profiles: dict[str, HostActivityProfileEntry] = Field(default_factory=dict)
    artifact_variants: HostActivityArtifactVariantsConfig
    firewall_deny: HostActivityFirewallDenyConfig

    @field_validator("host_types")
    @classmethod
    def required_host_types_present(
        cls, v: dict[str, HostActivityProfileEntry]
    ) -> dict[str, HostActivityProfileEntry]:
        missing = sorted({"workstation", "server", "domain_controller"} - set(v))
        if missing:
            raise ValueError(f"missing host type profiles: {missing}")
        return v


# --- Secret families (spillage event type) ---


class SecretFamilyEntry(BaseModel, extra="forbid"):
    """One credential family used by the spillage event type."""

    name: str
    description: str = ""
    structured: bool = True
    regex: str
    value_template: str | None = None
    examples: list[str] = Field(default_factory=list)
    default_app: str = "app"
    surfaces: list[str] = Field(default_factory=list)
    carriers: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("regex")
    @classmethod
    def _regex_compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid family regex: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _check_family(self) -> Self:
        if not self.value_template and not self.examples:
            raise ValueError(f"family {self.name!r} needs a value_template or examples")
        pattern = re.compile(self.regex)
        for ex in self.examples:
            if not pattern.search(ex):
                raise ValueError(
                    f"family {self.name!r} example {ex!r} does not match regex {self.regex!r}"
                )
        for surface, lines in self.carriers.items():
            for line in lines:
                if "{value}" not in line:
                    raise ValueError(
                        f"family {self.name!r} carrier for {surface!r} must contain {{value}}: "
                        f"{line!r}"
                    )
        return self


class SecretFamiliesConfig(BaseModel, extra="forbid"):
    """Top-level schema for secret_families.yaml (merged bundle + overlay)."""

    families: list[SecretFamilyEntry] = Field(default_factory=list, min_length=1)
    poison_markers: list[str] = Field(default_factory=list, min_length=1)
    vendor_fakes: list[str] = Field(default_factory=list)
    network_allowlist: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _unique_family_names(self) -> Self:
        names = [f.name for f in self.families]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate family names: {dupes}")
        return self

    @model_validator(mode="after")
    def _safe_marker_fake_domain_values(self) -> Self:
        # A degenerate marker/fake/domain silently weakens the safety guardrails
        # (e.g. an empty marker makes every value "contain a marker"; a 4-char
        # fake "AKIA" vouches for any real AWS key; a bare TLD allowlists all of
        # *.com). Reject these so a typo'd overlay can't defeat the safety contract.
        for marker in self.poison_markers:
            if len(marker.strip()) < 3:
                raise ValueError(
                    f"poison marker {marker!r} is empty/too short (need >=3 chars); "
                    "a short marker would mark real secrets as synthetic"
                )
        for fake in self.vendor_fakes:
            if len(fake) < 12:
                raise ValueError(
                    f"vendor_fake {fake!r} is too short (need >=12 chars); a short "
                    "fake would vouch for real credentials that merely share the prefix"
                )
        reserved_suffixes = (".example", ".test", ".invalid", ".localhost")
        reserved_exact = {
            "example.com",
            "example.net",
            "example.org",
            "example",
            "test",
            "invalid",
            "localhost",
        }
        for domain in self.network_allowlist.get("domains", []) or []:
            normalized = str(domain).lower().strip(".")
            if normalized not in reserved_exact and not normalized.endswith(reserved_suffixes):
                raise ValueError(
                    f"allowlist domain {domain!r} is not an RFC 2606/6761 reserved name; "
                    "use example.com/.net/.org or a .test/.invalid/.example/.localhost name"
                )
        return self


class PayloadFamilyEntry(BaseModel, extra="forbid"):
    """One adversarial-payload family used by the adversarial_payload event type.

    The counterpart to SecretFamilyEntry: a payload deliberately carries a log-
    pipeline injection primitive, so there is no credential `regex`; instead a
    family declares which `surfaces` it is valid in and, in `raw_surfaces`, the
    subset where its control bytes are emitted raw (the realistic weakness).
    """

    name: str
    description: str = ""
    weakness_class: str = ""
    value_template: str | None = None
    # An ordered list of variant templates (the engine picks one per event by seed):
    # ship the canonical form PLUS evasion/bypass variants so a dataset tests detection
    # QUALITY, not just presence. Mutually exclusive with value_template/examples.
    value_templates: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list, min_length=1)
    raw_surfaces: list[str] = Field(default_factory=list)
    carriers: dict[str, list[str]] = Field(default_factory=dict)
    expected_defender_signal: str = ""
    # The on-wire Snort/Suricata signature ID (from ids_signatures.yaml) a network
    # sensor should fire on when this family's payload rides a CLEARTEXT http request.
    # None = no network signature (e.g. a syslog-only / viewer-only weakness). The
    # SID's existence in the signature pool is verified by validate-config (cross-file
    # coupling), not here.
    ids_sid: int | None = None
    # The literal content token the flat ET signature keys on. The alert fires ONLY when
    # the (normalized) rendered payload still contains this token, so an evasion variant
    # that splits it produces NO alert — modeling the real rule's blind spot. Required
    # whenever ids_sid is set (else the signature would fire on every variant, including
    # the ones it is designed to miss).
    ids_fires_on: str | None = None

    @model_validator(mode="after")
    def _check_family(self) -> Self:
        sources = sum(bool(s) for s in (self.value_template, self.value_templates, self.examples))
        if sources == 0:
            raise ValueError(
                f"payload family {self.name!r} needs a value_template, value_templates, or examples"
            )
        if sources > 1:
            raise ValueError(
                f"payload family {self.name!r} must use exactly one of value_template / "
                "value_templates / examples"
            )
        extra = sorted(set(self.raw_surfaces) - set(self.surfaces))
        if extra:
            raise ValueError(
                f"payload family {self.name!r} raw_surfaces {extra} are not in its surfaces"
            )
        for surface, lines in self.carriers.items():
            for line in lines:
                if "{value}" not in line:
                    raise ValueError(
                        f"payload family {self.name!r} carrier for {surface!r} must contain "
                        f"{{value}}: {line!r}"
                    )
        # An on-wire IDS signature only fires on a cleartext http request, so a family
        # declaring ids_sid must have at least one http_* surface to carry it, and must
        # declare the content token (ids_fires_on) the flat rule keys on so the alert
        # fires only on matching (non-evasion) renderings.
        if self.ids_sid is not None:
            http_surfaces = {"http_user_agent", "http_request_url", "http_referrer"}
            if not (set(self.surfaces) & http_surfaces):
                raise ValueError(
                    f"payload family {self.name!r} declares ids_sid {self.ids_sid} but has no "
                    f"http_* surface for the signature to fire on (surfaces={self.surfaces})"
                )
            if not self.ids_fires_on:
                raise ValueError(
                    f"payload family {self.name!r} declares ids_sid {self.ids_sid} but no "
                    "ids_fires_on content token; without it the signature would fire on every "
                    "variant (including the evasion variants it is designed to miss)"
                )
        if self.ids_fires_on and self.ids_sid is None:
            raise ValueError(
                f"payload family {self.name!r} declares ids_fires_on but no ids_sid to fire"
            )
        return self


class PayloadFamiliesConfig(BaseModel, extra="forbid"):
    """Top-level schema for payload_families.yaml (merged bundle + overlay)."""

    families: list[PayloadFamilyEntry] = Field(default_factory=list, min_length=1)
    default_marker: str = "EFORGE_TEST"
    markers: list[str] = Field(default_factory=list, min_length=1)
    canary_host: str = "canary.eforge.invalid"
    network_allowlist: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _unique_family_names(self) -> Self:
        names = [f.name for f in self.families]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate payload family names: {dupes}")
        return self

    @model_validator(mode="after")
    def _safe_marker_canary_domain_values(self) -> Self:
        # Reject a degenerate marker/canary/domain that would silently weaken the
        # safety contract (an empty marker marks every payload synthetic; a real
        # callback host or a bare TLD would let a live payload reach the network).
        if len(self.default_marker.strip()) < 3:
            raise ValueError(
                f"default_marker {self.default_marker!r} is empty/too short (need >=3 chars)"
            )
        if self.default_marker not in self.markers:
            raise ValueError(
                f"default_marker {self.default_marker!r} must be in markers {self.markers}"
            )
        for marker in self.markers:
            stripped = marker.strip()
            if len(stripped) < 3:
                raise ValueError(
                    f"marker {marker!r} is empty/too short (need >=3 chars); a short marker "
                    "would mark real content as synthetic"
                )
            # Distinctiveness: marker matching is substring-based and the per-line
            # marker is the SOLE synthetic guarantee for adversarial payloads (no
            # credential-shape/vendor-fake backstop). A generic lowercase word (e.g.
            # "admin", "status") would mark ordinary forged log text as synthetic and
            # let an unmarked forged line through — require a "shouty" marker.
            uppers = sum(1 for c in stripped if c.isupper())
            has_sep = any(c.isdigit() or c == "_" for c in stripped)
            if not (uppers >= 1 and (has_sep or uppers >= 4)):
                raise ValueError(
                    f"marker {marker!r} is not distinctive enough; an adversarial-payload "
                    "marker must be shouty (an uppercase letter plus a digit/underscore, or "
                    ">=4 uppercase letters) so it cannot match ordinary log text"
                )
        reserved_suffixes = (".example", ".test", ".invalid", ".localhost")
        reserved_exact = {
            "example.com",
            "example.net",
            "example.org",
            "example",
            "test",
            "invalid",
            "localhost",
        }
        domains = list(self.network_allowlist.get("domains", []) or [])
        for domain in [self.canary_host, *domains]:
            normalized = str(domain).lower().strip(".")
            if normalized not in reserved_exact and not normalized.endswith(reserved_suffixes):
                raise ValueError(
                    f"host {domain!r} is not an RFC 2606/6761 reserved name; the canary and "
                    "allowlist must use example.com/.net/.org or a .test/.invalid/.localhost name"
                )
        return self


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
