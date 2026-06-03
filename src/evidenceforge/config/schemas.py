# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pydantic schemas for EvidenceForge config YAML files.

These models define the expected structure of each config file type.
Used by validate_config.py to validate merged data — not used by loaders
(loaders stay fast, validation is opt-in via eforge validate-config).

All models use extra="forbid" so misspelled fields are caught as errors.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from evidenceforge.config.public_dns_templates import validate_public_dns_answer_template

TLS_SERIAL_LENGTH_MAX_WEIGHT = 1_000_000
KERBEROS_TRANSPORT_MAX_WEIGHT = 1_000_000

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


# --- Application Catalog ---


class LoadedModuleEntry(BaseModel, extra="forbid"):
    """A DLL/module entry in a loaded_modules list."""

    path: str
    signed: bool = True
    signature: str = "Microsoft Windows"
    signature_status: str = "Valid"
    pe_metadata: dict[str, str] | None = None

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


class TlsOcspConfig(BaseModel, extra="forbid"):
    """OCSP behavior settings in tls_realism.yaml."""

    cache_bucket_seconds: int
    this_update_max_skew_seconds: int
    next_update_min_seconds: int
    next_update_max_seconds: int
    request_path: TlsOcspRequestPathConfig = Field(default_factory=TlsOcspRequestPathConfig)
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


class AuthNoiseConfig(BaseModel, extra="forbid"):
    """Root schema for auth_noise.yaml."""

    scheduled_stale_credentials: ScheduledStaleCredentialsConfig


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


# --- EDR Pools ---


class EdrFileSideEffectProfile(BaseModel, extra="forbid"):
    """A process-aware ambient FILE telemetry profile in edr_pools.yaml."""

    name: str
    executables: list[str] = Field(default_factory=list)
    executable_contains: list[str] = Field(default_factory=list)
    command_contains: list[str] = Field(default_factory=list)
    actions: list[Literal["create", "modify", "delete"]]
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


class RegistryNoiseConfig(BaseModel, extra="forbid"):
    """Ambient endpoint registry-noise policy."""

    dhcp_interface_values: DhcpInterfaceRegistryNoiseConfig


class EcarFlowIdentityConfig(BaseModel, extra="forbid"):
    """eCAR FLOW principal-attribution probability policy."""

    user_process_probability: float = Field(ge=0.0, le=1.0)
    service_process_probability: float = Field(ge=0.0, le=1.0)
    root_process_probability: float = Field(ge=0.0, le=1.0)
    inbound_listener_probability: float = Field(ge=0.0, le=1.0)


class EcarFileChurnOsConfig(BaseModel, extra="forbid"):
    """Per-OS ambient eCAR FILE event count and action policy."""

    count_min: int = Field(ge=0)
    count_max: int = Field(ge=0)
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


class ObservationSourceProfile(BaseModel, extra="forbid"):
    """Source-level observation behavior for a profile."""

    missingness: float = Field(default=0.0, ge=0.0, le=1.0)
    delay_ms: ObservationDelayRange = Field(
        default_factory=lambda: ObservationDelayRange(min_ms=0, max_ms=0)
    )
    host_missingness_multiplier: ObservationMultiplierRange = Field(
        default_factory=lambda: ObservationMultiplierRange(min=1.0, max=1.0)
    )


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

    description: str = ""
    default: ObservationSourceProfile = Field(default_factory=ObservationSourceProfile)
    sources: dict[str, ObservationSourceProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def source_names_are_known(self) -> Self:
        """Reject source-family typos."""
        unknown = sorted(set(self.sources) - self.VALID_SOURCE_FAMILIES)
        if unknown:
            raise ValueError(f"unknown observation source families: {', '.join(unknown)}")
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

    image: str
    command_templates: list[str]
    parent: str
    params: dict[str, list[str]] | None = None
    system_types: list[str] | None = None


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
