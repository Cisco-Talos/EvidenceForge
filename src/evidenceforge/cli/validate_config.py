# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Legacy CLI imports for the shared configuration validator."""

from evidenceforge.validation.configuration import (
    RECURRING_SYSLOG_STARTUP_PATTERNS,
    REQUIRED_PERSONA_FIELDS,
    VALID_BROWSING_INTENSITIES,
    VALID_RISK_PROFILES,
    WINDOWS_BOOT_ONLY_PROCESS_EXES,
    WINDOWS_SEEDED_PARENT_SYMBOLS,
    Issue,
    ValidationResult,
    _extract_field_refs,
    _get_persona_names,
    _safe_load_yaml,
    _validate_edr_file_path_pools,
    _validate_payload_families,
    _validate_proxy_phase_profiles,
    _validate_registry_mru_filenames,
    _validate_secret_families,
    _validate_storage_catalog,
    _validate_tls_issuer_overrides,
    validate_config,
)

__all__ = [
    "Issue",
    "RECURRING_SYSLOG_STARTUP_PATTERNS",
    "REQUIRED_PERSONA_FIELDS",
    "VALID_BROWSING_INTENSITIES",
    "VALID_RISK_PROFILES",
    "ValidationResult",
    "WINDOWS_BOOT_ONLY_PROCESS_EXES",
    "WINDOWS_SEEDED_PARENT_SYMBOLS",
    "_extract_field_refs",
    "_get_persona_names",
    "_safe_load_yaml",
    "_validate_edr_file_path_pools",
    "_validate_payload_families",
    "_validate_proxy_phase_profiles",
    "_validate_registry_mru_filenames",
    "_validate_secret_families",
    "_validate_storage_catalog",
    "_validate_tls_issuer_overrides",
    "validate_config",
]
