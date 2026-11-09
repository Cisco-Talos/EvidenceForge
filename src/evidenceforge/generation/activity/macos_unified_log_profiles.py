# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed native logging profiles using the existing effective-config owner."""

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.schemas import MacosUnifiedLogProfilesConfig
from evidenceforge.events.macos_logging import UnifiedLogCallsite

_CACHED_PROFILES: MacosUnifiedLogProfilesConfig | None = None


def load_macos_unified_log_profiles() -> MacosUnifiedLogProfilesConfig:
    """Load the bounded source profile with ordinary deep-mapping overlays."""
    global _CACHED_PROFILES
    if _CACHED_PROFILES is None:
        _CACHED_PROFILES = MacosUnifiedLogProfilesConfig.model_validate(
            load_with_overlay(
                get_activity_directory() / "macos_unified_log_profiles.yaml",
                "activity/macos_unified_log_profiles.yaml",
                deep_merge_dict,
            )
        )
    return _CACHED_PROFILES


def workspace_request_callsite() -> UnifiedLogCallsite:
    """Freeze the source profile's explicit main-image logging point."""
    profile = load_macos_unified_log_profiles().workspace_request
    return UnifiedLogCallsite(
        message_type=profile.message_type,
        subsystem=profile.subsystem,
        category=profile.category,
        format_string=profile.format_string,
        format_string_offset=profile.format_string_offset,
        program_counter=profile.program_counter,
        has_rules=profile.has_rules,
    )
