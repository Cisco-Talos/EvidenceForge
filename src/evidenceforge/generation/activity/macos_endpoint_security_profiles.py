# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen generation admission, separate from historical native wire codecs."""

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.provider import current_effective_config
from evidenceforge.config.schemas import (
    MacosEndpointSecurityProfile,
    MacosEndpointSecurityProfilesConfig,
)

_CACHED_PROFILE: MacosEndpointSecurityProfilesConfig | None = None


def load_macos_endpoint_security_profiles() -> MacosEndpointSecurityProfilesConfig | None:
    """Load active targets; older frozen inputs never inherit a newer source policy."""
    global _CACHED_PROFILE
    effective = current_effective_config()
    if (
        effective is not None
        and not effective.ambient_overlay_compat
        and not {
            "activity/macos_endpoint_security_profiles.yaml",
            "activity/macos_unified_log_profiles.yaml",
        }.issubset(effective.packaged_defaults)
    ):
        return None
    if _CACHED_PROFILE is None:
        values = load_with_overlay(
            get_activity_directory() / "macos_endpoint_security_profiles.yaml",
            "activity/macos_endpoint_security_profiles.yaml",
            deep_merge_dict,
        )
        if (
            effective is not None
            and not effective.ambient_overlay_compat
            and values.get("schema_version") == "1.0"
        ):
            return None  # Retired single-profile policy remains frozen, never upgraded.
        _CACHED_PROFILE = MacosEndpointSecurityProfilesConfig.model_validate(values)
    return _CACHED_PROFILE


def load_macos_endpoint_security_profile(
    os_major: int = 27, architecture: str = "arm64", *, profile_id: str | None = None
) -> MacosEndpointSecurityProfile | None:
    """Resolve one catalog entry, never substitute an adjacent OS release."""
    catalog = load_macos_endpoint_security_profiles()
    if catalog is None:
        return None
    return next(
        (
            profile
            for profile in catalog.profiles
            if (
                profile.profile == profile_id
                if profile_id is not None
                else (profile.os_major == os_major and profile.architecture == architecture)
            )
        ),
        None,
    )
