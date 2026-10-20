# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen generation admission, separate from historical native wire codecs."""

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.provider import current_effective_config
from evidenceforge.config.schemas import MacosEndpointSecurityProfile

_CACHED_PROFILE: MacosEndpointSecurityProfile | None = None


def load_macos_endpoint_security_profile() -> MacosEndpointSecurityProfile | None:
    """Retain unknown source policy in older immutable effective inputs."""
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
        _CACHED_PROFILE = MacosEndpointSecurityProfile.model_validate(
            load_with_overlay(
                get_activity_directory() / "macos_endpoint_security_profiles.yaml",
                "activity/macos_endpoint_security_profiles.yaml",
                deep_merge_dict,
            )
        )
    return _CACHED_PROFILE
